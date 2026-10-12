#!/usr/bin/env python3
"""PLAN M4.3: the file-attacker harness, attack x location x implementation.

An attacker who edits a .cryptand file recomputes every CRC (14 §9.4), so each
attack here is CRC-repaired and must still be refused by every implementation
with a named security error: tampering, or "wrong key" for a keyslot. Plain
corruption is accepted only where the edit makes the header structurally
impossible before any AEAD runs. Never: a successful read of a modified live
page, plaintext output, a crash or a hang. Rollback of a whole file (N2) is out
of scope (14 §1.2, §6.3) and is not attacked.

Stdlib only, and no code shared with the implementations under test.
Usage: tools/security_attack.py [--impl rust,java,dart] [--keep DIR]
"""
import argparse, os, shutil, struct, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = os.path.join(ROOT, 'reference')
KEY = '07' * 32
KEY_B = '0c' * 32
PASSWORD = '70617373776f7264c3a9'

# --- CRC-32C and the fixed offsets of 01-container.md / 14-security.md -------

_T = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
    _T.append(c)

def crc32c(b):
    c = 0xFFFFFFFF
    for x in b:
        c = _T[(c ^ x) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF

SB = 4096
SB_CIPHER, SB_COMMIT, SB_FEATURES_REQ, SB_CATALOG = 178, 16, 24, 64
SB_NEXT_NONCE, SB_MAC, SB_KEYSLOTS, SB_CRC, SB_UUID = 288, 296, 3512, 4092, 160
SLOT = 144
ENCRYPTED, EXTENT_HEAD = 2, 8
VLOG_SEGMENT, VLOG_DATA = 7, 104

# F-128 (14 §5.5): an older page replayed at its own position is tampering
# when anything reads it; one at a position nothing reaches reads the same.
REPLAY = frozenset({'tamper', 'ok-same'})

def page_size(b):
    return 1 << b[14]

def sb_at(b, s):
    """Slot A is page 0, slot B is page 1 (01-container.md §1)."""
    return s * page_size(b)

def newest_sb(b):
    """The superblock slot a reader picks: valid CRC, highest commit_id."""
    best = None
    for s in (0, 1):
        img = b[sb_at(b, s):sb_at(b, s) + SB]
        if img[:8] == b'CRYPTAND' and crc32c(img[:SB_CRC]) == struct.unpack_from('<I', img, SB_CRC)[0]:
            cid = struct.unpack_from('<Q', img, SB_COMMIT)[0]
            if best is None or cid > best[1]:
                best = (s, cid)
    return best[0]

def fix_sb(b, s):
    o = sb_at(b, s)
    struct.pack_into('<I', b, o + SB_CRC, crc32c(b[o:o + SB_CRC]))

def fix_page(b, p):
    ps = page_size(b)
    o = p * ps
    # A value-log head is written once and records are appended after it, so its
    # checksum stops at its 64-byte header (04-segments.md §6.2).
    end = o + 40 + (struct.unpack_from('<I', b, o + 28)[0] or struct.unpack_from('<I', b, o + 24)[0]) if b[o + 4] == VLOG_SEGMENT else o + ps
    struct.pack_into('<I', b, o, crc32c(b[o + 4:end]))

def pages(b):
    """(page_id, header fields) for every headed page, walking extents."""
    ps, out, p = page_size(b), [], 2
    while (p + 1) * ps <= len(b):
        h = b[p * ps:p * ps + 40]
        typ, fl = h[4], h[5]
        tree, ext = struct.unpack_from('<II', h, 8)
        cid, pl, sl, nonce = struct.unpack_from('<QIIQ', h, 16)
        out.append(dict(id=p, type=typ, flags=fl, tree=tree, ext=ext, stored=sl or pl, nonce=nonce))
        p += max(ext, 1)
    return out

def vlog_records(b, encrypted=True):
    """(offset of the field after record_len, record_len) for every record in
    every encrypted value-log segment, walked up to the first zero length
    (04-segments.md §6.2). The tail above tree 7's watermark is debris, and
    reads of it are not attacked."""
    ps, out = page_size(b), []
    for h in pages(b):
        o = h['id'] * ps
        if h['type'] != VLOG_SEGMENT:
            continue
        c = 8 if encrypted else 0   # the clear nonce, outside the CRC
        at, end = o + VLOG_DATA, o + h['ext'] * ps
        while at < end:
            n, sh, q = 0, 0, at
            while True:
                n |= (b[q] & 0x7F) << sh
                sh += 7
                q += 1
                if not b[q - 1] & 0x80:
                    break
            if n < c + 8 or q + n > end:
                break
            if crc32c(b[q + c:q + n - 4]) != struct.unpack_from('<I', b, q + n - 4)[0]:
                break
            out.append((q, n))
            at = q + n
    return out

def fix_record(b, q, n):
    struct.pack_into('<I', b, q + n - 4, crc32c(b[q + 8:q + n - 4]))

# --- the implementations, as conformance/interop/run.sh drives them ----------

class Impls:
    def __init__(self, names, work):
        self.names, self.work = names, work
        self.dart_exe = os.path.join(work, 'interop-dart')
        cp = os.path.join(REF, 'java/target/classes') + os.pathsep + os.path.join(REF, 'java/target/test-classes')
        self.cmd = {
            'rust': [os.path.join(REF, 'rust/target/release/interop')],
            'java': ['java', '-cp', cp, 'org.dizitart.cryptand.tool.Interop'],
            'dart': [self.dart_exe],
        }

    def build(self):
        sh = lambda c, d: subprocess.run(c, cwd=d, check=True)
        sh(['cargo', 'build', '--release', '-q', '-p', 'cryptand', '--features', 'harness', '--bin', 'interop'],
           os.path.join(REF, 'rust'))
        sh(['mvn', '-q', '-o', '-DskipTests', 'test-compile'], os.path.join(REF, 'java'))
        if 'dart' in self.names:
            sh(['dart', 'compile', 'exe', '-o', self.dart_exe, 'tool/interop.dart'], os.path.join(REF, 'dart/cryptand'))

    def run(self, impl, verb, path, cred, timeout=120):
        flag = ['--password', PASSWORD] if cred == 'pw' else ['--key', cred]
        try:
            p = subprocess.run(self.cmd[impl] + [verb, path] + flag, capture_output=True, text=True,
                               timeout=timeout, cwd=os.path.join(REF, 'dart/cryptand'))
            return p.returncode, p.stdout + p.stderr
        except subprocess.TimeoutExpired:
            return None, 'timeout'

    def digest(self, impl, data, cred):
        """Read a fresh copy (an open may write: §4.1's nonce publish)."""
        d = tempfile.mkdtemp(dir=self.work)
        f = os.path.join(d, 'f.cryptand')
        with open(f, 'wb') as o:
            o.write(data)
        rc, out = self.run(impl, 'read', f, cred)
        if rc == 0:
            # A read that succeeds must also verify: verify walks what read skips.
            vrc, vout = self.run(impl, 'verify', f, cred)
            if vrc != 0 or 'Tamper' in vout or 'Corrupt' in vout:
                rc, out = 1, vout
        shutil.rmtree(d, ignore_errors=True)
        return rc, out


def classify(rc, out, want):
    if rc is None:
        return 'hang'
    if rc == 0:
        for line in out.splitlines():
            if line.startswith('digest='):
                return 'ok-same' if line[7:] == want else 'ok-DIFFERENT'
        return 'ok-nodigest'
    low = out.lower()
    # Order matters: a tampering error may mention a checksum in its text.
    if 'tamper' in low or 'tag mismatch' in low or 'authentication failed' in low:
        return 'tamper'
    if 'cannot unlock' in low:
        return 'wrongkey'
    if 'unsupported' in low or 'unknown required feature' in low:
        return 'unsupported'
    if 'corrupt' in low:
        return 'corrupt'
    return 'unnamed'


# --- the attacks ---------------------------------------------------------------

def flip(b, o):
    b[o] ^= 0x01

def variants(base, cred, twin, other, older, live, live_recs=()):
    """Yield (location, attack, bytes, allowed outcomes)."""
    ps = page_size(base)
    hdr = {p['id']: p for p in pages(base)}
    SEC, HDR = {'tamper'}, {'tamper', 'corrupt'}

    def edit(fn):
        b = bytearray(base)
        fn(b)
        return bytes(b)

    for p in live:
        h, o = hdr[p], p * ps
        loc = f'page {p} type {h["type"]}'
        def page_edit(fn, p=p):
            return edit(lambda b: (fn(b), fix_page(b, p)))
        for field, off in (('page_type', 4), ('flags.COMPRESSED', 5), ('tree_id', 8), ('extent_pages', 12),
                           ('commit_id', 16), ('payload_len', 24), ('stored_len', 28), ('nonce', 32)):
            yield loc, f'header {field}', page_edit(lambda b, off=off: flip(b, o + off)), HDR
        yield loc, 'header flags.ENCRYPTED cleared', page_edit(lambda b: b.__setitem__(o + 5, b[o + 5] & ~ENCRYPTED)), HDR
        yield loc, 'ciphertext byte', page_edit(lambda b: flip(b, o + 40 + h['stored'] // 2)), SEC
        yield loc, 'tag byte', page_edit(lambda b: flip(b, o + 40 + h['stored'] - 1)), SEC
        yield loc, 'payload zeroed', page_edit(lambda b: b.__setitem__(slice(o + 40, o + 40 + h['stored']),
                                                                     bytes(h['stored']))), SEC
        yield loc, 'ciphertext byte, CRC not repaired', edit(lambda b: flip(b, o + 40 + h['stored'] // 2)), HDR
        # Splice across positions: another live page of the same type over this one.
        for q in live:
            if q != p and hdr[q]['type'] == h['type']:
                yield loc, f'spliced from page {q}', edit(lambda b, q=q: b.__setitem__(slice(o, o + ps),
                                                                                     base[q * ps:(q + 1) * ps])), SEC
                break
        # Splice across files: the same page id from another database, same key.
        if len(other) >= o + ps and other[o + 4] == base[o + 4]:
            yield loc, 'spliced from another database', edit(lambda b: b.__setitem__(slice(o, o + ps),
                                                                                    other[o:o + ps])), SEC
        # Replay: an older authentic version of this page, at its own position.
        if len(older) >= o + ps and older[o:o + ps] != base[o:o + ps] and older[o + 5] & ENCRYPTED:
            yield loc, 'replayed older version', edit(lambda b: b.__setitem__(slice(o, o + ps), older[o:o + ps])), \
                REPLAY
        # Forgery: the plaintext twin's page, unflagged, valid CRC.
        n = max(h['ext'], 1)
        if len(twin) >= o + n * ps and twin[o + 4] == base[o + 4] and not twin[o + 5] & ENCRYPTED:
            def forge(b, p=p, o=o, n=n):
                b[o:o + n * ps] = twin[o:o + n * ps]
                for q in range(p, p + n):
                    fix_page(b, q)
            yield loc, 'replaced by a forged plaintext page' + (f' extent ({n} pages)' if n > 1 else ''), \
                edit(forge), SEC

    # Value-log records (14 §5.3): an attacker repairs the record's CRC too.
    recs = vlog_records(base)
    plain = vlog_records(twin, encrypted=False) if twin else []
    for q, n in live_recs:
        loc = f'vlog record @{q}'
        def rec_edit(fn, q=q, n=n):
            return edit(lambda b: (fn(b), fix_record(b, q, n)))
        yield loc, 'nonce', rec_edit(lambda b: flip(b, q)), SEC
        yield loc, 'tree_id', rec_edit(lambda b: flip(b, q + 8)), SEC
        yield loc, 'ciphertext byte', rec_edit(lambda b: flip(b, q + 12 + (n - 32) // 2)), SEC
        yield loc, 'tag byte', rec_edit(lambda b: flip(b, q + n - 5)), SEC
        yield loc, 'ciphertext byte, CRC not repaired', edit(lambda b: flip(b, q + 12 + (n - 32) // 2)), HDR
        # Splice: another record of the same length, moved here (offset is in the AAD).
        for q2, n2 in recs:
            if q2 != q and n2 == n:
                yield loc, f'spliced from record @{q2}', edit(lambda b, q2=q2: b.__setitem__(
                    slice(q, q + n), base[q2:q2 + n])), SEC
                break
        # Forgery (F-127): a plaintext record with a valid CRC at a referenced offset.
        # It is shorter than the pointer's record (no nonce, no tag), so a reader
        # may refuse it on structure before any AEAD runs; it must never read it.
        # Both lengths are two-byte varints (128..16383), so the record starts where it did.
        fit = [(q2, n2) for q2, n2 in plain if 128 <= n2 <= n] if 128 <= n < 16384 else []
        if fit:
            q2, n2 = fit[0]
            yield loc, 'replaced by a forged plaintext record', edit(
                lambda b: b.__setitem__(slice(q - 2, q + n2), twin[q2 - 2:q2 + n2])), HDR
        if len(other) >= q + n and (q, n) in vlog_records(other):
            yield loc, 'spliced from another database', edit(lambda b: b.__setitem__(slice(q, q + n),
                                                                                   other[q:q + n])), SEC
    for h in pages(base):
        o = h['id'] * ps
        if live_recs and h['type'] == VLOG_SEGMENT:
            # 14 §8.3: a strict reader decrypts every record whatever byte 39 says.
            yield f'vlog segment page {h["id"]}', 'encrypted byte flipped', edit(
                lambda b, o=o, p=h['id']: (b.__setitem__(o + 40 + 39, b[o + 79] ^ 1), fix_page(b, p))), \
                {'tamper', 'ok-same'}
            yield f'vlog segment page {h["id"]}', 'nonce_base', edit(
                lambda b, o=o, p=h['id']: (flip(b, o + 40 + 40), fix_page(b, p))), HDR | {'ok-same'}  # records carry their own nonce

    s = newest_sb(base)
    so = sb_at(base, s)
    loc = f'superblock slot {"AB"[s]}'
    def sb_edit(fn):
        return edit(lambda b: (fn(b), fix_sb(b, s)))
    req = struct.unpack_from('<Q', base, so + SB_FEATURES_REQ)[0]
    if req:
        bit = req & -req   # T4: clear a feature the file needs; only the MAC can catch it
        yield loc, 'features_required bit cleared', sb_edit(
            lambda b: struct.pack_into('<Q', b, so + SB_FEATURES_REQ, req & ~bit)), SEC
    for field, off in (('cipher -> 0', None), ('commit_id', SB_COMMIT), ('features_required unknown bit', SB_FEATURES_REQ),
                       ('catalog_root', SB_CATALOG), ('database_uuid', SB_UUID), ('next_nonce', SB_NEXT_NONCE),
                       ('sb_mac', SB_MAC), ('writer_id', 256)):
        if off is None:
            yield loc, field, sb_edit(lambda b: b.__setitem__(so + SB_CIPHER, 0)), SEC
        else:
            # commit_id: raise it (bit 40), so the edited slot is still the one a reader picks.
            at = so + off + {SB_FEATURES_REQ: 2, SB_COMMIT: 5}.get(off, 0)
            yield loc, field, sb_edit(lambda b, at=at: flip(b, at)), \
                SEC | ({'unsupported'} if off == SB_FEATURES_REQ else set()) | \
                ({'wrongkey'} if off == SB_UUID else set())   # uuid is in the wrap AAD (§3.3)

    ks = so + SB_KEYSLOTS
    loc = 'keyslot 0'
    KEYS = {'wrongkey', 'tamper'}
    for field, off in (('kdf', 1), ('t_cost', 4), ('m_cost_kib', 8), ('parallelism', 12), ('salt', 16),
                       ('wrap_nonce', 48), ('wrapped_key', 72), ('wrap_tag', 104), ('label', 120)):
        if cred != 'pw' and field in ('t_cost', 'm_cost_kib', 'parallelism', 'salt'):
            val = lambda b, off=off: b.__setitem__(ks + off, 1)   # raw slot: these MUST be zero
        elif cred == 'pw' and field in ('t_cost', 'm_cost_kib', 'parallelism'):
            # Downgrade (T4): halve the cost the attacker would have to pay.
            val = lambda b, off=off: struct.pack_into('<I', b, ks + off,
                                                      max(1, struct.unpack_from('<I', b, ks + off)[0] // 2))
        else:
            val = lambda b, off=off: flip(b, ks + off)
        yield loc, field + (' lowered' if cred == 'pw' and field in ('t_cost', 'm_cost_kib', 'parallelism') else ''), \
            sb_edit(val), KEYS
    yield loc, 'moved to slot 1', sb_edit(lambda b: (b.__setitem__(slice(ks + SLOT, ks + 2 * SLOT), b[ks:ks + SLOT]),
                                                     b.__setitem__(slice(ks, ks + SLOT), bytes(SLOT)))), KEYS
    if other:
        oo = sb_at(other, newest_sb(other)) + SB_KEYSLOTS
        yield loc, 'copied from another database', sb_edit(
            lambda b: b.__setitem__(slice(ks, ks + SLOT), other[oo:oo + SLOT])), KEYS

    loc = 'file'
    last = max(live) if live else 2
    yield loc, 'truncated mid-page', base[:last * ps + ps // 2], HDR | {'unsupported'}
    yield loc, 'truncated by one page', base[:len(base) - ps], HDR | {'ok-same'}
    yield loc, 'extended by zero pages', base + bytes(3 * ps), HDR | {'ok-same'}
    yield loc, 'extended by a copy of a live page', base + base[last * ps:(last + 1) * ps], HDR | {'ok-same'}


# --- driver ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--impl', default='rust,java,dart')
    ap.add_argument('--writers', default=None, help='default: same as --impl')
    ap.add_argument('--pages', type=int, default=6, help='live pages attacked per file')
    ap.add_argument('--keep', help='keep the work directory here')
    ap.add_argument('--no-build', action='store_true')
    a = ap.parse_args()
    names = a.impl.split(',')
    writers = (a.writers or a.impl).split(',')
    work = a.keep or tempfile.mkdtemp(prefix='security_attack.')
    os.makedirs(work, exist_ok=True)
    im = Impls(sorted(set(names) | set(writers)), work)
    if not a.no_build:
        im.build()

    def make(w, name, cred, mutate=False, plain=False):
        f = os.path.join(work, f'{w}-{name}.cryptand')
        flag = [] if plain else (['--password', PASSWORD] if cred == 'pw' else ['--key', cred])
        for verb in (['write', f],) + ((['mutate', f, w],) if mutate else ()):
            subprocess.run(im.cmd[w] + verb + flag, check=True, capture_output=True,
                           cwd=os.path.join(REF, 'dart/cryptand'))
        return open(f, 'rb').read()

    failures, total, seen = [], 0, {}
    for w in writers:
        base_old = make(w, 'old', KEY)
        f = os.path.join(work, f'{w}-old.cryptand')
        subprocess.run(im.cmd[w] + ['mutate', f, w, '--key', KEY], check=True, capture_output=True,
                       cwd=os.path.join(REF, 'dart/cryptand'))
        base = open(f, 'rb').read()
        other = make(w, 'other', KEY, mutate=True)
        # The forger's page: same layout, different content (mutated under
        # another tag), plaintext, valid CRC. Accepting it is substitution.
        make(w, 'twin', None, plain=True)
        tf = os.path.join(work, f'{w}-twin.cryptand')
        subprocess.run(im.cmd[w] + ['mutate', tf, 'forged'], check=True, capture_output=True,
                       cwd=os.path.join(REF, 'dart/cryptand'))
        twin = open(tf, 'rb').read()
        pw = make(w, 'pw', 'pw')

        _, out = im.digest('rust', base, KEY)
        want = classify(0, out, None) and next(l[7:] for l in out.splitlines() if l.startswith('digest='))
        _, out = im.digest('rust', pw, 'pw')
        want_pw = next(l[7:] for l in out.splitlines() if l.startswith('digest='))

        # Live pages: those whose ciphertext the reader actually authenticates.
        live = []
        ps = page_size(base)
        for h in pages(base):
            if not h['flags'] & ENCRYPTED or len(live) >= a.pages:
                continue
            b = bytearray(base)
            flip(b, h['id'] * ps + 40 + h['stored'] // 2)
            fix_page(b, h['id'])
            if classify(*im.digest('rust', bytes(b), KEY), want) != 'ok-same':
                live.append(h['id'])
        # Live records the same way: first, middle and last whose change the reader sees.
        recs, live_recs = vlog_records(base), []
        for q, n in recs[::-1]:   # newest first: mutate supersedes the oldest
            if len(live_recs) >= 3:
                break
            b = bytearray(base)
            flip(b, q + 12 + (n - 32) // 2)
            fix_record(b, q, n)
            if classify(*im.digest('rust', bytes(b), KEY), want) != 'ok-same':
                live_recs.append((q, n))
        print(f'\n== {w}-written file: {len(base) // ps} pages, live pages attacked {live}, '
              f'{len(recs)} vlog records, live attacked {[q for q, _ in live_recs]}', flush=True)
        if not live:
            failures.append((w, '-', 'file', 'no live encrypted page found', 'the harness proves nothing'))
        if not live_recs:
            failures.append((w, '-', 'file', 'no live value-log record found', 'the vlog attacks prove nothing'))

        cases = [(c, KEY, want) for c in variants(base, KEY, twin, other, base_old, live, live_recs)]
        cases += [(c, 'pw', want_pw) for c in variants(pw, 'pw', b'', b'', b'', [])
                  if c[0].startswith('keyslot') and c[1] != 'copied from another database']
        for (loc, attack, data, allowed), cred, d0 in cases:
            row = []
            for r in names:
                got = classify(*im.digest(r, data, cred), d0)
                total += 1
                seen[got] = seen.get(got, 0) + 1
                row.append(f'{r}={got}')
                if got not in allowed:
                    failures.append((w, r, loc, attack + (' (password file)' if cred == 'pw' else ''),
                                     f'{got}, allowed {sorted(allowed)}'))
            print(f'   {loc:<18} {attack + (" [pw]" if cred == "pw" else ""):<40} {" ".join(row)}', flush=True)

    print(f'\n== result: {total} runs, outcomes {dict(sorted(seen.items()))}')
    for w, r, loc, attack, why in failures:
        print(f'   FAIL writer={w} reader={r} {loc}: {attack} -> {why}')
    if not a.keep:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
