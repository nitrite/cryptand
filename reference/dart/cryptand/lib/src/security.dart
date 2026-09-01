/// Security: the parts of `spec/14-security.md` that are byte layout and
/// keyed hashing.
///
/// **What is here:** SHA-256, HMAC-SHA256, HKDF-SHA256, subkey derivation
/// (section 3.4), nonce construction (section 4.2), the keyslot layout
/// (section 3.3), and the superblock MAC (section 6.2). Each has RFC test
/// vectors, which `test/security_test.dart` checks against.
///
/// **What is not here, and why:** XChaCha20-Poly1305 and Argon2id.
/// `REPORT.md` states the reasoning; in short, a reference implementation that
/// ships an *unverified* AEAD or KDF would have other SDKs match its errors,
/// and the environment this was written in cannot check either against
/// canonical vectors. The layouts they live in are implemented and tested, so
/// adding the two primitives is a drop-in.
library;

import 'dart:typed_data';

import 'bytes.dart';
import 'container.dart';
import 'errors.dart';

// ---------------------------------------------------------------------------
// SHA-256, FIPS 180-4
// ---------------------------------------------------------------------------

const List<int> _k = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

int _rotr(int x, int n) => ((x >>> n) | (x << (32 - n))) & 0xFFFFFFFF;

/// SHA-256 of [data]. 32 bytes.
Uint8List sha256(List<int> data) {
  final h = <int>[
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];
  final bitLen = data.length * 8;
  final padLen = ((55 - data.length) % 64 + 64) % 64 + 1;
  final msg = Uint8List(data.length + padLen + 8)..setRange(0, data.length, data);
  msg[data.length] = 0x80;
  final bd = ByteData.view(msg.buffer);
  bd.setUint64(msg.length - 8, bitLen);

  final w = Int32List(64);
  for (var block = 0; block < msg.length; block += 64) {
    for (var i = 0; i < 16; i++) {
      w[i] = bd.getUint32(block + i * 4);
    }
    for (var i = 16; i < 64; i++) {
      final x = w[i - 15] & 0xFFFFFFFF, y = w[i - 2] & 0xFFFFFFFF;
      final s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >>> 3);
      final s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >>> 10);
      w[i] = ((w[i - 16] & 0xFFFFFFFF) + s0 + (w[i - 7] & 0xFFFFFFFF) + s1) &
          0xFFFFFFFF;
    }
    var a = h[0], b = h[1], c = h[2], d = h[3];
    var e = h[4], f = h[5], g = h[6], hh = h[7];
    for (var i = 0; i < 64; i++) {
      final s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
      final ch = (e & f) ^ (~e & g);
      final t1 = (hh + s1 + ch + _k[i] + (w[i] & 0xFFFFFFFF)) & 0xFFFFFFFF;
      final s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final t2 = (s0 + maj) & 0xFFFFFFFF;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) & 0xFFFFFFFF;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & 0xFFFFFFFF;
    }
    h[0] = (h[0] + a) & 0xFFFFFFFF;
    h[1] = (h[1] + b) & 0xFFFFFFFF;
    h[2] = (h[2] + c) & 0xFFFFFFFF;
    h[3] = (h[3] + d) & 0xFFFFFFFF;
    h[4] = (h[4] + e) & 0xFFFFFFFF;
    h[5] = (h[5] + f) & 0xFFFFFFFF;
    h[6] = (h[6] + g) & 0xFFFFFFFF;
    h[7] = (h[7] + hh) & 0xFFFFFFFF;
  }
  final out = Uint8List(32);
  final ob = ByteData.view(out.buffer);
  for (var i = 0; i < 8; i++) {
    ob.setUint32(i * 4, h[i]);
  }
  return out;
}

/// HMAC-SHA256, RFC 2104.
Uint8List hmacSha256(List<int> key, List<int> message) {
  var k = Uint8List.fromList(key);
  if (k.length > 64) k = sha256(k);
  final pad = Uint8List(64)..setRange(0, k.length, k);
  final inner = Uint8List(64), outer = Uint8List(64);
  for (var i = 0; i < 64; i++) {
    inner[i] = pad[i] ^ 0x36;
    outer[i] = pad[i] ^ 0x5C;
  }
  final innerHash = sha256(Uint8List(64 + message.length)
    ..setRange(0, 64, inner)
    ..setRange(64, 64 + message.length, message));
  return sha256(Uint8List(96)
    ..setRange(0, 64, outer)
    ..setRange(64, 96, innerHash));
}

/// HKDF-SHA256, RFC 5869.
Uint8List hkdf(List<int> ikm, List<int> salt, List<int> info, int length) {
  if (length > 255 * 32) {
    throw const InvalidArgumentException('HKDF output longer than 255 * HashLen');
  }
  final prk = hmacSha256(salt, ikm);
  final out = Uint8List(length);
  var t = <int>[];
  var pos = 0;
  for (var i = 1; pos < length; i++) {
    t = hmacSha256(prk, <int>[...t, ...info, i]);
    final n = (length - pos) < 32 ? (length - pos) : 32;
    out.setRange(pos, pos + n, t);
    pos += n;
  }
  return out;
}

/// Constant-time byte comparison.
///
/// `spec/14-security.md` section 2: "An implementation MUST use a constant-time
/// tag comparison. A byte-by-byte early-exit compare on a Poly1305 or HMAC tag
/// is a forgery oracle."
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

// ---------------------------------------------------------------------------
// Subkeys, section 3.4
// ---------------------------------------------------------------------------

/// Subkey purposes, section 3.4.
class Purpose {
  static const String page = 'page';
  static const String vlog = 'vlog';
  static const String sbMac = 'sbmac';
}

/// ```
/// salt   = database_uuid
/// ikm    = master key
/// info   = "cryptand/v1/" || purpose
/// subkey = HKDF-Expand(HKDF-Extract(salt, ikm), info, 32)
/// ```
///
/// Using `database_uuid` as the salt is what makes two files with the same
/// password have different content keys, so a nonce that repeats across files
/// is harmless.
Uint8List deriveSubkey(
    List<int> masterKey, List<int> databaseUuid, String purpose) {
  if (masterKey.length != 32) {
    throw const InvalidArgumentException('master key is 32 bytes');
  }
  if (databaseUuid.length != 16) {
    throw const InvalidArgumentException('database_uuid is 16 bytes');
  }
  return hkdf(masterKey, databaseUuid, encodeUtf8Strict('cryptand/v1/$purpose'), 32);
}

// ---------------------------------------------------------------------------
// Nonces, section 4.2
// ---------------------------------------------------------------------------

/// Nonce domains, section 4.2.
class NonceDomain {
  static const int page = 1;
  static const int vlogRecord = 2;
  static const int keyWrap = 3;
}

/// The gap a writer leaves past the last durably published `next_nonce`
/// before it must publish a new floor. Section 4.1.
const int kNonceGap = 1 << 20;

/// ```
/// nonce := u8 domain || u64 counter || u64 object_id || u56 offset
/// ```
/// 1 + 8 + 8 + 7 = 24 bytes, little-endian throughout.
Uint8List buildNonce(int domain, int counter, int objectId, int offset) {
  if (domain < 1 || domain > 255) {
    throw InvalidArgumentException('nonce domain $domain out of range');
  }
  if (offset < 0 || offset >= (1 << 56)) {
    throw InvalidArgumentException('nonce offset $offset does not fit u56');
  }
  final out = Uint8List(24);
  out[0] = domain;
  final bd = ByteData.view(out.buffer);
  bd
    ..setUint64(1, counter, Endian.little)
    ..setUint64(9, objectId, Endian.little);
  for (var i = 0; i < 7; i++) {
    out[17 + i] = (offset >>> (8 * i)) & 0xFF;
  }
  return out;
}

/// Allocates nonce counters under the watermark discipline of section 4.1.
///
/// `next_nonce` is a **reservation watermark**, not a counter: every value
/// below it may already have been allocated, every value at or above it has
/// not. Three rules, and any two of them leave a hole:
///
///   1. on open, publish `persisted + 2^20` durably **before allocating
///      anything**;
///   2. allocate upward from `persisted`, never reaching what was published;
///   3. on reaching it, publish `published + 2^20` and only then continue.
///
/// Rule 1 is the one an earlier draft of the spec omitted. Without it a
/// session that crashes without publishing leaves the watermark unmoved, the
/// next session computes the same start, and the same nonces are handed out
/// twice — which for a stream cipher discloses both plaintexts and the
/// authentication key, with every affected page still verifying perfectly.
/// `test/security_test.dart` is where that was caught.
final class NonceAllocator {
  NonceAllocator._(this._next, this._published);

  /// Opens at a persisted watermark. [publish] is called with the value that
  /// MUST be durable before the first allocation; a caller that cannot make it
  /// durable must not proceed.
  factory NonceAllocator.open(
      int persistedNextNonce, void Function(int nextNonce) publish) {
    final floor = persistedNextNonce + kNonceGap;
    publish(floor); // rule 1: durable before anything is allocated
    return NonceAllocator._(persistedNextNonce, floor);
  }

  int _next;
  int _published;

  int get next => _next;

  /// The watermark currently durable.
  int get publishedWatermark => _published;

  /// Whether a new watermark must be published before allocating again.
  bool get mustPublish => _next >= _published;

  /// The value to publish next.
  int get toPublish => _published + kNonceGap;

  int allocate() {
    if (mustPublish) {
      throw StateError(
          'nonce watermark reached at $_next: publish next_nonce = $toPublish '
          'durably before allocating again (spec/14-security.md section 4.1)');
    }
    return _next++;
  }

  /// Records that a superblock carrying [watermark] is durable.
  void published(int watermark) {
    if (watermark <= _published) {
      throw const InvalidArgumentException(
          'the nonce watermark must strictly advance, or a crash reissues '
          'values the previous session allocated');
    }
    _published = watermark;
  }
}

// ---------------------------------------------------------------------------
// Keyslots, section 3.3
// ---------------------------------------------------------------------------

/// One 144-byte keyslot.
final class Keyslot {
  Keyslot({
    required this.state,
    required this.kdf,
    required this.tCost,
    required this.mCostKib,
    required this.parallelism,
    required this.salt,
    required this.wrapNonce,
    required this.wrappedKey,
    required this.wrapTag,
    required this.label,
  }) {
    if (salt.length != 32) throw const InvalidArgumentException('salt is 32 B');
    if (wrapNonce.length != 24) {
      throw const InvalidArgumentException('wrap_nonce is 24 B');
    }
    if (wrappedKey.length != 32) {
      throw const InvalidArgumentException('wrapped_key is 32 B');
    }
    if (wrapTag.length != 16) {
      throw const InvalidArgumentException('wrap_tag is 16 B');
    }
    if (encodeUtf8Strict(label).length > 16) {
      throw const InvalidArgumentException('label exceeds 16 B');
    }
  }

  static const int size = Sb.keyslotSize; // 144
  static const int empty = 0;
  static const int occupied = 1;
  static const int kdfRaw = 0;
  static const int kdfArgon2id = 1;

  final int state;
  final int kdf;
  final int tCost;
  final int mCostKib;
  final int parallelism;
  final Uint8List salt;
  final Uint8List wrapNonce;
  final Uint8List wrappedKey;
  final Uint8List wrapTag;
  final String label;

  Uint8List encode() {
    final out = Uint8List(size);
    final bd = ByteData.view(out.buffer);
    final labelBytes = encodeUtf8Strict(label);
    bd
      ..setUint8(0, state)
      ..setUint8(1, kdf)
      ..setUint8(2, labelBytes.length)
      ..setUint8(3, 0)
      ..setUint32(4, tCost, Endian.little)
      ..setUint32(8, mCostKib, Endian.little)
      ..setUint32(12, parallelism, Endian.little);
    out
      ..setRange(16, 48, salt)
      ..setRange(48, 72, wrapNonce)
      ..setRange(72, 104, wrappedKey)
      ..setRange(104, 120, wrapTag)
      ..setRange(120, 120 + labelBytes.length, labelBytes);
    return out;
  }

  static Keyslot decode(Uint8List raw, int index) {
    if (raw.length < size) {
      throw const CorruptionException('keyslot shorter than 144 bytes');
    }
    final bd = ByteData.view(raw.buffer, raw.offsetInBytes, size);
    final state = bd.getUint8(0);
    if (state > 1) {
      throw CorruptionException('keyslot $index state ${bd.getUint8(0)} is not 0 or 1');
    }
    final labelLen = bd.getUint8(2);
    if (labelLen > 16) {
      throw CorruptionException('keyslot $index label_len $labelLen exceeds 16');
    }
    return Keyslot(
      state: state,
      kdf: bd.getUint8(1),
      tCost: bd.getUint32(4, Endian.little),
      mCostKib: bd.getUint32(8, Endian.little),
      parallelism: bd.getUint32(12, Endian.little),
      salt: Uint8List.fromList(raw.sublist(16, 48)),
      wrapNonce: Uint8List.fromList(raw.sublist(48, 72)),
      wrappedKey: Uint8List.fromList(raw.sublist(72, 104)),
      wrapTag: Uint8List.fromList(raw.sublist(104, 120)),
      label: String.fromCharCodes(raw.sublist(120, 120 + labelLen)),
    );
  }

  /// AAD for the wrap: `database_uuid || slot_index : u8`.
  ///
  /// This binds a slot to its file, so a keyslot lifted from another database
  /// does not unwrap here — threat T3.
  static Uint8List wrapAad(List<int> databaseUuid, int slotIndex) {
    final out = Uint8List(17)..setRange(0, 16, databaseUuid);
    out[16] = slotIndex;
    return out;
  }

  /// The minimum Argon2id cost a writer may *create* a slot with, section 3.2.
  static void checkCreateCost(int tCost, int mCostKib, int parallelism) {
    if (tCost < 2 || mCostKib < 16384 || parallelism < 1) {
      throw InvalidArgumentException(
          'Argon2id cost t=$tCost m=${mCostKib}KiB p=$parallelism is below the '
          'floor a writer may create (t>=2, m>=16384, p>=1)');
    }
  }
}

// ---------------------------------------------------------------------------
// Superblock MAC, section 6.2
// ---------------------------------------------------------------------------

/// ```
/// sb_mac = HMAC-SHA256(
///     key = subkey("sbmac"),
///     msg = superblock bytes 0..4091, with bytes 296..327 zeroed )
/// ```
Uint8List superblockMac(List<int> sbMacKey, Uint8List superblock) {
  if (superblock.length < Sb.size) {
    throw const InvalidArgumentException('superblock is 4096 bytes');
  }
  final msg = Uint8List(Sb.checksum)
    ..setRange(0, Sb.checksum, superblock);
  for (var i = Sb.sbMac; i < Sb.sbMac + 32; i++) {
    msg[i] = 0;
  }
  return hmacSha256(sbMacKey, msg);
}

/// Verifies [superblock]'s MAC in constant time.
///
/// Section 6.2: a mismatch is **tampering**, reported distinctly from
/// corruption, and nothing else in the superblock may be acted on first.
void verifySuperblockMac(List<int> sbMacKey, Uint8List superblock) {
  final stored = superblock.sublist(Sb.sbMac, Sb.sbMac + 32);
  if (!constantTimeEquals(stored, superblockMac(sbMacKey, superblock))) {
    throw const TamperException(
        'superblock MAC mismatch: this file has been modified by someone '
        'without the key (spec/14-security.md section 6.2)');
  }
}
