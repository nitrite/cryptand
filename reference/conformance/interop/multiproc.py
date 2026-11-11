#!/usr/bin/env python3
"""13-operations.md §8 across languages (PLAN A1.5): a writer process in one
language, a reader process in another. The reader pins commit N, the writer
overwrites, compacts and shrinks, then the reader scans its snapshot whole.

    reference/conformance/interop/multiproc.py [rust java dart]

Children: Rust `multiproc_test mp_child`, Java `MultiprocChild`, Dart
`tool/multiproc_child.dart`. Each prints `ready commit=N` / `churned floor=F`
as a writer and `mode=...` / `rows=R bad=B` as a reader.
"""
import json
import os
import select
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUST = os.path.join(ROOT, "rust")
JAVA = os.path.join(ROOT, "java")
DART = os.path.join(ROOT, "dart", "cryptand")
ROWS = 5000


def rust_exe():
    out = subprocess.run(
        ["cargo", "test", "-q", "-p", "cryptand", "--test", "multiproc_test", "--no-run",
         "--message-format=json"], cwd=RUST, check=True, capture_output=True, text=True).stdout
    for line in out.splitlines():
        m = json.loads(line)
        if m.get("executable") and m.get("target", {}).get("name") == "multiproc_test":
            return m["executable"]
    raise SystemExit("multiproc_test executable not found")


def command(lang, role, path, built):
    if lang == "rust":
        env = dict(os.environ, CRYPTAND_MP_CHILD=path, CRYPTAND_MP_ROLE=role)
        return [built["rust"], "mp_child", "--exact", "--nocapture", "--test-threads=1"], env
    if lang == "java":
        cp = os.pathsep.join([os.path.join(JAVA, "target", "classes"), os.path.join(JAVA, "target", "test-classes")])
        return ["java", "-cp", cp, "org.dizitart.cryptand.MultiprocChild", role, path], None
    if lang == "dart":
        return [built["dart"], role, path], None
    raise SystemExit("unknown language " + lang)


def build(langs):
    built = {}
    if "rust" in langs:
        built["rust"] = rust_exe()
    if "java" in langs:
        subprocess.run(["mvn", "-B", "-q", "test-compile"], cwd=JAVA, check=True)
    if "dart" in langs:
        exe = os.path.join(tempfile.gettempdir(), "cryptand-multiproc-child")
        subprocess.run(["dart", "compile", "exe", "tool/multiproc_child.dart", "-o", exe],
                       cwd=DART, check=True, capture_output=True)
        built["dart"] = exe
    return built


class Child:
    def __init__(self, lang, role, path, built):
        cmd, env = command(lang, role, path, built)
        self.p = subprocess.Popen(cmd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def line(self, prefix, timeout=180):
        while True:
            r, _, _ = select.select([self.p.stdout], [], [], timeout)
            if not r:
                raise AssertionError("timed out waiting for " + prefix)
            l = self.p.stdout.readline()
            if not l:
                raise AssertionError("exited before " + prefix)
            if prefix in l:
                return l[l.index(prefix):].strip()

    def send(self):
        self.p.stdin.write("next\n")
        self.p.stdin.flush()

    def close(self):
        try:
            self.send()
        except BrokenPipeError:
            pass
        try:
            self.p.wait(30)
        except subprocess.TimeoutExpired:
            self.p.kill()


def pair(w, r, built):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "mp.cryptand")
        writer = Child(w, "writer", path, built)
        reader = None
        try:
            n = int(writer.line("ready commit=").split("=")[1])
            reader = Child(r, "reader", path, built)
            mode = reader.line("mode=")
            assert mode.startswith("mode=slotted") and mode.endswith("commit=%d" % n), mode
            writer.send()
            floor = int(writer.line("churned floor=").split("=")[1])
            assert floor < n, "floor %d not held below the pin %d" % (floor, n)
            reader.send()
            got = reader.line("rows=")
            assert got == "rows=%d bad=0" % ROWS, got
            return "pinned %d, floor %d, %s" % (n, floor, got)
        finally:
            if reader:
                reader.close()
            writer.close()


def main():
    langs = sys.argv[1:] or ["rust", "java", "dart"]
    built = build(langs)
    failed = 0
    for w in langs:
        for r in langs:
            try:
                print("   ok   %s writer, %s reader: %s" % (w, r, pair(w, r, built)))
            except AssertionError as e:
                failed += 1
                print("   FAIL %s writer, %s reader: %s" % (w, r, e))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
