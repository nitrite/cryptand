#!/usr/bin/env python3
"""PLAN 6.7 soak. Runs `rss_scale PATH N soak SEED` (Rust) or `RssScale PATH N
soak SEED` (Java) or `scale soak PATH N SEED` (Dart) on an existing N-document file, SIGKILLs it after 10-30 min,
restarts it (the child verifies on open), for HOURS, then a final verify.
SOAK_KILL_S=lo,hi overrides the kill window in seconds (smoke tests). Every 30 s it samples RSS,
open fds and file bytes into OUT/samples.csv; each cycle's peaks go to
OUT/cycles.csv. Fails on any unsound verify, or when a metric's peak over the
last third of cycles is >10% above the first third (monotonic growth).

  tools/soak.py rust|java|dart PATH N HOURS OUT
Build the base first: `rss_scale PATH N` / `RssScale PATH N` / `scale build PATH N`.
Java runs with a fixed heap (SOAK_JAVA_XMX, default 3g): an uncapped JVM grows
its heap lazily toward 1/4 of RAM, which the growth check reads as a leak.
"""
import csv, os, random, signal, subprocess, sys, time

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def command(lang):
    if lang == "rust":
        rs = f"{root}/reference/rust"
        subprocess.run(["cargo", "build", "-q", "--release", "--example", "rss_scale"], cwd=rs, check=True)
        return [f"{rs}/target/release/examples/rss_scale"], lambda p, n, s: [p, str(n), "soak", str(s)]
    if lang == "dart":
        d = f"{root}/reference/dart/cryptand"
        os.makedirs(f"{d}/build", exist_ok=True)
        subprocess.run(["dart", "compile", "exe", "tool/scale.dart", "-o", "build/scale"], cwd=d, check=True,
                       stdout=subprocess.DEVNULL)
        return [f"{d}/build/scale"], lambda p, n, s: ["soak", p, str(n), str(s)]
    java = f"{root}/reference/java"
    subprocess.run(["mvn", "-B", "-q", "test-compile", "-Djacoco.skip=true"], cwd=java, check=True)
    cp = f"{java}/target/soak-cp.txt"
    subprocess.run(["mvn", "-B", "-q", "dependency:build-classpath", f"-Dmdep.outputFile={cp}",
                    "-Dmdep.includeScope=test"], cwd=java, check=True)
    jcp = f"{java}/target/classes:{java}/target/test-classes:{open(cp).read().strip()}"
    xmx = os.environ.get("SOAK_JAVA_XMX", "3g")
    return ["java", f"-Xms{xmx}", f"-Xmx{xmx}", "-cp", jcp, "org.dizitart.cryptand.bench.RssScale"], lambda p, n, s: [p, str(n), "soak", str(s)]


def sample(pid, path):
    rss = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    fds = subprocess.run(["lsof", "-p", str(pid)], capture_output=True, text=True).stdout.count("\n") - 1
    d, base = os.path.split(path)
    size = sum(os.path.getsize(os.path.join(d, f)) for f in os.listdir(d) if f.startswith(base))
    return int(rss or 0) >> 10, max(fds, 0), size


def main(lang, path, n, hours, out):
    os.makedirs(out, exist_ok=True)
    exe, args = command(lang)
    end, cycle, bad = time.time() + float(hours) * 3600, 0, 0
    samples = csv.writer(open(f"{out}/samples.csv", "a", buffering=1))
    cycles = csv.writer(open(f"{out}/cycles.csv", "a", buffering=1))
    samples.writerow(["t", "cycle", "rss_mb", "fds", "bytes"])
    cycles.writerow(["cycle", "verify_ms", "sound", "acked", "peak_rss_mb", "peak_fds", "peak_bytes"])
    peaks = []
    kill_s = [float(x) for x in os.environ.get("SOAK_KILL_S", "600,1800").split(",")]
    while time.time() + kill_s[0] < end:  # no cycle the deadline would cut short
        cycle += 1
        log = open(f"{out}/cycle{cycle}.log", "w")
        p = subprocess.Popen(exe + args(path, n, cycle), stdout=subprocess.PIPE, stderr=log, text=True)
        verify = p.stdout.readline().strip()  # blocks through open + verify
        print(f"cycle {cycle}: {verify}", flush=True)
        sound = "verify_sound=true" in verify
        bad += not sound
        os.set_blocking(p.stdout.fileno(), False)
        kill_at, acked, peak = time.time() + random.uniform(*kill_s), 0, (0, 0, 0)
        while time.time() < min(kill_at, end) and p.poll() is None:
            time.sleep(30)
            for line in p.stdout.readlines():
                if line.startswith("acked="):
                    acked = int(line[6:])
            s = sample(p.pid, path)
            samples.writerow([int(time.time()), cycle, *s])
            peak = tuple(map(max, peak, s))
        if p.poll() is not None:
            print(f"cycle {cycle}: child exited {p.returncode}, see {out}/cycle{cycle}.log", flush=True)
            bad += 1
        p.send_signal(signal.SIGKILL)
        p.wait()
        cycles.writerow([cycle, verify.split()[0][10:] if verify else "", sound, acked, *peak])
        peaks.append(peak)
        if not sound:
            break  # keep the file for diagnosis
    if bad == 0:  # the last kill gets its reopen + verify too
        p = subprocess.Popen(exe + args(path, n, 0), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        verify = p.stdout.readline().strip()
        p.kill()
        p.wait()
        print(f"final: {verify}", flush=True)
        bad += "verify_sound=true" not in verify
    third = max(len(peaks) // 3, 1)
    for i, name in enumerate(["rss_mb", "fds", "bytes"]):
        first, last = max(p[i] for p in peaks[:third]), max(p[i] for p in peaks[-third:])
        grew = last > first * 1.1
        bad += grew
        print(f"{name}: first-third peak {first}, last-third peak {last}{'  GREW' if grew else ''}")
    print(f"soak {lang}: {cycle} cycles, {'FAIL' if bad else 'PASS'}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main(*sys.argv[1:])
