#!/usr/bin/env python3
"""M2.2 kill -9 torture. For each seed: generate an op-log, replay it in a child
process on a real file, SIGKILL the child after a random number of durable
acks plus a random delay, then reopen in the same language and check: it opens,
verify is clean, and the data equals the model at some op boundary at or after
the last acknowledged one (no acked write lost; every op all-or-nothing).

  tools/torture.py rust|java A B [oplog_gen knobs...]   seeds A..B-1
Failing logs and files are kept in reference/bench/runs/torture/.
"""
import os, random, signal, subprocess, sys, time

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rel = f"{root}/reference/rust/target/release"
out = f"{root}/reference/bench/runs/torture"


def build(lang):
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "cryptand", "--features", "harness",
                    "--bin", "oplog_gen", "--bin", "oplog_check"], cwd=f"{root}/reference/rust", check=True)
    if lang == "rust":
        return [f"{rel}/oplog_check"]
    java = f"{root}/reference/java"
    subprocess.run(["mvn", "-B", "-q", "test-compile", "-Djacoco.skip=true"], cwd=java, check=True)
    cp = f"{out}/cp"
    subprocess.run(["mvn", "-B", "-q", "dependency:build-classpath", f"-Dmdep.outputFile={cp}",
                    "-Dmdep.includeScope=test"], cwd=java, check=True)
    jcp = f"{java}/target/classes:{java}/target/test-classes:{open(cp).read().strip()}"
    return ["java", "-cp", jcp, "org.dizitart.cryptand.lsm.OplogCheckTest"]


def one(cmd, seed, knobs):
    log, db = f"{out}/s{seed}.jsonl", f"{out}/s{seed}.cff"
    with open(log, "w") as f:
        subprocess.run([f"{rel}/oplog_gen", "--seed", str(seed), *knobs], stdout=f, check=True)
    for p in (db, db + ".lock"):
        if os.path.exists(p):
            os.remove(p)
    acks = sum(1 for l in open(log) if '"d":"sync"' in l or '"d":"full"' in l
               or '"op":"checkpoint"' in l or '"op":"reopen"' in l)
    rng = random.Random(seed)
    target, delay = rng.randint(0, acks), rng.uniform(0, 0.02)
    err = open(f"{out}/s{seed}.err", "w")
    child = subprocess.Popen([*cmd, "--child", log, db], stdout=subprocess.PIPE, stderr=err, text=True)
    last, seen, killed, said = 1, 0, False, ""
    if target == 0:
        time.sleep(delay)
        child.send_signal(signal.SIGKILL)
        killed = True
    created = False
    for line in child.stdout:
        created = created or line.startswith("created")
        if not line.startswith("ack ") and not line.startswith("created"):
            said = line.strip() or said
        if line.startswith("ack "):
            last, seen = int(line.split()[1]), seen + 1
            if seen == target and not killed:
                time.sleep(delay)
                child.send_signal(signal.SIGKILL)
                killed = True
    child.wait()
    err.close()
    if not created and killed:
        # Killed inside create(): nothing was promised, the file may be anything.
        os.remove(log)
        for p in (db, db + ".lock", f"{out}/s{seed}.err"):
            if os.path.exists(p):
                os.remove(p)
        return True, f"seed {seed}: killed before create() returned"
    if not killed and child.returncode != 0:
        tail = open(f"{out}/s{seed}.err").read().strip().splitlines()
        return False, f"seed {seed}: child failed on its own after ack {seen}: {said or (tail[0] if tail else child.returncode)}"
    os.remove(f"{out}/s{seed}.err")
    r = subprocess.run([*cmd, "--after-kill", log, db, str(last)], capture_output=True, text=True)
    res = (r.stdout + r.stderr).strip().splitlines()
    ok = r.returncode == 0 and res and res[-1].startswith("ok")
    if ok:
        # The backup op writes s<seed>.bak (Rust) or s<seed>.cff.bak (Java).
        for p in (log, db, db[:-4] + ".bak", db + ".bak"):  # an erase may have removed the file already
            if os.path.exists(p):
                os.remove(p)
    return ok, f"seed {seed}: killed after ack {seen}/{acks} (line {last}): {res[-1] if res else 'no output'}"


def main():
    lang, a, b, knobs = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4:]
    os.makedirs(out, exist_ok=True)
    cmd = build(lang)
    fails = 0
    for seed in range(a, b):
        ok, msg = one(cmd, seed, knobs)
        if not ok:
            fails += 1
            print("FAIL " + msg, flush=True)
        elif (seed - a) % 100 == 99:
            print(f"{seed - a + 1} kills, {fails} failures", flush=True)
    print(f"{lang} seeds {a}..{b}: {b - a} kills, {fails} failures")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
