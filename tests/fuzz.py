#!/usr/bin/env python3
"""Feed mutated and random blobs at the fuzz driver; any nonzero exit,
crash or sanitizer report fails."""
import argparse, os, random, subprocess, sys

p = argparse.ArgumentParser()
p.add_argument("--blobs", type=int, default=200)
p.add_argument("--seed", type=int, default=1)
p.add_argument("--driver", default="build/test-fuzz")
a = p.parse_args()
rng = random.Random(a.seed)

def run(blob, label):
    r = subprocess.run([a.driver], input=blob, capture_output=True)
    if r.returncode != 0 or b"runtime error" in r.stderr or b"AddressSanitizer" in r.stderr:
        sys.stderr.write("fuzz failure (%s): rc=%d\n%s\n" % (label, r.returncode, r.stderr[:400]))
        sys.exit(1)

# Seed with a real encrypted file in a private scratch directory.
import tempfile
subprocess.run(["make", "-s", "build/test-fuzz", "build/cipher"], check=True)
with tempfile.TemporaryDirectory(prefix="cipher-fuzz-") as td:
    source = os.path.join(td, "source")
    target = os.path.join(td, "encrypted")
    with open(source, "wb") as f:
        f.write(bytes(range(256)) * 512)
    env = dict(os.environ, CIPHER_KDF_ITER="1")
    subprocess.run(["build/cipher", "encrypt", source, target], input=b"pw\npw\n",
                   capture_output=True, check=True, env=env)
    with open(target, "rb") as f:
        valid = f.read()
if not valid.startswith(b"CIPH"):
    sys.exit("fuzz setup broken: expected a CIPH container")
run(valid, "valid file decrypts without incident")
for i in range(a.blobs):
    if i % 3 == 0:
        b = bytearray(valid)
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        run(bytes(b), "mutation %d" % i)
    elif i % 3 == 1:
        run(bytes(rng.randrange(256) for _ in range(rng.randrange(0, 600))), "random %d" % i)
    else:
        cut = rng.randrange(len(valid))
        run(valid[:cut], "truncation %d" % i)
print("fuzz ok: %d blobs, seed %d" % (a.blobs, a.seed))
