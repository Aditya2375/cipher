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

# seeds: a real encrypted file plus structure-ish blobs
subprocess.run(["make", "-s", "build/test-fuzz"], check=True)
valid = subprocess.run(
    ["/bin/sh", "-c",
     "printf 'the quick brown fox jumps over the lazy dog' > /tmp/cipher-fuzz-src && "
     "printf 'pw\\npw\\n' | CIPHER_KDF_ITER=1 build/cipher encrypt /tmp/cipher-fuzz-src /tmp/cipher-fuzz.cph && "
     "cat /tmp/cipher-fuzz.cph"], capture_output=True, check=True).stdout
if not valid.startswith(b"CIPH"):
    sys.exit("fuzz setup broken: build/cipher did not produce a CIPH file")
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
