#!/bin/sh
# check-docs.sh - the README's claims must match the code. When a pinned
# number changes on purpose, change it here and in README.md together.
set -eu
cd "$(dirname "$0")/.."
fail() { echo "check-docs: $1" >&2; exit 1; }

UNIT=$(./build/test-unit | tail -1 | grep -o '^[0-9]*')
[ "$UNIT" = "28" ] || fail "unit checks: README says 28, binary says $UNIT"
grep -q "28 unit checks" README.md || fail "README no longer says 28 unit checks"
grep -q "8 integration checks" README.md || fail "README no longer says 8 integration checks"

for pin in "CIPHER_CHUNK (64 \* 1024)" "CIPHER_ITER_DEFAULT 600000" \
           "CIPHER_ITER_MAX 10000000u" "CIPHER_HEADER_LEN 38"; do
  grep -q "$pin" src/format.h || fail "format pin missing: $pin"
done
for claim in "600,000 iterations" "ChaCha20-Poly1305" "PBKDF2-HMAC-SHA256" \
             "16-byte salt" "constant time"; do
  grep -q "$claim" README.md || fail "README claim missing: $claim"
done
grep -q "not\s*guaranteed constant-time\|not.*constant-time" README.md \
  || fail "README lost the constant-time caveat"

# no stray AI/tooling mentions anywhere public-facing
! grep -ri --exclude=check-docs.sh "claude\|anthropic\|openai\|chatgpt\|copilot" \
  README.md docs/ src/ wasm/ tests/ .github/ Makefile 2>/dev/null \
  || fail "tooling mention found"
echo "check-docs ok"
