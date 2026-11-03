#!/bin/sh
# run-tests.sh - end-to-end CLI tests in a scratch directory.
set -eu
cd "$(dirname "$0")/.."
BIN=build/cipher
make -s "$BIN" >/dev/null 2>&1 || make -s >/dev/null
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
PASS=0
ok() { PASS=$((PASS + 1)); echo "ok $PASS - $1"; }
die() { echo "not ok - $1" >&2; exit 1; }
export CIPHER_KDF_ITER=1000

printf 'attack at dawn\n' > $T/msg.txt
head -c 200000 /dev/urandom > $T/big.bin
: > $T/empty.txt

printf 'hunter2\nhunter2\n' | $BIN encrypt $T/msg.txt >/dev/null
printf 'hunter2\n' | $BIN decrypt $T/msg.txt.cph $T/msg.out >/dev/null
cmp -s $T/msg.txt $T/msg.out && ok "round trip: small file" || die "small round trip"

printf 'hunter2\nhunter2\n' | $BIN encrypt $T/big.bin >/dev/null
printf 'hunter2\n' | $BIN decrypt $T/big.bin.cph $T/big.out >/dev/null
cmp -s $T/big.bin $T/big.out && ok "round trip: multi-chunk file" || die "big round trip"

printf 'hunter2\nhunter2\n' | $BIN encrypt $T/empty.txt >/dev/null
printf 'hunter2\n' | $BIN decrypt $T/empty.txt.cph $T/empty.out >/dev/null
cmp -s $T/empty.txt $T/empty.out && ok "round trip: empty file" || die "empty round trip"

if printf 'wrong\n' | $BIN decrypt $T/msg.txt.cph $T/w.out 2>/dev/null; then
    die "wrong password accepted"
fi
[ ! -e $T/w.out ] && ok "wrong password: rejected, no output left" || die "partial output left"

cp $T/msg.txt.cph $T/tampered.cph
printf '\\x01' | dd of=$T/tampered.cph bs=1 seek=45 conv=notrunc 2>/dev/null
if printf 'hunter2\n' | $BIN decrypt $T/tampered.cph $T/t.out 2>/dev/null; then
    die "tampered ciphertext accepted"
fi
[ ! -e $T/t.out ] && ok "tampered chunk: rejected, no output left" || die "partial output left"

head -c 40 $T/msg.txt.cph > $T/trunc.cph
if printf 'hunter2\n' | $BIN decrypt $T/trunc.cph $T/t2.out 2>/dev/null; then
    die "truncated file accepted"
fi
[ ! -e $T/t2.out ] && ok "truncated file: rejected, no output left" || die "partial output left"

cat $T/msg.txt.cph $T/msg.txt.cph > $T/double.cph
if printf 'hunter2\n' | $BIN decrypt $T/double.cph $T/d.out 2>/dev/null; then
    die "appended data accepted"
fi
[ ! -e $T/d.out ] && ok "trailing data after final chunk: rejected" || die "partial output left"

printf 'a\nb\n' | $BIN encrypt $T/msg.txt $T/mismatch.cph 2>/dev/null && die "mismatched passwords accepted"
[ ! -e $T/mismatch.cph ] && ok "mismatched password confirmation refused" || die "mismatch left output"

# An output destination must never overwrite a file or follow a link.
printf 'keep me' > "$T/keep"
if printf 'pw\npw\n' | $BIN encrypt "$T/msg.txt" "$T/keep" 2>/dev/null; then die "overwrote output"; fi
[ "$(cat "$T/keep")" = "keep me" ] && ok "existing output preserved" || die "output modified"
ln -s "$T/msg.txt" "$T/link"
if printf 'pw\npw\n' | $BIN encrypt "$T/msg.txt" "$T/link" 2>/dev/null; then die "followed symlink"; fi
[ -L "$T/link" ] && ok "symlink output refused" || die "link removed"
ln "$T/msg.txt" "$T/hard"
if printf 'pw\npw\n' | $BIN encrypt "$T/msg.txt" "$T/hard" 2>/dev/null; then die "followed hard link"; fi
[ "$(cat "$T/hard")" = "attack at dawn" ] && ok "hard-link output refused" || die "input destroyed"
[ "$(stat -c %a "$T/msg.out")" = 600 ] && ok "plaintext output is owner-only" || die "plaintext permissions"
python3 -c 'print("x"*300); print("x"*300)' | $BIN encrypt "$T/msg.txt" "$T/long" 2>/dev/null && die "long password accepted"
[ ! -e "$T/long" ] && ok "overlong password rejected, not truncated" || die "password output left"
head -c 65536 /dev/urandom > "$T/exact"
printf 'pw\npw\n' | $BIN encrypt "$T/exact" >/dev/null
printf 'pw\n' | $BIN decrypt "$T/exact.cph" "$T/exact.out" >/dev/null
cmp "$T/exact" "$T/exact.out" && ok "exact chunk boundary round trip" || die "boundary failed"
echo "all $PASS integration checks passed"
