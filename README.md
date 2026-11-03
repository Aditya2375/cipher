# cipher

Password file encryption from scratch in C: ChaCha20-Poly1305 AEAD,
PBKDF2-HMAC-SHA256 key derivation, a chunked tamper-evident file format,
and not one line of someone else's crypto. Every primitive is validated
against its published test vectors.

No dependencies beyond libc and an emscripten SDK for the web build.

## Try it

```sh
make build/cipher
build/cipher encrypt diary.txt          # prompts twice, writes diary.txt.cph
build/cipher decrypt diary.txt.cph      # prompts once, writes diary.txt
```

When stdin is not a terminal the password is read from stdin once
(encrypt reads two lines: password and confirmation).

## How it works

**Primitives** (`src/`): SHA-256 (FIPS 180-4), HMAC (RFC 2104), HKDF
(RFC 5869), PBKDF2-HMAC-SHA256 (RFC 8018), ChaCha20 and Poly1305
(RFC 8439), and the ChaCha20-Poly1305 AEAD construction. Poly1305 uses
five 26-bit limbs so every product fits in 64 bits; tags are compared
in constant time.

**Key derivation.** A fresh 16-byte salt per file; PBKDF2-HMAC-SHA256
with 600,000 iterations (capped at 10,000,000 when reading hostile
files) stretches the password into the 32-byte AEAD key.

**File format** (`src/format.h`):

```
header:  magic "CIPH" | version | kdf | iterations u32le | salt 16 | base nonce 12
chunk i: clen u32le | flags (bit0: final) | ciphertext | tag 16
         nonce = base nonce XOR le64(i)   aad = header || clen || flags || le64(i)
```

64 KB chunks are authenticated before their plaintext is released;
only the final chunk may be short or empty; the final chunk must be the
last bytes of the file. Truncation, reordering, splicing and bit flips
all fail the same way: `authentication failed`, exit 1, and no partial
output file is left behind. Encryption reads fresh randomness from
`/dev/urandom`; key material is zeroed after use.

## Deliberate simplifications

This is a teaching tool, not a replacement for age/gpg:

- ChaCha20 and Poly1305 are reference-style implementations,
  not guaranteed constant-time. Fine for a demo, wrong for real secrets on shared
  machines.
- The password KDF is PBKDF2, not a memory-hard function (scrypt/argon2).
- No key files, no public-key mode, no metadata beyond the header.
- Files are encrypted with one password; changing it means re-encrypting.

## Development

```sh
make test            # 28 unit checks: every RFC vector plus tamper cases
make sanitize        # the same under ASan/UBSan, plus a fuzz pass
sh tests/run-tests.sh   # CLI end-to-end: round trips, wrong password,
                        # tamper, truncation, trailing data, confirmation
python3 tests/fuzz.py   # mutated + random blobs at the parsers
```

Layout: `src/` the C core (crypto, AEAD, file format, CLI), `tests/`
unit, integration and fuzz suites, `wasm/` + `docs/` the browser demo.

28 unit checks, 8 integration checks, all green; CI runs every suite on
every push.
