#!/bin/sh
# Rebuild the browser demo strictly from source. Requires emsdk on PATH.
set -eu
cd "$(dirname "$0")/.."
emcc -O2 -Isrc \
  src/sha256.c src/hmac.c src/pbkdf2.c src/chacha20.c src/poly1305.c \
  src/aead.c src/format.c wasm/cipher_wasm.c \
  -o docs/cipher.js \
  -sEXPORTED_FUNCTIONS='["_w_overhead","_w_crypt","_cipher_wipe","_malloc","_free"]' \
  -sEXPORTED_RUNTIME_METHODS='["ccall","cwrap","HEAPU8"]' \
  -sALLOW_MEMORY_GROWTH=1 -sINITIAL_MEMORY=33554432 \
  -sMODULARIZE=1 -sEXPORT_NAME=createCipher --no-entry
