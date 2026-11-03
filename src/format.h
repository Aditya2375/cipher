/* format.h - the cipher file format: a header plus AEAD chunks.
 *
 *   header (38 bytes):
 *     magic "CIPH" | version u8 | kdf u8 | iterations u32le |
 *     salt 16 | base nonce 12
 *   chunk i:
 *     clen u32le | flags u8 (bit0: final) | ct clen | tag 16
 *     nonce  = base nonce with bytes 4..11 XORed by le64(i)
 *     aad    = header || clen || flags || le64(i)
 *
 * Chunks are authenticated before their plaintext is released, a
 * non-final chunk must be full, and the final chunk must be the last
 * bytes in the file: truncation and reordering cannot pass. */
#ifndef CIPHER_FORMAT_H
#define CIPHER_FORMAT_H
#include <stdio.h>

#define CIPHER_MAGIC "CIPH"
#define CIPHER_VERSION 1
#define CIPHER_CHUNK (64 * 1024)
#define CIPHER_HEADER_LEN 38
#define CIPHER_KDF_PBKDF2 1
#define CIPHER_ITER_DEFAULT 600000
#define CIPHER_ITER_MAX 10000000u

/* Encrypt (decrypt=0) or decrypt a stream pair; returns 0 on success.
 * Decryption releases no plaintext until its chunk's tag verifies. */
int cipher_crypt_file(FILE *in, FILE *out, const char *password, int decrypt);
int cipher_random(unsigned char *out, size_t n);
void cipher_wipe(void *p, size_t n);


#endif
