/* sha256.h - SHA-256 (FIPS 180-4), streaming. */
#ifndef CIPHER_SHA256_H
#define CIPHER_SHA256_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint64_t total;
    unsigned char buf[64];
    size_t n;
} CipherSha256;

void cipher_sha256_init(CipherSha256 *c);
void cipher_sha256_update(CipherSha256 *c, const void *data, size_t len);
void cipher_sha256_final(CipherSha256 *c, unsigned char out[32]);
void cipher_sha256(const void *data, size_t len, unsigned char out[32]);

#endif
