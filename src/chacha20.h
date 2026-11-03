/* chacha20.h - ChaCha20 stream cipher (RFC 8439). */
#ifndef CIPHER_CHACHA20_H
#define CIPHER_CHACHA20_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t st[16];
    unsigned char ks[64];
    size_t n;
} CipherChaCha20;

void cipher_chacha20_init(CipherChaCha20 *c, const unsigned char key[32],
                          const unsigned char nonce[12], uint32_t counter);
void cipher_chacha20_xor(CipherChaCha20 *c, const unsigned char *in,
                         unsigned char *out, size_t len);
/* one-shot, in may equal out */
void cipher_chacha20(const unsigned char key[32], const unsigned char nonce[12],
                     uint32_t counter, const unsigned char *in,
                     unsigned char *out, size_t len);

#endif
