#include "wipe.h"
#include "chacha20.h"
#include <string.h>

static uint32_t rotl(uint32_t x, int n) { return x << n | x >> (32 - n); }

#define QR(a, b, c, d) \
    a += b; d ^= a; d = rotl(d, 16); \
    c += d; b ^= c; b = rotl(b, 12); \
    a += b; d ^= a; d = rotl(d, 8);  \
    c += d; b ^= c; b = rotl(b, 7);

static void block(uint32_t out[16], const uint32_t st[16]) {
    uint32_t x[16];
    memcpy(x, st, sizeof x);
    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < 16; i++) out[i] = x[i] + st[i];
}

static uint32_t ld32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

void cipher_chacha20_init(CipherChaCha20 *c, const unsigned char key[32],
                          const unsigned char nonce[12], uint32_t counter) {
    c->st[0] = 0x61707865; c->st[1] = 0x3320646e;
    c->st[2] = 0x79622d32; c->st[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) c->st[4 + i] = ld32(key + i * 4);
    c->st[12] = counter;
    for (int i = 0; i < 3; i++) c->st[13 + i] = ld32(nonce + i * 4);
    c->n = 64;   /* force a block on first use */
}

void cipher_chacha20_xor(CipherChaCha20 *c, const unsigned char *in,
                         unsigned char *out, size_t len) {
    while (len) {
        if (c->n == 64) {
            uint32_t b[16];
            block(b, c->st);
            for (int i = 0; i < 16; i++) {
                c->ks[i*4] = (unsigned char)b[i];
                c->ks[i*4+1] = (unsigned char)(b[i] >> 8);
                c->ks[i*4+2] = (unsigned char)(b[i] >> 16);
                c->ks[i*4+3] = (unsigned char)(b[i] >> 24);
            }
            c->st[12]++;
            c->n = 0;
            cipher_secure_zero(b, sizeof b);
        }
        size_t take = 64 - c->n < len ? 64 - c->n : len;
        for (size_t i = 0; i < take; i++) out[i] = in[i] ^ c->ks[c->n + i];
        c->n += take;
        in += take; out += take; len -= take;
    }
}

void cipher_chacha20(const unsigned char key[32], const unsigned char nonce[12],
                     uint32_t counter, const unsigned char *in,
                     unsigned char *out, size_t len) {
    CipherChaCha20 c;
    cipher_chacha20_init(&c, key, nonce, counter);
    cipher_chacha20_xor(&c, in, out, len);
    cipher_secure_zero(&c, sizeof c);
}
