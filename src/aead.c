#include "aead.h"
#include "chacha20.h"
#include "poly1305.h"
#include <string.h>
#include <stdint.h>

static void mac(const unsigned char otk[32], const unsigned char *aad, size_t alen,
                const unsigned char *ct, size_t clen, unsigned char tag[16]) {
    CipherPoly1305 p;
    unsigned char z[16] = {0}, lens[16];
    for (int i = 0; i < 8; i++) {
        lens[i] = (unsigned char)((uint64_t)alen >> (i * 8));
        lens[8 + i] = (unsigned char)((uint64_t)clen >> (i * 8));
    }
    cipher_poly1305_init(&p, otk);
    cipher_poly1305_update(&p, aad, alen);
    if (alen % 16) cipher_poly1305_update(&p, z, 16 - alen % 16);
    cipher_poly1305_update(&p, ct, clen);
    if (clen % 16) cipher_poly1305_update(&p, z, 16 - clen % 16);
    cipher_poly1305_update(&p, lens, 16);
    cipher_poly1305_final(&p, tag);
}

void cipher_aead_seal(const unsigned char key[32], const unsigned char nonce[12],
                      const unsigned char *aad, size_t alen,
                      const unsigned char *pt, size_t plen,
                      unsigned char *ct, unsigned char tag[16]) {
    unsigned char otk[64] = {0};
    cipher_chacha20(key, nonce, 0, otk, otk, 64);
    cipher_chacha20(key, nonce, 1, pt, ct, plen);
    mac(otk, aad, alen, ct, plen, tag);
    memset(otk, 0, sizeof otk);
}

int cipher_aead_open(const unsigned char key[32], const unsigned char nonce[12],
                     const unsigned char *aad, size_t alen,
                     const unsigned char *ct, size_t clen,
                     const unsigned char tag[16], unsigned char *pt) {
    unsigned char otk[64] = {0}, want[16];
    cipher_chacha20(key, nonce, 0, otk, otk, 64);
    mac(otk, aad, alen, ct, clen, want);
    int ok = cipher_ct_eq(tag, want, 16);
    memset(otk, 0, sizeof otk);
    memset(want, 0, sizeof want);
    if (!ok)
        return -1;
    cipher_chacha20(key, nonce, 1, ct, pt, clen);
    return 0;
}

int cipher_ct_eq(const unsigned char *a, const unsigned char *b, size_t n) {
    unsigned char d = 0;
    for (size_t i = 0; i < n; i++) d |= (unsigned char)(a[i] ^ b[i]);
    return d == 0;
}
