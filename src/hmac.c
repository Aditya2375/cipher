#include "hmac.h"
#include "sha256.h"
#include <string.h>

void cipher_hmac_sha256(const unsigned char *key, size_t klen,
                        const unsigned char *msg, size_t mlen,
                        unsigned char out[32]) {
    unsigned char k[64], inner[32];
    memset(k, 0, sizeof k);
    if (klen > 64)
        cipher_sha256(key, klen, k);
    else
        memcpy(k, key, klen);
    CipherSha256 c;
    unsigned char pad[64];
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    cipher_sha256_init(&c);
    cipher_sha256_update(&c, pad, 64);
    cipher_sha256_update(&c, msg, mlen);
    cipher_sha256_final(&c, inner);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    cipher_sha256_init(&c);
    cipher_sha256_update(&c, pad, 64);
    cipher_sha256_update(&c, inner, 32);
    cipher_sha256_final(&c, out);
    memset(k, 0, sizeof k);
    memset(pad, 0, sizeof pad);
    memset(inner, 0, sizeof inner);
}
