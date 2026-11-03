#include "wipe.h"
#include "pbkdf2.h"
#include "hmac.h"
#include <string.h>

void cipher_pbkdf2(const unsigned char *pass, size_t plen,
                   const unsigned char *salt, size_t slen,
                   uint32_t iterations, unsigned char *out, size_t out_len) {
    unsigned char block[1024 + 4], u[32], t[32];
    if (slen > 1024) slen = 1024;   /* callers use 16; never crash on abuse */
    memcpy(block, salt, slen);
    for (uint32_t i = 1; out_len; i++) {
        block[slen] = (unsigned char)(i >> 24);
        block[slen+1] = (unsigned char)(i >> 16);
        block[slen+2] = (unsigned char)(i >> 8);
        block[slen+3] = (unsigned char)i;
        cipher_hmac_sha256(pass, plen, block, slen + 4, u);
        memcpy(t, u, 32);
        for (uint32_t j = 1; j < iterations; j++) {
            cipher_hmac_sha256(pass, plen, u, 32, u);
            for (int k = 0; k < 32; k++) t[k] ^= u[k];
        }
        size_t take = out_len < 32 ? out_len : 32;
        memcpy(out, t, take);
        out += take;
        out_len -= take;
    }
    cipher_secure_zero(block, sizeof block);
    cipher_secure_zero(u, 32);
    cipher_secure_zero(t, 32);
}
