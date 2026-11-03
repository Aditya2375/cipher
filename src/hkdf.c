#include "hkdf.h"
#include "hmac.h"
#include <string.h>

int cipher_hkdf(const unsigned char *salt, size_t slen,
                const unsigned char *ikm, size_t ilen,
                const unsigned char *info, size_t inlen,
                unsigned char *out, size_t out_len) {
    if (out_len == 0 || out_len > 255 * 32)
        return -1;
    unsigned char zero[32] = {0}, prk[32], t[32];
    if (!salt) { salt = zero; slen = 32; }
    cipher_hmac_sha256(salt, slen, ikm, ilen, prk);
    size_t done = 0, tlen = 0;
    for (unsigned char i = 1; done < out_len; i++) {
        /* T(i) = HMAC(PRK, T(i-1) || info || i) */
        unsigned char buf[32 + 1024 + 1];
        if (inlen > 1024) { memset(prk, 0, 32); return -1; }
        memcpy(buf, t, tlen);
        memcpy(buf + tlen, info, inlen);
        buf[tlen + inlen] = i;
        cipher_hmac_sha256(prk, 32, buf, tlen + inlen + 1, t);
        tlen = 32;
        size_t take = out_len - done < 32 ? out_len - done : 32;
        memcpy(out + done, t, take);
        done += take;
    }
    memset(prk, 0, 32);
    memset(t, 0, 32);
    return 0;
}
