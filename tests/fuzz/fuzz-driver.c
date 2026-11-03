/* fuzz-driver: throw stdin bytes at the AEAD and the file format. Never
 * crashes, never hangs; run under ASan/UBSan in CI. */
#include "../src/aead.h"
#include "../src/poly1305.h"
#include "../src/format.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    static unsigned char buf[4096];
    size_t n = fread(buf, 1, sizeof buf, stdin);
    if (n == 0)
        return 0;

    /* AEAD: split the blob into key|nonce|aad|ct|tag by length bytes */
    if (n > 32 + 12 + 16) {
        const unsigned char *key = buf, *nonce = buf + 32;
        size_t alen = buf[44] % 32, rest = n - 45;
        if (alen > rest) alen = rest;
        const unsigned char *aad = buf + 45;
        size_t left = n - 45 - alen;
        size_t clen = left > 16 ? left - 16 : 0;
        const unsigned char *ct = aad + alen, *tag = ct + clen;
        static unsigned char pt[4096], ct2[64], tag2[16];
        cipher_aead_open(key, nonce, aad, alen, ct, clen, tag, pt);
        cipher_aead_seal(key, nonce, aad, alen, pt, 32, ct2, tag2);
        CipherPoly1305 p;
        cipher_poly1305_init(&p, key);
        cipher_poly1305_update(&p, buf, n);
        cipher_poly1305_final(&p, tag2);
    }

    /* the file format: parse the blob as a .cph with a fixed password */
    FILE *in = fmemopen(buf, n, "rb");
    FILE *out = tmpfile();
    if (in && out) {
        setenv("CIPHER_KDF_ITER", "1", 1);
        cipher_crypt_file(in, out, "fuzz-password", 1);
    }
    if (in) fclose(in);
    if (out) fclose(out);
    return 0;
}
