/* fuzz-driver: throw stdin bytes at the AEAD and the file format. Bounded input, run under ASan/UBSan in CI. */
#include "../src/aead.h"
#include "../src/poly1305.h"
#include "../src/format.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    static unsigned char buf[2 * CIPHER_CHUNK + 256];
    size_t n = fread(buf, 1, sizeof buf, stdin);
    if (n == 0)
        return 0;

    /* AEAD: split the blob into key|nonce|aad|ct|tag by length bytes */
    if (n > 32 + 12 + 16) {
        const unsigned char *key = buf, *nonce = buf + 32;
        size_t alen = buf[44] % 32, rest = n - 45 - 16;
        if (alen > rest) alen = rest;
        const unsigned char *aad = buf + 45;
        size_t left = n - 45 - alen;
        size_t clen = left > 16 ? left - 16 : 0;
        const unsigned char *ct = aad + alen, *tag = ct + clen;
        static unsigned char pt[sizeof buf], ct2[64], tag2[16];
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
        /* Keep fuzzing cheap: the KDF field is separately boundary-tested.
         * Restore a small value before parsing mutated valid containers. */
        if (n >= 10 && !memcmp(buf, "CIPH", 4)) {
            buf[6] = 1; buf[7] = buf[8] = buf[9] = 0;
        }
        cipher_crypt_file(in, out, "pw", 1);
    }
    if (in) fclose(in);
    if (out) fclose(out);
    return 0;
}
