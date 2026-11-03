/* In-memory bridge to the same chunked format implementation as the CLI. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/format.h"
#define MAX_INPUT (16u * 1024u * 1024u + 6000u)

size_t w_overhead(size_t inlen) {
    return CIPHER_HEADER_LEN + (inlen / CIPHER_CHUNK + 1) * 21;
}

long w_crypt(const unsigned char *in, size_t inlen, const char *password,
             int decrypt, unsigned char *out, size_t outcap) {
    if (inlen > MAX_INPUT || !password || !*password || strlen(password) > 254)
        return -1;
    unsigned char empty = 0;
    char *result = NULL;
    size_t len = 0;
    FILE *fi = fmemopen((void *)(inlen ? in : &empty), inlen, "rb");
    FILE *fo = open_memstream(&result, &len);
    long n = -1;
    if (fi && fo && cipher_crypt_file(fi, fo, password, decrypt) == 0 &&
        fflush(fo) == 0 && len <= outcap) {
        memcpy(out, result, len);
        n = (long)len;
    }
    if (fi) fclose(fi);
    if (fo) fclose(fo);
    if (result) { cipher_wipe(result, len); free(result); }
    return n;
}
