/* cipher_wasm.c - in-browser file encryption for the demo page.
 *
 * The page hands the whole file over as one buffer; the wrapper runs it
 * through the same cipher_crypt_file() the CLI uses (via MEMFS temp
 * files) and returns the result buffer. Nothing leaves the browser. */
#include <emscripten.h>
#include <stdio.h>
#include <string.h>
#include "../src/format.h"

/* Worst-case encrypt overhead on top of inlen: the header plus each
 * chunk's length, flags and tag. */
EMSCRIPTEN_KEEPALIVE
size_t w_overhead(size_t inlen) {
    size_t chunks = inlen / CIPHER_CHUNK + 1;
    return CIPHER_HEADER_LEN + chunks * (4 + 1 + 16) + 16;
}

/* Returns the output length (>= 0), or -1 on any failure (wrong
 * password, tampered data, I/O error). For encryption out must hold
 * inlen + w_overhead(inlen) bytes; for decryption, inlen bytes. */
EMSCRIPTEN_KEEPALIVE
long w_crypt(const unsigned char *in, size_t inlen, const char *password,
             int decrypt, unsigned char *out, size_t outcap) {
    FILE *fi = tmpfile(), *fo = NULL;
    long n = -1;
    if (!fi)
        return -1;
    if (inlen && fwrite(in, 1, inlen, fi) != inlen)
        goto out;
    rewind(fi);
    fo = tmpfile();
    if (!fo)
        goto out;
    if (cipher_crypt_file(fi, fo, password, decrypt) != 0)
        goto out;
    n = ftell(fo);
    if (n < 0 || (size_t)n > outcap) {
        n = -1;
        goto out;
    }
    rewind(fo);
    if (n && fread(out, 1, (size_t)n, fo) != (size_t)n) {
        n = -1;
        goto out;
    }
out:
    if (fo)
        fclose(fo);
    fclose(fi);
    return n;
}
