/* format.c - chunked AEAD file encryption over the crypto primitives. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include "pbkdf2.h"
#include "aead.h"
#include "format.h"

static void wipe(void *p, size_t n) {
    volatile unsigned char *v = p;
    while (n--) *v++ = 0;
}

static int rand_bytes(unsigned char *out, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, out + got, n - got);
        if (r <= 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

int cipher_random(unsigned char *out, size_t n) { return rand_bytes(out, n); }

void cipher_wipe(void *p, size_t n) { wipe(p, n); }

static void put32le(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}

static uint32_t get32le(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void chunk_nonce(const unsigned char base[12], uint64_t i, unsigned char out[12]) {
    memcpy(out, base, 12);
    for (int k = 0; k < 8; k++)
        out[4 + k] ^= (unsigned char)(i >> (k * 8));
}

int cipher_crypt_file(FILE *in, FILE *out, const char *password, int decrypt) {
    static unsigned char hdr[CIPHER_HEADER_LEN], pt[CIPHER_CHUNK], ct[CIPHER_CHUNK];
    unsigned char key[32], salt[16], base[12];
    uint32_t iterations;
    int rc = 1;

    if (!decrypt) {
        const char *it = getenv("CIPHER_KDF_ITER");
        iterations = it ? (uint32_t)strtoul(it, NULL, 10) : CIPHER_ITER_DEFAULT;
        if (iterations < 1 || iterations > CIPHER_ITER_MAX) iterations = CIPHER_ITER_DEFAULT;
        if (rand_bytes(salt, 16) != 0 || rand_bytes(base, 12) != 0) {
            fprintf(stderr, "cannot read randomness\n");
            return 1;
        }
        memcpy(hdr, CIPHER_MAGIC, 4);
        hdr[4] = CIPHER_VERSION;
        hdr[5] = CIPHER_KDF_PBKDF2;
        put32le(hdr + 6, iterations);
        memcpy(hdr + 10, salt, 16);
        memcpy(hdr + 26, base, 12);
    } else {
        if (fread(hdr, 1, CIPHER_HEADER_LEN, in) != CIPHER_HEADER_LEN ||
            memcmp(hdr, CIPHER_MAGIC, 4) != 0) {
            fprintf(stderr, "not a cipher file (or truncated header)\n");
            return 1;
        }
        if (hdr[4] != CIPHER_VERSION || hdr[5] != CIPHER_KDF_PBKDF2) {
            fprintf(stderr, "unsupported version or kdf\n");
            return 1;
        }
        iterations = get32le(hdr + 6);
        if (iterations < 1 || iterations > CIPHER_ITER_MAX) {
            fprintf(stderr, "kdf iterations out of range\n");
            return 1;
        }
        memcpy(salt, hdr + 10, 16);
        memcpy(base, hdr + 26, 12);
    }
    cipher_pbkdf2((const unsigned char *)password, strlen(password), salt, 16,
                  iterations, key, 32);

    for (uint64_t i = 0;; i++) {
        unsigned char nonce[12], tag[16];
        uint32_t clen;
        int final;
        if (!decrypt) {
            size_t r = fread(pt, 1, CIPHER_CHUNK, in);
            if (ferror(in)) { fprintf(stderr, "read error\n"); goto out; }
            final = r < CIPHER_CHUNK;
            clen = (uint32_t)r;
        } else {
            unsigned char meta[5];
            size_t r = fread(meta, 1, 5, in);
            if (r == 0) { fprintf(stderr, "truncated: no final chunk\n"); goto out; }
            if (r != 5) { fprintf(stderr, "truncated chunk header\n"); goto out; }
            clen = get32le(meta);
            final = meta[4] & 1;
            if (meta[4] & ~(unsigned char)1 || clen > CIPHER_CHUNK ||
                (clen < 1 && !final)) {   /* only the final chunk may be empty */
                fprintf(stderr, "bad chunk header\n");
                goto out;
            }
            if (!final && clen != CIPHER_CHUNK) {
                fprintf(stderr, "non-final chunk not full\n");
                goto out;
            }
            if (fread(ct, 1, clen, in) != clen || fread(tag, 1, 16, in) != 16) {
                fprintf(stderr, "truncated chunk\n");
                goto out;
            }
        }
        chunk_nonce(base, i, nonce);
        /* aad = header || clen || flags || le64(i) */
        unsigned char aad[CIPHER_HEADER_LEN + 13];
        memcpy(aad, hdr, CIPHER_HEADER_LEN);
        put32le(aad + CIPHER_HEADER_LEN, clen);
        aad[CIPHER_HEADER_LEN + 4] = (unsigned char)final;
        for (int k = 0; k < 8; k++)
            aad[CIPHER_HEADER_LEN + 5 + k] = (unsigned char)(i >> (k * 8));
        if (!decrypt) {
            cipher_aead_seal(key, nonce, aad, sizeof aad, pt, clen, ct, tag);
            unsigned char meta[5];
            put32le(meta, clen);
            meta[4] = (unsigned char)final;
            if (i == 0 && fwrite(hdr, 1, CIPHER_HEADER_LEN, out) != CIPHER_HEADER_LEN)
                goto write_fail;
            if (fwrite(meta, 1, 5, out) != 5 || fwrite(ct, 1, clen, out) != clen ||
                fwrite(tag, 1, 16, out) != 16)
                goto write_fail;
        } else {
            if (cipher_aead_open(key, nonce, aad, sizeof aad, ct, clen, tag, pt) != 0) {
                fprintf(stderr, "authentication failed: wrong password or tampered data\n");
                goto out;
            }
            if (fwrite(pt, 1, clen, out) != clen)
                goto write_fail;
            if (final) {
                if (fgetc(in) != EOF || ferror(in)) {
                    fprintf(stderr, "trailing data after the final chunk\n");
                    goto out;
                }
            }
        }
        if (final)
            break;
        continue;
write_fail:
        fprintf(stderr, "write error\n");
        goto out;
    }
    rc = 0;
out:
    wipe(key, sizeof key);
    wipe(pt, sizeof pt);
    wipe(ct, sizeof ct);
    return rc;
}

