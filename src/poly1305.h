/* poly1305.h - Poly1305 one-time authenticator (RFC 8439). */
#ifndef CIPHER_POLY1305_H
#define CIPHER_POLY1305_H
#include <stddef.h>

typedef struct {
    unsigned int h[5];
    unsigned int r[5];
    unsigned int pad[4];
    unsigned char buf[16];
    size_t n;
} CipherPoly1305;

void cipher_poly1305_init(CipherPoly1305 *c, const unsigned char key[32]);
void cipher_poly1305_update(CipherPoly1305 *c, const void *data, size_t len);
void cipher_poly1305_final(CipherPoly1305 *c, unsigned char tag[16]);

#endif
