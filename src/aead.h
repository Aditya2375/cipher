/* aead.h - ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8). */
#ifndef CIPHER_AEAD_H
#define CIPHER_AEAD_H
#include <stddef.h>

void cipher_aead_seal(const unsigned char key[32], const unsigned char nonce[12],
                      const unsigned char *aad, size_t alen,
                      const unsigned char *pt, size_t plen,
                      unsigned char *ct, unsigned char tag[16]);
/* returns 0 when the tag verifies (and fills pt), -1 otherwise */
int cipher_aead_open(const unsigned char key[32], const unsigned char nonce[12],
                     const unsigned char *aad, size_t alen,
                     const unsigned char *ct, size_t clen,
                     const unsigned char tag[16], unsigned char *pt);
/* constant-time equality for tags */
int cipher_ct_eq(const unsigned char *a, const unsigned char *b, size_t n);

#endif
