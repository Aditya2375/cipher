/* hmac.h - HMAC-SHA256 (RFC 2104). */
#ifndef CIPHER_HMAC_H
#define CIPHER_HMAC_H
#include <stddef.h>
void cipher_hmac_sha256(const unsigned char *key, size_t klen,
                        const unsigned char *msg, size_t mlen,
                        unsigned char out[32]);
#endif
