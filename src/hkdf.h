/* hkdf.h - HKDF-SHA256 (RFC 5869), one-shot extract+expand. */
#ifndef CIPHER_HKDF_H
#define CIPHER_HKDF_H
#include <stddef.h>
/* out_len <= 8160 (255 * 32); returns -1 on bad length. */
int cipher_hkdf(const unsigned char *salt, size_t slen,
                const unsigned char *ikm, size_t ilen,
                const unsigned char *info, size_t inlen,
                unsigned char *out, size_t out_len);
#endif
