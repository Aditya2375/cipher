/* pbkdf2.h - PBKDF2-HMAC-SHA256 (RFC 8018). */
#ifndef CIPHER_PBKDF2_H
#define CIPHER_PBKDF2_H
#include <stddef.h>
#include <stdint.h>
void cipher_pbkdf2(const unsigned char *pass, size_t plen,
                   const unsigned char *salt, size_t slen,
                   uint32_t iterations, unsigned char *out, size_t out_len);
#endif
