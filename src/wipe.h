#ifndef CIPHER_WIPE_H
#define CIPHER_WIPE_H
#include <stddef.h>
static inline void cipher_secure_zero(void *p, size_t n) {
    volatile unsigned char *v = p;
    while (n--) *v++ = 0;
}
#endif
