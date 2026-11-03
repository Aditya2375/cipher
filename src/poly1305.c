#include "poly1305.h"
#include <string.h>
#include <stdint.h>

/* five 26-bit limbs mod 2^130 - 5; 64-bit products cannot overflow
 * (26-bit limb x 28-bit slimb, five terms < 2^57). */

static uint32_t ld32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

void cipher_poly1305_init(CipherPoly1305 *c, const unsigned char key[32]) {
    uint32_t t0 = ld32(key), t1 = ld32(key + 4), t2 = ld32(key + 8), t3 = ld32(key + 12);
    c->r[0] = t0 & 0x3ffffff;
    c->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    c->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    c->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    c->r[4] = (t3 >> 8) & 0x00fffff;
    for (int i = 0; i < 5; i++) c->h[i] = 0;
    for (int i = 0; i < 4; i++) c->pad[i] = ld32(key + 16 + i * 4);
    c->n = 0;
}

static void absorb(CipherPoly1305 *c, const unsigned char *p, int full) {
    uint32_t t0 = ld32(p), t1 = ld32(p + 4), t2 = ld32(p + 8), t3 = ld32(p + 12);
    c->h[0] += t0 & 0x3ffffff;
    c->h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
    c->h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
    c->h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
    c->h[4] += (t3 >> 8) | (full ? (1u << 24) : 0);
    uint64_t s1 = c->r[1] * 5, s2 = c->r[2] * 5, s3 = c->r[3] * 5, s4 = c->r[4] * 5;
    uint64_t d0 = (uint64_t)c->h[0] * c->r[0] + (uint64_t)c->h[1] * s4 + (uint64_t)c->h[2] * s3 + (uint64_t)c->h[3] * s2 + (uint64_t)c->h[4] * s1;
    uint64_t d1 = (uint64_t)c->h[0] * c->r[1] + (uint64_t)c->h[1] * c->r[0] + (uint64_t)c->h[2] * s4 + (uint64_t)c->h[3] * s3 + (uint64_t)c->h[4] * s2;
    uint64_t d2 = (uint64_t)c->h[0] * c->r[2] + (uint64_t)c->h[1] * c->r[1] + (uint64_t)c->h[2] * c->r[0] + (uint64_t)c->h[3] * s4 + (uint64_t)c->h[4] * s3;
    uint64_t d3 = (uint64_t)c->h[0] * c->r[3] + (uint64_t)c->h[1] * c->r[2] + (uint64_t)c->h[2] * c->r[1] + (uint64_t)c->h[3] * c->r[0] + (uint64_t)c->h[4] * s4;
    uint64_t d4 = (uint64_t)c->h[0] * c->r[4] + (uint64_t)c->h[1] * c->r[3] + (uint64_t)c->h[2] * c->r[2] + (uint64_t)c->h[3] * c->r[1] + (uint64_t)c->h[4] * c->r[0];
    uint64_t carry;
    carry = d0 >> 26; c->h[0] = (uint32_t)d0 & 0x3ffffff; d1 += carry;
    carry = d1 >> 26; c->h[1] = (uint32_t)d1 & 0x3ffffff; d2 += carry;
    carry = d2 >> 26; c->h[2] = (uint32_t)d2 & 0x3ffffff; d3 += carry;
    carry = d3 >> 26; c->h[3] = (uint32_t)d3 & 0x3ffffff; d4 += carry;
    carry = d4 >> 26; c->h[4] = (uint32_t)d4 & 0x3ffffff;
    c->h[0] += (uint32_t)carry * 5;
    carry = c->h[0] >> 26; c->h[0] &= 0x3ffffff; c->h[1] += (uint32_t)carry;
}

void cipher_poly1305_update(CipherPoly1305 *c, const void *data, size_t len) {
    const unsigned char *p = data;
    while (len) {
        size_t take = 16 - c->n < len ? 16 - c->n : len;
        memcpy(c->buf + c->n, p, take);
        c->n += take; p += take; len -= take;
        if (c->n == 16) { absorb(c, c->buf, 1); c->n = 0; }
    }
}

void cipher_poly1305_final(CipherPoly1305 *c, unsigned char tag[16]) {
    if (c->n) {
        memset(c->buf + c->n, 0, 16 - c->n);
        c->buf[c->n] = 1;
        absorb(c, c->buf, 0);
    }
    uint32_t h0 = c->h[0], h1 = c->h[1], h2 = c->h[2], h3 = c->h[3], h4 = c->h[4], carry;
    carry = h1 >> 26; h1 &= 0x3ffffff; h2 += carry;
    carry = h2 >> 26; h2 &= 0x3ffffff; h3 += carry;
    carry = h3 >> 26; h3 &= 0x3ffffff; h4 += carry;
    carry = h4 >> 26; h4 &= 0x3ffffff;
    h0 += carry * 5;
    carry = h0 >> 26; h0 &= 0x3ffffff; h1 += carry;
    /* g = h + 5 - p; use g only if it did not borrow */
    uint32_t g0 = h0 + 5; carry = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + carry; carry = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + carry; carry = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + carry; carry = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + carry - (1u << 26);
    uint32_t mask = (uint32_t)(-(int32_t)(g4 >> 31));   /* all ones when h < p */
    h0 = (h0 & mask) | (g0 & ~mask);
    h1 = (h1 & mask) | (g1 & ~mask);
    h2 = (h2 & mask) | (g2 & ~mask);
    h3 = (h3 & mask) | (g3 & ~mask);
    h4 = (h4 & mask) | (g4 & ~mask);
    /* squeeze to four 32-bit words and add the pad */
    uint64_t f;
    f = (uint64_t)(h0 | (h1 << 26)) + c->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)((h1 >> 6) | (h2 << 20)) + c->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)((h2 >> 12) | (h3 << 14)) + c->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)((h3 >> 18) | (h4 << 8)) + c->pad[3] + (f >> 32); h3 = (uint32_t)f;
    uint32_t w[4] = {h0, h1, h2, h3};
    for (int i = 0; i < 4; i++) {
        tag[i*4] = (unsigned char)w[i];
        tag[i*4+1] = (unsigned char)(w[i] >> 8);
        tag[i*4+2] = (unsigned char)(w[i] >> 16);
        tag[i*4+3] = (unsigned char)(w[i] >> 24);
    }
    memset(c, 0, sizeof *c);
}
