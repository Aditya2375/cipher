/* test-unit.c - published vectors and adversarial checks for every
 * primitive. Prints one line per check and a final "N checks passed". */
#include "sha256.h"
#include "hmac.h"
#include "pbkdf2.h"
#include "chacha20.h"
#include "poly1305.h"
#include "aead.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int checks;
#define CHECK(cond, label) do { \
    if (!(cond)) { fprintf(stderr, "FAIL %d: %s\n", checks + 1, label); exit(1); } \
    checks++; \
} while (0)

static int unhex(const char *s, unsigned char *out, size_t cap) {
    size_t n = 0;
    while (s[0] && s[1] && n < cap) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (unsigned char)v;
        s += 2;
    }
    return (int)n;
}

static void hex(const unsigned char *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) sprintf(out + i * 2, "%02x", b[i]);
    out[n * 2] = 0;
}

int main(void) {
    unsigned char d[64], key[131], nonce[12], buf[256], buf2[256], tag[16];
    char h[512];

    /* ---- SHA-256: FIPS 180-4 ---- */
    cipher_sha256("", 0, d);
    hex(d, 32, h);
    CHECK(!strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
          "sha256 empty");
    cipher_sha256("abc", 3, d);
    hex(d, 32, h);
    CHECK(!strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
          "sha256 abc");
    cipher_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
    hex(d, 32, h);
    CHECK(!strcmp(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
          "sha256 56 bytes");
    /* streaming in odd-size bites equals one-shot */
    {
        CipherSha256 c;
        char msg[100];
        memset(msg, 'x', sizeof msg);
        cipher_sha256(msg, sizeof msg, d);
        cipher_sha256_init(&c);
        for (size_t i = 0; i < sizeof msg; i += 7)
            cipher_sha256_update(&c, msg + i, 7 < sizeof msg - i ? 7 : sizeof msg - i);
        cipher_sha256_final(&c, buf);
        CHECK(!memcmp(d, buf, 32), "sha256 streaming equals one-shot");
    }

    /* ---- HMAC-SHA256: RFC 4231 case 1 and 2 ---- */
    memset(key, 0x0b, 20);
    cipher_hmac_sha256(key, 20, (const unsigned char *)"Hi There", 8, d);
    hex(d, 32, h);
    CHECK(!strcmp(h, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
          "hmac-sha256 rfc4231 #1");
    cipher_hmac_sha256((const unsigned char *)"Jefe", 4,
                       (const unsigned char *)"what do ya want for nothing?", 28, d);
    hex(d, 32, h);
    CHECK(!strcmp(h, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
          "hmac-sha256 rfc4231 #2");
    /* key longer than the block size is hashed first (RFC 4231 #6) */
    memset(key, 0xaa, 131);
    cipher_hmac_sha256(key, 131,
                       (const unsigned char *)"Test Using Larger Than Block-Size Key - Hash Key First", 54, d);
    hex(d, 32, h);
    CHECK(!strcmp(h, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
          "hmac-sha256 long key (rfc4231 #6)");

    /* ---- PBKDF2-HMAC-SHA256: well-known vectors ---- */
    cipher_pbkdf2((const unsigned char *)"password", 8,
                  (const unsigned char *)"salt", 4, 1, d, 32);
    hex(d, 32, h);
    CHECK(!strcmp(h, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
          "pbkdf2 c=1");
    cipher_pbkdf2((const unsigned char *)"password", 8,
                  (const unsigned char *)"salt", 4, 2, d, 32);
    hex(d, 32, h);
    CHECK(!strcmp(h, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
          "pbkdf2 c=2");
    cipher_pbkdf2((const unsigned char *)"password", 8,
                  (const unsigned char *)"salt", 4, 4096, d, 32);
    hex(d, 32, h);
    CHECK(!strcmp(h, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
          "pbkdf2 c=4096");

    /* ---- ChaCha20: RFC 8439 section 2.3.2 (block) and 2.4.2 (stream) ---- */
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;
    unhex("000000090000004a00000000", nonce, 12);
    {
        CipherChaCha20 c;
        cipher_chacha20_init(&c, key, nonce, 1);
        memset(buf, 0, 64);
        cipher_chacha20_xor(&c, buf, buf2, 64);
        hex(buf2, 16, h);
        CHECK(!strcmp(h, "10f1e7e4d13b5915500fdd1fa32071c4"), "chacha20 block vector");
    }
    {
        const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you "
                         "only one tip for the future, sunscreen would be it.";
        unhex("000000000000004a00000000", nonce, 12);   /* the 2.4.2 nonce */
        cipher_chacha20(key, nonce, 1, (const unsigned char *)pt, buf, 114);
        hex(buf, 16, h);
        CHECK(!strcmp(h, "6e2e359a2568f98041ba0728dd0d6981"), "chacha20 stream vector prefix");
        /* decrypting restores the plaintext, in odd-size bites */
        CipherChaCha20 c;
        cipher_chacha20_init(&c, key, nonce, 1);
        memset(buf2, 0, sizeof buf2);
        for (size_t i = 0; i < 114; i += 13)
            cipher_chacha20_xor(&c, buf + i, buf2 + i, 13 < 114 - i ? 13 : 114 - i);
        CHECK(!memcmp(buf2, pt, 114), "chacha20 streaming round trip");
    }

    /* ---- Poly1305: RFC 8439 section 2.5.2 ---- */
    unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", key, 32);
    {
        CipherPoly1305 p;
        const char *msg = "Cryptographic Forum Research Group";
        cipher_poly1305_init(&p, key);
        cipher_poly1305_update(&p, msg, 34);
        cipher_poly1305_final(&p, tag);
        hex(tag, 16, h);
        CHECK(!strcmp(h, "a8061dc1305136c6c22b8baf0c0127a9"), "poly1305 rfc8439 vector");
        /* byte-at-a-time feeding matches */
        cipher_poly1305_init(&p, key);
        for (int i = 0; i < 34; i++) cipher_poly1305_update(&p, msg + i, 1);
        cipher_poly1305_final(&p, tag);
        hex(tag, 16, h);
        CHECK(!strcmp(h, "a8061dc1305136c6c22b8baf0c0127a9"), "poly1305 streaming matches");
    }

    /* ---- AEAD: RFC 8439 section 2.8.2 ---- */
    {
        unsigned char aad[12], ct[114], pt2[114], tag2[16];
        for (int i = 0; i < 32; i++) key[i] = (unsigned char)(0x80 + i);
        unhex("070000004041424344454647", nonce, 12);
        unhex("50515253c0c1c2c3c4c5c6c7", aad, 12);
        const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you "
                         "only one tip for the future, sunscreen would be it.";
        cipher_aead_seal(key, nonce, aad, 12, (const unsigned char *)pt, 114, ct, tag);
        hex(ct, 16, h);
        CHECK(!strcmp(h, "d31a8d34648e60db7b86afbc53ef7ec2"), "aead ciphertext prefix");
        hex(tag, 16, h);
        CHECK(!strcmp(h, "1ae10b594f09e26a7e902ecbd0600691"), "aead tag vector");
        CHECK(cipher_aead_open(key, nonce, aad, 12, ct, 114, tag, pt2) == 0 &&
              !memcmp(pt2, pt, 114), "aead round trip");
        tag[0] ^= 1;
        CHECK(cipher_aead_open(key, nonce, aad, 12, ct, 114, tag, pt2) == -1,
              "aead rejects a flipped tag bit");
        tag[0] ^= 1;
        ct[50] ^= 0x80;
        CHECK(cipher_aead_open(key, nonce, aad, 12, ct, 114, tag, pt2) == -1,
              "aead rejects a tampered ciphertext");
        ct[50] ^= 0x80;
        CHECK(cipher_aead_open(key, nonce, aad, 11, ct, 114, tag, pt2) == -1,
              "aead rejects truncated aad");
        cipher_aead_seal(key, nonce, aad, 0, (const unsigned char *)"", 0, ct, tag2);
        CHECK(cipher_aead_open(key, nonce, aad, 0, ct, 0, tag2, pt2) == 0,
              "aead empty message round trip");
    }

    /* ---- constant-time compare ---- */
    memset(buf, 0, 16); memset(buf2, 0, 16);
    CHECK(cipher_ct_eq(buf, buf2, 16) == 1, "ct_eq equal");
    buf2[15] = 1;
    CHECK(cipher_ct_eq(buf, buf2, 16) == 0, "ct_eq detects the last byte");

    printf("%d checks passed\n", checks);
    return 0;
}
