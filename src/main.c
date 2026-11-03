/* main.c - cipher: password file encryption, from scratch. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/stat.h>
#include "format.h"

static void wipe(void *p, size_t n) {
    volatile unsigned char *v = p;
    while (n--) *v++ = 0;
}

static int read_password(const char *prompt1, const char *prompt2,
                         char *out, size_t cap) {
    struct termios old, no;
    int have_tty = isatty(0);
    if (have_tty) {
        tcgetattr(0, &old);
        no = old;
        no.c_lflag &= ~(unsigned)ECHO;
        fputs(prompt1, stderr);
        tcsetattr(0, TCSANOW, &no);
    }
    int rc = -1;
    if (!fgets(out, (int)cap, stdin))
        goto done;
    if (have_tty) {
        tcsetattr(0, TCSANOW, &old);
        fputc('\n', stderr);
        fputs(prompt2, stderr);
        tcsetattr(0, TCSANOW, &no);
    }
    size_t l = strlen(out);
    while (l && (out[l-1] == '\n' || out[l-1] == '\r')) out[--l] = 0;
    if (prompt2) {
        char again[256];
        if (!fgets(again, (int)cap, stdin))
            goto done;
        size_t al = strlen(again);
        while (al && (again[al-1] == '\n' || again[al-1] == '\r')) again[--al] = 0;
        if (strcmp(out, again) != 0) {
            wipe(again, sizeof again);
            fprintf(stderr, "passwords do not match\n");
            goto done;
        }
        wipe(again, sizeof again);
    }
    rc = 0;
done:
    if (have_tty)
        tcsetattr(0, TCSANOW, &old);
    return rc;
}

static int run(const char *in_path, const char *out_path, int decrypt) {
    char password[256];
    if (read_password(decrypt ? "password: " : "new password: ",
                      decrypt ? NULL : "confirm: ", password, sizeof password) != 0) {
        fprintf(stderr, "could not read the password\n");
        return 1;
    }
    if (!*password) {
        fprintf(stderr, "empty password\n");
        wipe(password, sizeof password);
        return 1;
    }
    FILE *in = fopen(in_path, "rb");
    if (!in) { perror(in_path); wipe(password, sizeof password); return 1; }
    FILE *out = fopen(out_path, "wb");
    if (!out) { perror(out_path); fclose(in); wipe(password, sizeof password); return 1; }
    int rc = cipher_crypt_file(in, out, password, decrypt);
    fclose(in);
    int werr = fclose(out) != 0;
    if (rc != 0 || werr) {
        remove(out_path);   /* never leave a partial or unverified file */
        rc = 1;
    }
    wipe(password, sizeof password);
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        fprintf(stderr,
            "cipher - password file encryption (ChaCha20-Poly1305, PBKDF2)\n"
            "  cipher encrypt <file> [out.cph]   (default: <file>.cph)\n"
            "  cipher decrypt <file.cph> [out]   (default: strip .cph)\n");
        return 2;
    }
    int decrypt;
    if (!strcmp(argv[1], "encrypt")) decrypt = 0;
    else if (!strcmp(argv[1], "decrypt")) decrypt = 1;
    else { fprintf(stderr, "unknown command: %s\n", argv[1]); return 2; }
    char outbuf[4096];
    const char *out_path;
    if (argc == 4) {
        out_path = argv[3];
    } else if (!decrypt) {
        if (snprintf(outbuf, sizeof outbuf, "%s.cph", argv[2]) >= (int)sizeof outbuf)
            return 2;
        out_path = outbuf;
    } else {
        size_t l = strlen(argv[2]);
        if (l > 4 && !strcmp(argv[2] + l - 4, ".cph")) {
            if (l - 4 >= sizeof outbuf) return 2;
            memcpy(outbuf, argv[2], l - 4);
            outbuf[l - 4] = 0;
        } else if (snprintf(outbuf, sizeof outbuf, "%s.out", argv[2]) >= (int)sizeof outbuf)
            return 2;
        out_path = outbuf;
    }
    if (!strcmp(argv[2], out_path)) {
        fprintf(stderr, "input and output paths are the same\n");
        return 2;
    }
    return run(argv[2], out_path, decrypt);
}
