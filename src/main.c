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

static int read_line(char *out, size_t cap) {
    if (!fgets(out, (int)cap, stdin)) return -1;
    size_t n = strlen(out);
    if (n && out[n-1] != '\n' && !feof(stdin)) {
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {}
        fprintf(stderr, "password too long (maximum 254 bytes)\n");
        return -1;
    }
    while (n && (out[n-1] == '\n' || out[n-1] == '\r')) out[--n] = 0;
    return n <= 254 ? 0 : -1;
}

static int read_password(const char *prompt1, const char *prompt2,
                         char *out, size_t cap) {
    struct termios old, no;
    int have_tty = isatty(0), rc = -1;
    char again[256] = {0};
    if (have_tty) {
        if (tcgetattr(0, &old) != 0) return -1;
        no = old;
        no.c_lflag &= ~(unsigned)ECHO;
        fputs(prompt1, stderr);
        if (tcsetattr(0, TCSANOW, &no) != 0) return -1;
    }
    if (read_line(out, cap) != 0) goto done;
    if (prompt2) {
        if (have_tty) { fputc('\n', stderr); fputs(prompt2, stderr); }
        if (read_line(again, sizeof again) != 0) goto done;
        if (strcmp(out, again) != 0) {
            fprintf(stderr, "passwords do not match\n");
            goto done;
        }
    }
    rc = 0;
done:
    wipe(again, sizeof again);
    if (have_tty) {
        tcsetattr(0, TCSANOW, &old);
        fputc('\n', stderr);
    }
    return rc;
}

static int run(const char *in_path, const char *out_path, int decrypt) {
    char password[256] = {0};
    if (read_password(decrypt ? "password: " : "new password: ",
                      decrypt ? NULL : "confirm: ", password, sizeof password) != 0) {
        fprintf(stderr, "could not read the password\n");
        wipe(password, sizeof password);
        return 1;
    }
    if (!*password) {
        fprintf(stderr, "empty password\n");
        wipe(password, sizeof password);
        return 1;
    }
    FILE *in = fopen(in_path, "rb");
    if (!in) { perror(in_path); wipe(password, sizeof password); return 1; }
    /* Never follow a symlink, truncate another file, or expose plaintext
     * to other local users. Exclusive creation also rejects hard links. */
    int fd = open(out_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) { perror(out_path); fclose(in); wipe(password, sizeof password); return 1; }
    FILE *out = fdopen(fd, "wb");
    if (!out) { close(fd); remove(out_path); }
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
