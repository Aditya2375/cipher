CC ?= cc
WARN := -Wall -Wextra -Werror
CFLAGS ?= -O2 -g
CFLAGS += $(WARN) -Isrc
CORE := src/sha256.c src/hmac.c src/pbkdf2.c src/chacha20.c src/poly1305.c src/aead.c src/format.c
HDRS := $(wildcard src/*.h)

all: build/cipher build/test-unit

build:
	mkdir -p build

build/cipher: src/main.c $(CORE) $(HDRS) | build
	$(CC) $(CFLAGS) $(EXTRA) -o $@ src/main.c $(CORE)

build/test-unit: tests/unit/test-unit.c $(CORE) $(HDRS) | build
	$(CC) $(CFLAGS) $(EXTRA) -o $@ tests/unit/test-unit.c $(CORE)

build/test-fuzz: tests/fuzz/fuzz-driver.c $(CORE) $(HDRS) | build
	$(CC) $(CFLAGS) $(EXTRA) -o $@ tests/fuzz/fuzz-driver.c $(CORE)

test: build/test-unit
	./build/test-unit

sanitize: EXTRA = -fsanitize=address,undefined,float-cast-overflow -fno-sanitize-recover=all -fno-omit-frame-pointer
sanitize: clean build/cipher build/test-unit build/test-fuzz
	./build/test-unit
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 python3 tests/fuzz.py --blobs 60

clean:
	rm -rf build

.PHONY: all test sanitize clean
