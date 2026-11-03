#!/usr/bin/env python3
"""Optional independent oracle test: needs the cryptography package.
No runtime dependency. Build a temporary shared object; compare the complete
AEAD ciphertext/tag with its vetted ChaCha20Poly1305 implementation."""
import ctypes as c
import random
import subprocess
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
rng = random.Random(20261103)
with tempfile.TemporaryDirectory() as td:
    lib = Path(td) / 'cipher.so'
    subprocess.run(['cc', '-O2', '-shared', '-fPIC', '-Isrc', '-o', str(lib),
                    'src/chacha20.c', 'src/poly1305.c', 'src/aead.c'], check=True)
    obj = c.CDLL(str(lib))
    obj.cipher_aead_seal.argtypes = [c.c_void_p, c.c_void_p, c.c_void_p, c.c_size_t,
                                    c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p]
    obj.cipher_aead_open.argtypes = obj.cipher_aead_seal.argtypes
    for i in range(1000):
        n = [0, 1, 15, 16, 17, 63, 64, 65, 65536][i % 9] if i < 90 else rng.randrange(4096)
        key, nonce = rng.randbytes(32), rng.randbytes(12)
        pt, aad = rng.randbytes(n), rng.randbytes(rng.randrange(100))
        ct, tag = c.create_string_buffer(n), c.create_string_buffer(16)
        obj.cipher_aead_seal(key, nonce, aad, len(aad), pt, n, ct, tag)
        want = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
        assert ct.raw + tag.raw == want, ('ciphertext or tag mismatch', i, n)
        back = c.create_string_buffer(n)
        assert obj.cipher_aead_open(key, nonce, aad, len(aad), ct, n, tag, back) == 0
        assert back.raw == pt
print('1000 independent AEAD oracle comparisons passed')
