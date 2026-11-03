/* Dedicated worker keeps expensive password derivation off the UI thread. */
"use strict";
importScripts("cipher.js");
const moduleReady = createCipher();
self.onmessage = async ({data}) => {
  let M, inp = 0, outp = 0, pwp = 0, cap = 0, pass;
  try {
    M = await moduleReady;
    pass = new TextEncoder().encode(data.password);
    if (!pass.length || pass.length > 254 || pass.includes(0))
      throw new Error("Use a password of 1 to 254 UTF-8 bytes, without NUL characters.");
    const bytes = new Uint8Array(data.bytes);
    if (bytes.length > 16 * 1024 * 1024 + (data.decrypt ? 6000 : 0)) throw new Error("File exceeds the 16 MB demo limit.");
    inp = M._malloc(bytes.length || 1);
    cap = data.decrypt ? bytes.length : bytes.length + M._w_overhead(bytes.length);
    outp = M._malloc(cap || 1);
    pwp = M._malloc(pass.length + 1);
    if (!inp || !outp || !pwp) throw new Error("Not enough memory.");
    M.HEAPU8.set(bytes, inp);
    M.HEAPU8.set(pass, pwp); M.HEAPU8[pwp + pass.length] = 0;
    const n = M._w_crypt(inp, bytes.length, pwp, data.decrypt ? 1 : 0, outp, cap);
    if (n < 0) throw new Error(data.decrypt ? "Decryption failed: wrong password or damaged file." : "Encryption failed.");
    const result = M.HEAPU8.slice(outp, outp + n);
    self.postMessage({ok: true, bytes: result.buffer}, [result.buffer]);
  } catch (e) {
    self.postMessage({ok: false, error: e.message || "Operation failed."});
  } finally {
    if (pass) pass.fill(0);
    if (M) {
      for (const [p, n] of [[inp, data.bytes.byteLength], [outp, cap], [pwp, pass ? pass.length + 1 : 0]]) {
        if (p) { M._cipher_wipe(p, n); M._free(p); }
      }
    }
    // No retained file buffers or live module after completion.
    self.close();
  }
};
