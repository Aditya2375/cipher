/* app.js - drives the in-page cipher wasm build: pick a file, type a
 * password, encrypt or decrypt entirely in the browser. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const MAX = 16 * 1024 * 1024;
  let M = null;
  let file = null;

  function log(msg, cls) {
    const d = document.createElement("div");
    if (cls) d.className = cls;
    d.textContent = msg;
    const el = $("log");
    el.appendChild(d);
    el.scrollTop = el.scrollHeight;
  }

  function ready() {
    const on = M && file && file.size <= MAX;
    $("enc").disabled = !on;
    $("dec").disabled = !on;
  }

  createCipher().then((m) => {
    M = m;
    log("wasm module ready: the same format.c the CLI runs", "ok");
    ready();
  }).catch(() => log("failed to load the wasm module", "bad"));

  $("pick").addEventListener("change", (e) => {
    file = e.target.files[0] || null;
    $("dl").style.display = "none";
    if (!file) {
      $("fname").textContent = "no file chosen (16 MB demo limit)";
    } else if (file.size > MAX) {
      $("fname").textContent = file.name + " is over the 16 MB demo limit";
      log("file too large for the browser demo; the CLI has no such limit", "bad");
    } else {
      $("fname").textContent = file.name + " (" + file.size + " bytes)";
    }
    ready();
  });

  function outName(name, decrypt) {
    if (decrypt)
      return name.endsWith(".cph") ? name.slice(0, -4) : name + ".dec";
    return name + ".cph";
  }

  function crypt(decrypt) {
    const pw = $("pw").value;
    if (!pw) {
      log("enter a password first", "bad");
      return;
    }
    $("enc").disabled = true;
    $("dec").disabled = true;
    file.arrayBuffer().then((buf) => {
      const inlen = buf.byteLength;
      const inp = M._malloc(inlen || 1);
      M.HEAPU8.set(new Uint8Array(buf), inp);
      const cap = decrypt
        ? inlen
        : inlen + M.ccall("w_overhead", "number", ["number"], [inlen]);
      const outp = M._malloc(cap || 1);
      const t0 = performance.now();
      const n = M.ccall("w_crypt", "number",
        ["number", "number", "string", "number", "number", "number"],
        [inp, inlen, pw, decrypt, outp, cap]);
      M.HEAPU8.fill(0, inp, inp + inlen);
      M._free(inp);
      if (n < 0) {
        M._free(outp);
        log(decrypt
          ? "decryption failed: wrong password or tampered file"
          : "encryption failed", "bad");
        ready();
        return;
      }
      const res = M.HEAPU8.slice(outp, outp + n);
      M.HEAPU8.fill(0, outp, outp + n);
      M._free(outp);
      const a = $("dl");
      if (a.href && a.href.startsWith("blob:")) URL.revokeObjectURL(a.href);
      a.href = URL.createObjectURL(new Blob([res], { type: "application/octet-stream" }));
      a.download = outName(file.name, decrypt);
      a.textContent = "download " + a.download + " (" + n + " bytes)";
      a.style.display = "inline";
      log((decrypt ? "decrypted" : "encrypted") + " in " +
          Math.round(performance.now() - t0) + " ms, " + n + " bytes out", "ok");
      ready();
    });
  }

  $("enc").addEventListener("click", () => crypt(false));
  $("dec").addEventListener("click", () => crypt(true));
})();
