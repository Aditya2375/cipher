/* All file work stays on-device. No uploads, persistence or analytics. */
(function () {
  "use strict";
  const $ = id => document.getElementById(id);
  const MAX = 16 * 1024 * 1024;
  const INPUT_MAX = MAX + 6000;
  let file = null, busy = false, url = null;
  function log(msg, cls) {
    const d = document.createElement("div");
    d.className = cls || "dim"; d.textContent = msg;
    $("log").appendChild(d);
    $("log").scrollTop = $("log").scrollHeight;
  }
  function clearResult() {
    if (url) URL.revokeObjectURL(url);
    url = null; $("dl").removeAttribute("href"); $("dl").style.display = "none";
  }
  function ready() {
    $("pick").disabled = busy;
    $("pw").disabled = busy; $("confirm").disabled = busy;
    $("enc").disabled = busy || !file || file.size > INPUT_MAX;
    $("dec").disabled = $("enc").disabled;
  }
  $("pick").addEventListener("change", e => {
    file = e.target.files[0] || null; clearResult();
    $("fname").textContent = !file ? "no file chosen (16 MB demo limit)" :
      file.name + " (" + file.size + " bytes)" + (file.size > INPUT_MAX ? " - too large" : "");
    ready();
  });
  async function crypt(decrypt) {
    if (busy || !file || file.size > INPUT_MAX) return;
    if (!decrypt && file.size > MAX) { log("Plaintext exceeds the 16 MB demo limit.", "bad"); return; }
    const chosen = file;
    const pw = $("pw").value;
    const pass = new TextEncoder().encode(pw);
    const valid = pass.length > 0 && pass.length <= 254 && !pass.includes(0);
    pass.fill(0);
    if (!valid) { log("Use a password of 1 to 254 UTF-8 bytes, without NUL characters.", "bad"); return; }
    if (!decrypt && pw !== $("confirm").value) { log("Password confirmation does not match.", "bad"); return; }
    busy = true; ready(); clearResult();
    log((decrypt ? "Decrypting" : "Encrypting") + " in a background worker...", "dim");
    let worker = null;
    const t0 = performance.now();
    try {
      const bytes = await chosen.arrayBuffer();
      worker = new Worker("worker.js");
      const result = await new Promise((resolve, reject) => {
        worker.onmessage = ({data}) => data.ok ? resolve(data.bytes) : reject(new Error(data.error));
        worker.onerror = () => reject(new Error("The encryption worker could not finish."));
        worker.postMessage({bytes, password: pw, decrypt}, [bytes]);
      });
      const name = decrypt ? (chosen.name.endsWith(".cph") && chosen.name.length > 4 ? chosen.name.slice(0,-4) : chosen.name + ".dec") : chosen.name + ".cph";
      url = URL.createObjectURL(new Blob([result], {type: "application/octet-stream"}));
      const a = $("dl"); a.href = url; a.download = name;
      a.textContent = "download " + name + " (" + result.byteLength + " bytes)";
      a.style.display = "inline";
      log((decrypt ? "Decrypted" : "Encrypted") + " in " + Math.round(performance.now()-t0) + " ms, " + result.byteLength + " bytes out", "ok");
    } catch (e) { log(e.message || "Could not read the file.", "bad"); }
    finally {
      if (worker) worker.terminate();
      $("pw").value = ""; $("confirm").value = "";
      busy = false; ready();
    }
  }
  $("enc").addEventListener("click", () => crypt(false));
  $("dec").addEventListener("click", () => crypt(true));
  log("Ready. File data stays in memory; password derivation runs in a worker.", "ok");
  ready();
})();
