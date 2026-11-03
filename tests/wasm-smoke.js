/* Smoke test for the wasm demo build: boots the module and drives the
 * same w_crypt API the page uses - encrypt, round trip, wrong password,
 * tamper rejection, empty file. Run after sh wasm/build.sh:
 *   node tests/wasm-smoke.js [path/to/cipher.js] */
const factory = require(process.argv[2] || require("path").join(__dirname, "..", "docs", "cipher.js"));
let fails = 0;
function ok(cond, label) {
    if (cond) console.log("ok: " + label);
    else { console.log("FAIL: " + label); fails = 1; }
}
factory().then(m => {
    function crypt(bytes, pw, decrypt) {
        const inp = m._malloc(bytes.length || 1);
        m.HEAPU8.set(bytes, inp);
        const cap = decrypt ? bytes.length
            : bytes.length + m.ccall("w_overhead", "number", ["number"], [bytes.length]);
        const outp = m._malloc(cap || 1);
        const n = m.ccall("w_crypt", "number",
            ["number", "number", "string", "number", "number", "number"],
            [inp, bytes.length, pw, decrypt ? 1 : 0, outp, cap]);
        const res = n >= 0 ? m.HEAPU8.slice(outp, outp + n) : null;
        m._free(inp);
        m._free(outp);
        return res;
    }

    ok(typeof m.ccall("w_overhead", "number", ["number"], [1000]) === "number",
       "module boots and answers w_overhead");

    const pt = new Uint8Array(200000);
    for (let i = 0; i < pt.length; i++) pt[i] = (i * 31 + 7) & 0xff;

    const ct = crypt(pt, "correct horse battery staple", false);
    ok(ct && ct.length > pt.length &&
       ct[0] === 0x43 && ct[1] === 0x49 && ct[2] === 0x50 && ct[3] === 0x48,
       "encrypt produces a CIPH container");

    const back = crypt(ct, "correct horse battery staple", true);
    ok(back && back.length === pt.length && back.every((b, i) => b === pt[i]),
       "decrypt round-trips 200 KB across chunk boundaries");

    ok(crypt(ct, "wrong password", true) === null,
       "a wrong password is rejected");

    const bad = ct.slice();
    bad[bad.length - 20] ^= 1;
    ok(crypt(bad, "correct horse battery staple", true) === null,
       "a flipped ciphertext byte is rejected");

    const empty = crypt(new Uint8Array(0), "pw", false);
    const emptyBack = empty && crypt(empty, "pw", true);
    ok(emptyBack && emptyBack.length === 0, "an empty file round-trips");

    process.exit(fails);
});
