/* Run the actual worker script with a minimal worker host in Node. */
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const factory = require('../docs/cipher.js');
async function run(bytes, password, decrypt) {
  let close, finish;
  const done = new Promise(resolve => { finish = resolve; });
  const host = {TextEncoder, Uint8Array, Error, createCipher:factory, importScripts() {},
    self:{postMessage:finish, close() { close = true; }}};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../docs/worker.js'),'utf8'),host);
  await host.self.onmessage({data:{bytes:bytes.buffer, password, decrypt}});
  if (!close) throw new Error('worker was not closed');
  return done;
}
(async () => {
  const pt = new TextEncoder().encode('sample \u2603 text');
  const enc = await run(pt, 'long demo passphrase',false);
  if (!enc.ok) throw Error(enc.error);
  const dec = await run(new Uint8Array(enc.bytes),'long demo passphrase',true);
  if (!dec.ok || Buffer.compare(Buffer.from(dec.bytes),Buffer.from(pt))) throw Error('worker round trip failed');
  const wrong = await run(new Uint8Array(enc.bytes),'wrong',true);
  if (wrong.ok) throw Error('wrong password accepted');
  const long = await run(pt,'x'.repeat(255),false);
  if (long.ok) throw Error('long password accepted');
  const nul = await run(pt,'a\0b',false);
  if (nul.ok) throw Error('NUL password accepted');
  console.log('5 worker checks passed');
})().catch(e => { console.error(e);process.exit(1); });
