/* 校验 web/index.html 里的加密实现与固定测试向量一致。
 * 用法：node web/test-crypto.mjs
 */
import fs from 'node:fs';
import path from 'node:path';

const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const html = fs.readFileSync(path.join(here, 'index.html'), 'utf8');
const m = html.match(/\/\* ==== BEGIN-CRYPTO ==== \*\/([\s\S]*?)\/\* ==== END-CRYPTO ==== \*\//);
if (!m) { console.error('crypto block not found'); process.exit(1); }
const block = m[1];

const vectors = JSON.parse(fs.readFileSync(path.join(here, 'vectors.json'), 'utf8').replace(/^\uFEFF/, ''));

const stubs = `
const __el = () => ({ appendChild(){}, set innerHTML(v){}, get innerText(){return ''}, textContent:'', className:'', scrollTop:0, scrollHeight:0, style:{} });
const document = { getElementById: __el, createElement: __el };
`;
const factory = new Function(stubs + block + '\nreturn { BfgCrypto, hex, toHex, concat, pwd16FromString };');
const { BfgCrypto, hex, toHex, pwd16FromString } = factory();

const assert = (cond, msg) => { if (!cond) { console.error('FAIL:', msg); process.exitCode = 1; } else console.log('ok  :', msg); };

// 1. Encryption1
{
  const c = new BfgCrypto(pwd16FromString(vectors.name));
  await c.init();
  const frame = c.enc1(hex(vectors.precomm_plain));
  assert(toHex(frame) === vectors.precomm_enc1, `pre-comm enc1 == ${vectors.precomm_enc1}`);
  assert(toHex(c.dec1(frame)) === vectors.precomm_plain, 'pre-comm dec1 round-trip');
}

// 2. Encryption2
{
  const c = new BfgCrypto(pwd16FromString(vectors.name));
  await c.init();
  await c.setSession(hex(vectors.session_key_hex), hex(vectors.auth_hex));
  for (const v of vectors.enc2) {
    const frame = await c.enc2(v.ctr, hex(v.plain));
    assert(toHex(frame) === v.frame, `enc2 ${v.plain.slice(0, 12)}... matches python`);
    const d = await c.dec2(hex(v.frame));
    assert(d.macOk && d.ctr === v.ctr && toHex(d.plain) === v.plain, `dec2 ${v.plain.slice(0, 12)}... mac+plain ok`);
  }
}

// 3. 篡改必须被 MAC 拒绝
{
  const c = new BfgCrypto(pwd16FromString(vectors.name));
  await c.init();
  await c.setSession(hex(vectors.session_key_hex), hex(vectors.auth_hex));
  const fr = hex(vectors.enc2[1].frame);
  fr[6] ^= 0xFF;
  const d = await c.dec2(fr);
  assert(d.macOk === false, 'tampered frame rejected by MAC');
}
