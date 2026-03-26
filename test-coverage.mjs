import { ed25519 } from '/tmp/node_modules/@noble/curves/ed25519.js';
import { blake2b } from '/tmp/node_modules/@noble/hashes/blake2.js';
import { sha512 } from '/tmp/node_modules/@noble/hashes/sha2.js';
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';

const SC = webcrypto.subtle;
const ENC = new TextEncoder();
const DEC = new TextDecoder();
const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('');
const fromHex = h => { const s = h.replace(/\s/g,''); return new Uint8Array(s.match(/.{2}/g).map(b=>parseInt(b,16))); };
const toB64 = b => Buffer.from(b).toString('base64');
const fromB64 = s => Uint8Array.from(Buffer.from(s, 'base64'));
const toPem = (t,b) => `-----BEGIN ${t}-----\n${toB64(b).match(/.{1,64}/g).join('\n')}\n-----END ${t}-----`;
const fromPem = p => fromB64(p.replace(/-----[^-]+-----|\s/g,''));
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
const L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
const Pt = ed25519.Point;
const leToBI = b => { let n=0n; for(let i=b.length-1;i>=0;i--) n=(n<<8n)|BigInt(b[i]); return n; };
const biToLE = (n,len) => { const a=new Uint8Array(len); for(let i=0;i<len;i++){a[i]=Number(n&0xffn);n>>=8n;} return a; };

function kpTweak(pub, name) {
  const nb = typeof name==='string' ? ENC.encode(name) : name;
  const seed = blake2b(new Uint8Array([...pub,...nb]), {dkLen:32});
  const h = sha512(seed).slice(0, 32); h[31] &= 0x7f;
  return { scalar: leToBI(h), pub: Pt.BASE.multiply(leToBI(h) % L).toBytes() };
}
function kpFullDerive(pp, ps, name) {
  const t = kpTweak(pp, name); const cs = (ps + t.scalar) % L;
  return { pub: Pt.BASE.multiply(cs).toBytes(), scalar: cs };
}

async function aesGCMEncrypt(keyBytes, plaintext) {
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const k = await SC.importKey('raw', keyBytes, {name:'AES-GCM'}, false, ['encrypt']);
  const ct = await SC.encrypt({name:'AES-GCM',iv}, k, ENC.encode(plaintext));
  const out = new Uint8Array(12+ct.byteLength); out.set(iv); out.set(new Uint8Array(ct),12);
  return toB64(out);
}
async function aesGCMDecrypt(keyBytes, b64) {
  const bytes = fromB64(b64);
  const k = await SC.importKey('raw', keyBytes, {name:'AES-GCM'}, false, ['decrypt']);
  return DEC.decode(await SC.decrypt({name:'AES-GCM',iv:bytes.slice(0,12)}, k, bytes.slice(12)));
}
async function hmacOTP(secret, counter, digits, alg) {
  const key = await SC.importKey('raw', secret, { name: 'HMAC', hash: alg }, false, ['sign']);
  const buf = new ArrayBuffer(8); const dv = new DataView(buf);
  dv.setUint32(0, Math.floor(counter / 0x100000000)); dv.setUint32(4, counter >>> 0);
  const hmac = new Uint8Array(await SC.sign('HMAC', key, buf));
  const off = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[off]&0x7f)<<24|(hmac[off+1]<<16)|(hmac[off+2]<<8)|hmac[off+3]) % (10**digits);
  return code.toString().padStart(digits, '0');
}
function parseOTPAuth(uri) {
  try {
    const u = new URL(uri);
    const secret = u.searchParams.get('secret') || '';
    const alg = (u.searchParams.get('algorithm') || 'SHA1').replace('SHA', 'SHA-');
    const digits = +(u.searchParams.get('digits') || 6);
    const period = +(u.searchParams.get('period') || 30);
    const issuer = u.searchParams.get('issuer') || '';
    const type = u.hostname === 'totp' || u.pathname.startsWith('//totp') ? 'totp' : 'hotp';
    const counter = +(u.searchParams.get('counter') || 0);
    return { secret, alg, digits, period, issuer, type, counter };
  } catch { return null; }
}
function base32Encode(bytes) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  let out = ''; for (let i = 0; i < bits.length; i += 5) out += A[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
}

let passed = 0, failed = 0;
function assert(c, l) { if (c) { console.log(`  ✓ ${l}`); passed++; } else { console.error(`  ✗ FAIL: ${l}`); failed++; } }
function assertEq(a, b, l) { const sa = typeof a==='string'?a:toHex(a), sb = typeof b==='string'?b:toHex(b);
  if (sa!==sb) console.error(`    got:      ${sa}\n    expected: ${sb}`); assert(sa===sb, l); }

console.log('\n══ Coverage test suite ══\n');

console.log('── 33: toPem / fromPem ──');
{
  const cases = [new Uint8Array([0x42]), new Uint8Array(48).fill(0xAB), new Uint8Array(256).fill(0xCD)];
  for (const bytes of cases) {
    const pem = toPem('PUBLIC KEY', bytes);
    assert(pem.startsWith('-----BEGIN PUBLIC KEY-----'), `PEM header (${bytes.length}B)`);
    assert(pem.endsWith('-----END PUBLIC KEY-----'), `PEM footer (${bytes.length}B)`);
    assert(pem.split('\n').slice(1,-1).every(l => l.length <= 64), `PEM line wrap (${bytes.length}B)`);
    assertEq(fromPem(pem), bytes, `PEM round-trip (${bytes.length}B)`);
  }
  assertEq(fromPem(toPem('PRIVATE KEY', new Uint8Array(32).fill(0xFF))), new Uint8Array(32).fill(0xFF), 'PEM type PRIVATE KEY');
}

console.log('\n── 34: HTML esc() ──');
{
  assertEq(esc('a&b'), 'a&amp;b', 'esc &');
  assertEq(esc('a<b'), 'a&lt;b', 'esc <');
  assertEq(esc('a>b'), 'a&gt;b', 'esc >');
  assertEq(esc('a"b'), 'a&quot;b', 'esc "');
  assertEq(esc("a'b"), "a&#39;b", "esc '");
  assertEq(esc('<script>alert("xss")</script>'), '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;', 'esc XSS payload');
  assertEq(esc('normal 123'), 'normal 123', 'esc passthrough');
  assertEq(esc(42), '42', 'esc number coercion');
  assertEq(esc(null), 'null', 'esc null coercion');
}

console.log('\n── 35: parseOTPAuth ──');
{
  const p1 = parseOTPAuth('otpauth://totp/Test:user@ex.com?secret=JBSWY3DPEHPK3PXP&issuer=Test&algorithm=SHA256&digits=8&period=60');
  assertEq(p1.secret, 'JBSWY3DPEHPK3PXP', 'OTP secret'); assertEq(p1.alg, 'SHA-256', 'OTP alg');
  assert(p1.digits === 8, 'OTP digits'); assert(p1.period === 60, 'OTP period');
  assertEq(p1.issuer, 'Test', 'OTP issuer'); assertEq(p1.type, 'totp', 'OTP type=totp');
  const p2 = parseOTPAuth('otpauth://hotp/C?secret=ABC&counter=42');
  assertEq(p2.type, 'hotp', 'OTP type=hotp'); assert(p2.counter === 42, 'OTP counter');
  const p3 = parseOTPAuth('otpauth://totp/M?secret=XYZ');
  assertEq(p3.alg, 'SHA-1', 'OTP default alg'); assert(p3.digits === 6, 'OTP default digits'); assert(p3.period === 30, 'OTP default period');
  assert(parseOTPAuth('not-a-url') === null, 'OTP invalid → null');
  assert(parseOTPAuth('') === null, 'OTP empty → null');
}

console.log('\n── 36: BIP39 wordlist integrity ──');
{
  const src = readFileSync(new URL('./bip39.js', import.meta.url), 'utf8');
  const BIP39 = eval(src.replace('const BIP39 = ', '').replace(/;\s*$/, ''));
  assert(BIP39.length === 2048, 'BIP39 has 2048 words');
  assert(new Set(BIP39).size === 2048, 'BIP39 no duplicates');
  assert(JSON.stringify(BIP39) === JSON.stringify([...BIP39].sort()), 'BIP39 sorted');
  assertEq(BIP39[0], 'abandon', 'BIP39[0]'); assertEq(BIP39[2047], 'zoo', 'BIP39[2047]');
  assertEq(BIP39[1], 'ability', 'BIP39[1]'); assertEq(BIP39[100], 'arrive', 'BIP39[100]');
}

console.log('\n── 37: Mnemonic generation logic ──');
{
  const src = readFileSync(new URL('./bip39.js', import.meta.url), 'utf8');
  const BIP39 = eval(src.replace('const BIP39 = ', '').replace(/;\s*$/, ''));
  function genMn(bytes, count) {
    const bits = Array.from(bytes).map(b=>b.toString(2).padStart(8,'0')).join('');
    return Array.from({length:count}, (_,i) => BIP39[parseInt(bits.slice(i*11,(i+1)*11),2)%2048]).join(' ');
  }
  const m12 = genMn(new Uint8Array(16).fill(0), 12);
  assert(m12.split(' ').length === 12, '12 words from 16B'); assert(m12.split(' ')[0] === 'abandon', 'zeros → abandon');
  assert(m12.split(' ').every(w => BIP39.includes(w)), '12-word all valid');
  const m24 = genMn(new Uint8Array(32).fill(0xFF), 24);
  assert(m24.split(' ').length === 24, '24 words from 32B'); assert(m24.split(' ')[0] === 'zoo', '0xFF → zoo');
  assert(genMn(new Uint8Array(16).fill(0), 12) === m12, 'mnemonic deterministic');
  assert(genMn(new Uint8Array(16).fill(0x42), 12) !== m12, 'different entropy → different words');
}

console.log('\n── 38: BIP39 seed derivation (RFC vector) ──');
{
  const mn = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const b = await SC.importKey('raw', ENC.encode(mn), {name:'PBKDF2'}, false, ['deriveBits']);
  const seed = await SC.deriveBits({name:'PBKDF2',hash:'SHA-512',salt:ENC.encode('mnemonic'),iterations:2048}, b, 512);
  assertEq(toHex(seed), '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4', 'BIP39 seed vector');
  const b2 = await SC.importKey('raw', ENC.encode(mn), {name:'PBKDF2'}, false, ['deriveBits']);
  const withPass = await SC.deriveBits({name:'PBKDF2',hash:'SHA-512',salt:ENC.encode('mnemonicTREZOR'),iterations:2048}, b2, 512);
  assert(toHex(withPass) !== toHex(seed), 'passphrase changes seed');
}

console.log('\n── 39: RSA-OAEP encrypt/decrypt ──');
{
  const rk = await SC.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
  const ct = await SC.encrypt({name:'RSA-OAEP'}, rk.publicKey, ENC.encode('rsa test'));
  assertEq(DEC.decode(await SC.decrypt({name:'RSA-OAEP'}, rk.privateKey, ct)), 'rsa test', 'RSA round-trip');
  const rk2 = await SC.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
  try { await SC.decrypt({name:'RSA-OAEP'}, rk2.privateKey, ct); assert(false, 'RSA wrong key'); } catch { assert(true, 'RSA wrong key rejects'); }
  const spki = await SC.exportKey('spki', rk.publicKey);
  const pem = toPem('PUBLIC KEY', spki);
  const reimp = await SC.importKey('spki', fromPem(pem), {name:'RSA-OAEP',hash:'SHA-256'}, false, ['encrypt']);
  const ct2 = await SC.encrypt({name:'RSA-OAEP'}, reimp, ENC.encode('pem'));
  assertEq(DEC.decode(await SC.decrypt({name:'RSA-OAEP'}, rk.privateKey, ct2)), 'pem', 'RSA PEM import');
}

console.log('\n── 40: Ed25519 WebCrypto keygen ──');
{
  const ek = await SC.generateKey({name:'Ed25519'},true,['sign','verify']);
  const sig = await SC.sign({name:'Ed25519'}, ek.privateKey, ENC.encode('ed25519 test'));
  assert(new Uint8Array(sig).length === 64, 'Ed25519 sig 64B');
  assert(await SC.verify({name:'Ed25519'}, ek.publicKey, sig, ENC.encode('ed25519 test')), 'Ed25519 verify ok');
  assert(!await SC.verify({name:'Ed25519'}, ek.publicKey, sig, ENC.encode('wrong')), 'Ed25519 verify rejects');
}

console.log('\n── 41: ECDH → HKDF → AES pipeline ──');
{
  const a = await SC.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const b = await SC.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const sA = await SC.deriveBits({name:'ECDH',public:b.publicKey},a.privateKey,256);
  const sB = await SC.deriveBits({name:'ECDH',public:a.publicKey},b.privateKey,256);
  assertEq(sA, sB, 'ECDH shared secret match');
  const hk = await SC.importKey('raw',sA,{name:'HKDF'},false,['deriveBits']);
  const aesK = new Uint8Array(await SC.deriveBits({name:'HKDF',hash:'SHA-256',salt:ENC.encode('encalc-ecdh'),info:ENC.encode('aes-256-gcm')},hk,256));
  const ct = await aesGCMEncrypt(aesK, 'ecdh msg');
  const hkB = await SC.importKey('raw',sB,{name:'HKDF'},false,['deriveBits']);
  const aesKB = new Uint8Array(await SC.deriveBits({name:'HKDF',hash:'SHA-256',salt:ENC.encode('encalc-ecdh'),info:ENC.encode('aes-256-gcm')},hkB,256));
  assertEq(await aesGCMDecrypt(aesKB, ct), 'ecdh msg', 'Bob decrypts Alice');
  const eve = await SC.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const sE = await SC.deriveBits({name:'ECDH',public:b.publicKey},eve.privateKey,256);
  const hkE = await SC.importKey('raw',sE,{name:'HKDF'},false,['deriveBits']);
  const aesE = new Uint8Array(await SC.deriveBits({name:'HKDF',hash:'SHA-256',salt:ENC.encode('encalc-ecdh'),info:ENC.encode('aes-256-gcm')},hkE,256));
  try { await aesGCMDecrypt(aesE, ct); assert(false, 'Eve decrypts'); } catch { assert(true, 'Eve cannot decrypt'); }
}

console.log('\n── 42: Format conversion matrix ──');
{
  const h = '48656c6c6f'; const bytes = fromHex(h);
  assertEq(DEC.decode(bytes), 'Hello', 'hex→utf8');
  assertEq(toB64(bytes), 'SGVsbG8=', 'hex→b64');
  assertEq(toHex(fromB64('SGVsbG8=')), h, 'b64→hex');
  assertEq(toHex(ENC.encode('Hello')), h, 'utf8→hex');
  assertEq(DEC.decode(fromPem(toPem('T', ENC.encode('Hello')))), 'Hello', 'pem round-trip');
  assertEq(toHex(fromB64(toB64(fromHex('cafebabe')))), 'cafebabe', 'hex→b64→hex');
}

console.log('\n── 43: Password AES salt:ct format ──');
{
  async function pbkdf2Key(p, s) { const b = await SC.importKey('raw',ENC.encode(p),{name:'PBKDF2'},false,['deriveKey']);
    return SC.deriveKey({name:'PBKDF2',salt:ENC.encode(s),hash:'SHA-256',iterations:100000},b,{name:'AES-GCM',length:256},true,['encrypt','decrypt']); }
  const salt = toHex(webcrypto.getRandomValues(new Uint8Array(8)));
  assert(salt.length === 16, 'salt is 16 hex chars');
  const k = new Uint8Array(await SC.exportKey('raw', await pbkdf2Key('pass', salt)));
  const ct = await aesGCMEncrypt(k, 'pw-test');
  const combined = salt + ':' + ct;
  assert(combined.includes(':'), 'format has colon');
  const [s2, ct2] = combined.split(':');
  const k2 = new Uint8Array(await SC.exportKey('raw', await pbkdf2Key('pass', s2)));
  assertEq(await aesGCMDecrypt(k2, ct2), 'pw-test', 'pw encrypt round-trip');
  const k3 = new Uint8Array(await SC.exportKey('raw', await pbkdf2Key('wrong', s2)));
  try { await aesGCMDecrypt(k3, ct2); assert(false, 'wrong pw'); } catch { assert(true, 'wrong pw rejects'); }
}

console.log('\n── 44: TOTP SHA-256/512 RFC 6238 ──');
{
  const s256 = ENC.encode('12345678901234567890123456789012');
  const v256 = [[59,'46119246'],[1111111109,'68084774'],[1111111111,'67062674'],[1234567890,'91819424'],[2000000000,'90698825']];
  for (const [t, exp] of v256) assertEq(await hmacOTP(s256, Math.floor(t/30), 8, 'SHA-256'), exp, `TOTP-256 t=${t}`);
  const s512 = ENC.encode('1234567890123456789012345678901234567890123456789012345678901234');
  const v512 = [[59,'90693936'],[1111111109,'25091201'],[1111111111,'99943326'],[1234567890,'93441116'],[2000000000,'38618901']];
  for (const [t, exp] of v512) assertEq(await hmacOTP(s512, Math.floor(t/30), 8, 'SHA-512'), exp, `TOTP-512 t=${t}`);
}

console.log('\n── 45: HOTP RFC 4226 vectors ──');
{
  const secret = ENC.encode('12345678901234567890');
  const expected = ['755224','287082','359152','969429','338314','254676','287922','162583','399871','520489'];
  for (let i = 0; i < 10; i++) assertEq(await hmacOTP(secret, i, 6, 'SHA-1'), expected[i], `HOTP c=${i}`);
}

console.log('\n── 46: Tree-path encrypt isolation ──');
{
  const seed = fromHex('deadbeefcafebabe0102030405060708090a0b0c0d0e0f101112131415161718');
  function pathKey(s, path) { let sc=leToBI(s)%L, pub=Pt.BASE.multiply(sc).toBytes();
    for (const seg of path.split('/').filter(Boolean)){const d=kpFullDerive(pub,sc,seg);pub=d.pub;sc=d.scalar;} return pub.slice(0,32); }
  const k1 = pathKey(seed, 'app/enc'), k2 = pathKey(seed, 'app/sign');
  assert(toHex(k1) !== toHex(k2), 'different paths → different keys');
  const ct = await aesGCMEncrypt(k1, 'tree msg');
  assertEq(await aesGCMDecrypt(k1, ct), 'tree msg', 'same path decrypts');
  try { await aesGCMDecrypt(k2, ct); assert(false, 'wrong path'); } catch { assert(true, 'wrong path rejects'); }
  const diffSeed = fromHex('aa'.repeat(32));
  try { await aesGCMDecrypt(pathKey(diffSeed, 'app/enc'), ct); assert(false, 'wrong seed'); } catch { assert(true, 'wrong seed rejects'); }
}

console.log(`\n${'═'.repeat(52)}`);
console.log(`  ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
