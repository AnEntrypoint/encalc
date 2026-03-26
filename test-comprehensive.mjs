import { ed25519 } from '/tmp/node_modules/@noble/curves/ed25519.js';
import { blake2b } from '/tmp/node_modules/@noble/hashes/blake2.js';
import { sha512 } from '/tmp/node_modules/@noble/hashes/sha2.js';
import { webcrypto } from 'node:crypto';

const SC = webcrypto.subtle;
const ENC = new TextEncoder();
const DEC = new TextDecoder();
const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('');
const fromHex = h => { const s = h.replace(/\s/g,''); return new Uint8Array(s.match(/.{2}/g).map(b=>parseInt(b,16))); };
const toB64 = b => Buffer.from(b).toString('base64');
const fromB64 = s => Uint8Array.from(Buffer.from(s, 'base64'));
const isHex64 = s => /^[0-9a-f]{64}$/i.test(s.trim());

const L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
const Pt = ed25519.Point;
const leToBI = b => { let n=0n; for(let i=b.length-1;i>=0;i--) n=(n<<8n)|BigInt(b[i]); return n; };
const biToLE = (n,len) => { const a=new Uint8Array(len); for(let i=0;i<len;i++){a[i]=Number(n&0xffn);n>>=8n;} return a; };

let passed = 0, failed = 0;
function assert(cond, label) {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else { console.error(`  ✗ FAIL: ${label}`); failed++; }
}
function assertEq(a, b, label) {
  const sa = typeof a === 'string' ? a : toHex(a);
  const sb = typeof b === 'string' ? b : toHex(b);
  if (sa !== sb) console.error(`    got:      ${sa}\n    expected: ${sb}`);
  assert(sa === sb, label);
}

function kpTweak(pub, name) {
  const nb = typeof name==='string' ? ENC.encode(name) : name;
  const seed = blake2b(new Uint8Array([...pub,...nb]), {dkLen:32});
  const h = sha512(seed).slice(0, 32);
  h[31] &= 0x7f;
  const scalar = leToBI(h);
  return { scalar, pub: Pt.BASE.multiply(scalar % L).toBytes() };
}
function kpPubDerive(parentPub, name) {
  const t = kpTweak(parentPub, name);
  return Pt.fromHex(toHex(parentPub)).add(Pt.fromHex(toHex(t.pub))).toBytes();
}
function kpFullDerive(parentPub, parentScalar, name) {
  const t = kpTweak(parentPub, name);
  const cs = (parentScalar + t.scalar) % L;
  return { pub: Pt.BASE.multiply(cs).toBytes(), scalar: cs };
}
async function kpSign(scalar, msg) {
  const nb = typeof msg==='string' ? ENC.encode(msg) : msg;
  const pubBytes = Pt.BASE.multiply(scalar).toBytes();
  const scalarBytes = biToLE(scalar, 32);
  const r = leToBI(blake2b(new Uint8Array([...scalarBytes, ...nb]), {dkLen:64})) % L;
  const R = Pt.BASE.multiply(r).toBytes();
  const kBytes = new Uint8Array(await SC.digest('SHA-512', new Uint8Array([...R, ...pubBytes, ...nb])));
  const k = leToBI(kBytes) % L;
  const S = (r + k * scalar) % L;
  return new Uint8Array([...R, ...biToLE(S, 32)]);
}
function kpVerify(pubBytes, msg, sigBytes) {
  try { return ed25519.verify(sigBytes, typeof msg==='string'?ENC.encode(msg):msg, pubBytes); }
  catch { return false; }
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

function base32Decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  s = s.replace(/[=\s-]/g,'').toUpperCase();
  let bits = '';
  for (const c of s) { const i = A.indexOf(c); if (i >= 0) bits += i.toString(2).padStart(5, '0'); }
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(out);
}
function base32Encode(bytes) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < bits.length; i += 5) out += A[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
}

async function hmacOTP(secret, counter, digits, alg) {
  const key = await SC.importKey('raw', secret, { name: 'HMAC', hash: alg }, false, ['sign']);
  const buf = new ArrayBuffer(8);
  const dv = new DataView(buf);
  dv.setUint32(0, Math.floor(counter / 0x100000000));
  dv.setUint32(4, counter >>> 0);
  const hmac = new Uint8Array(await SC.sign('HMAC', key, buf));
  const off = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[off] & 0x7f) << 24 | (hmac[off + 1] << 16) | (hmac[off + 2] << 8) | hmac[off + 3]) % (10 ** digits);
  return code.toString().padStart(digits, '0');
}

function autoDetect(s) {
  if (/^[0-9a-f\s]+$/i.test(s) && s.replace(/\s/g,'').length%2===0) return 'hex';
  if (s.includes('-----BEGIN')) return 'pem';
  if (/^[A-Za-z0-9+/=]+$/.test(s)) return 'base64';
  return 'utf8';
}

async function deriveSeedBytes(raw, kdf, salt='encalc') {
  raw = raw.trim();
  if (kdf==='raw' || isHex64(raw)) return fromHex(raw.slice(0,64));
  if (kdf==='bip39') {
    const b = await SC.importKey('raw',ENC.encode(raw),{name:'PBKDF2'},false,['deriveBits']);
    return new Uint8Array(await SC.deriveBits({name:'PBKDF2',hash:'SHA-512',salt:ENC.encode('mnemonic'+salt),iterations:2048},b,256));
  }
  const b = await SC.importKey('raw',ENC.encode(raw),{name:'PBKDF2'},false,['deriveBits']);
  return new Uint8Array(await SC.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:ENC.encode(salt),iterations:100000},b,256));
}

console.log('\n══ Comprehensive encalc test suite ══\n');

console.log('── 8: Hex encode/decode round-trip ──');
{
  const cases = ['', '00', 'ff', 'deadbeef', '0123456789abcdef'.repeat(4)];
  for (const hex of cases) {
    if (!hex) continue;
    const bytes = fromHex(hex);
    assertEq(toHex(bytes), hex, `hex round-trip "${hex.slice(0,16)}${hex.length>16?'…':''}"`)
  }
  const zeros = new Uint8Array(32);
  assertEq(toHex(zeros), '0'.repeat(64), 'toHex preserves leading zeros');
}

console.log('\n── 9: Base64 encode/decode round-trip ──');
{
  const inputs = [new Uint8Array([]), new Uint8Array([0]), new Uint8Array([255]), new Uint8Array(256).fill(0xab)];
  for (const bytes of inputs) {
    const b64 = toB64(bytes);
    const decoded = fromB64(b64);
    assertEq(decoded, bytes, `base64 round-trip ${bytes.length} bytes`);
  }
}

console.log('\n── 10: leToBI / biToLE round-trip ──');
{
  const values = [0n, 1n, 255n, 256n, L - 1n, L, L + 1n, (1n << 256n) - 1n];
  for (const v of values) {
    const le = biToLE(v, 32);
    const back = leToBI(le);
    assert(back === (v & ((1n << 256n) - 1n)), `biToLE/leToBI round-trip ${v < 1000n ? v.toString() : '2^'+v.toString(2).length}`);
  }
}

console.log('\n── 11: isHex64 validation ──');
{
  assert(isHex64('a'.repeat(64)), 'valid lowercase hex64');
  assert(isHex64('A'.repeat(64)), 'valid uppercase hex64');
  assert(isHex64('0123456789abcdef'.repeat(4)), 'valid mixed hex64');
  assert(!isHex64('a'.repeat(63)), 'rejects 63 chars');
  assert(!isHex64('a'.repeat(65)), 'rejects 65 chars');
  assert(!isHex64('g'.repeat(64)), 'rejects non-hex chars');
  assert(!isHex64(''), 'rejects empty');
}

console.log('\n── 12: AES-GCM encrypt/decrypt round-trip ──');
{
  const key = webcrypto.getRandomValues(new Uint8Array(32));
  const messages = ['', 'hello', 'a'.repeat(10000), '🔐 unicode test'];
  for (const msg of messages) {
    const ct = await aesGCMEncrypt(key, msg);
    const pt = await aesGCMDecrypt(key, ct);
    assert(pt === msg, `AES-GCM round-trip "${msg.slice(0,20)}${msg.length>20?'…':''}" (${msg.length} chars)`);
  }
}

console.log('\n── 13: AES-GCM rejects wrong key ──');
{
  const key1 = webcrypto.getRandomValues(new Uint8Array(32));
  const key2 = webcrypto.getRandomValues(new Uint8Array(32));
  const ct = await aesGCMEncrypt(key1, 'secret');
  try { await aesGCMDecrypt(key2, ct); assert(false, 'should reject wrong key'); }
  catch { assert(true, 'rejects wrong key'); }
}

console.log('\n── 14: AES-GCM rejects tampered ciphertext ──');
{
  const key = webcrypto.getRandomValues(new Uint8Array(32));
  const ct = await aesGCMEncrypt(key, 'test');
  const bytes = fromB64(ct);
  bytes[bytes.length - 1] ^= 0xff;
  try { await aesGCMDecrypt(key, toB64(bytes)); assert(false, 'should reject tampered ct'); }
  catch { assert(true, 'rejects tampered ciphertext'); }
}

console.log('\n── 15: AES-GCM unique IVs ──');
{
  const key = webcrypto.getRandomValues(new Uint8Array(32));
  const ct1 = await aesGCMEncrypt(key, 'same');
  const ct2 = await aesGCMEncrypt(key, 'same');
  assert(ct1 !== ct2, 'different IVs produce different ciphertexts');
  const pt1 = await aesGCMDecrypt(key, ct1);
  const pt2 = await aesGCMDecrypt(key, ct2);
  assert(pt1 === pt2 && pt1 === 'same', 'both decrypt to same plaintext');
}

console.log('\n── 16: HKDF-SHA256 RFC 5869 test vectors ──');
{
  const tc1_ikm = fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
  const tc1_salt = fromHex('000102030405060708090a0b0c');
  const tc1_info = fromHex('f0f1f2f3f4f5f6f7f8f9');
  const k = await SC.importKey('raw', tc1_ikm, {name:'HKDF'}, false, ['deriveBits']);
  const okm = await SC.deriveBits({name:'HKDF',hash:'SHA-256',salt:tc1_salt,info:tc1_info}, k, 42*8);
  assertEq(toHex(okm), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865', 'HKDF TC1');

  const tc2_ikm = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f');
  const tc2_salt = fromHex('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf');
  const tc2_info = fromHex('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
  const k2 = await SC.importKey('raw', tc2_ikm, {name:'HKDF'}, false, ['deriveBits']);
  const okm2 = await SC.deriveBits({name:'HKDF',hash:'SHA-256',salt:tc2_salt,info:tc2_info}, k2, 82*8);
  assertEq(toHex(okm2), 'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87', 'HKDF TC2');
}

console.log('\n── 17: PBKDF2 known vectors ──');
{
  const k = await SC.importKey('raw', ENC.encode('password'), {name:'PBKDF2'}, false, ['deriveBits']);
  const out = await SC.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:ENC.encode('salt'),iterations:1}, k, 256);
  assertEq(toHex(out), '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b', 'PBKDF2 SHA256 iter=1');

  const k2 = await SC.importKey('raw', ENC.encode('password'), {name:'PBKDF2'}, false, ['deriveBits']);
  const out2 = await SC.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:ENC.encode('salt'),iterations:2}, k2, 256);
  assertEq(toHex(out2), 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43', 'PBKDF2 SHA256 iter=2');
}

console.log('\n── 18: SHA hash functions ──');
{
  assertEq(toHex(await SC.digest('SHA-256', ENC.encode(''))), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'SHA-256("")');
  assertEq(toHex(await SC.digest('SHA-256', ENC.encode('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'SHA-256("abc")');
  assertEq(toHex(await SC.digest('SHA-384', ENC.encode(''))), '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b', 'SHA-384("")');
  assertEq(toHex(await SC.digest('SHA-512', ENC.encode(''))), 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e', 'SHA-512("")');
}

console.log('\n── 19: BLAKE2b hash ──');
{
  const b256 = blake2b(ENC.encode('abc'), {dkLen:32});
  assert(b256.length === 32, 'BLAKE2b-256 output length');
  const b512 = blake2b(ENC.encode('abc'), {dkLen:64});
  assert(b512.length === 64, 'BLAKE2b-512 output length');
  const b1 = blake2b(ENC.encode('test'), {dkLen:32});
  const b2 = blake2b(ENC.encode('test'), {dkLen:32});
  assertEq(b1, b2, 'BLAKE2b deterministic');
  const b3 = blake2b(ENC.encode('test2'), {dkLen:32});
  assert(toHex(b1) !== toHex(b3), 'BLAKE2b different inputs differ');
}

console.log('\n── 20: Base32 RFC 4648 test vectors ──');
{
  const vectors = [['f','MY'],['fo','MZXQ'],['foo','MZXW6'],['foob','MZXW6YQ'],['fooba','MZXW6YTB'],['foobar','MZXW6YTBOI']];
  for (const [input, expected] of vectors) {
    assertEq(base32Encode(ENC.encode(input)), expected, `base32Encode("${input}")`);
    assertEq(DEC.decode(base32Decode(expected)), input, `base32Decode("${expected}")`);
  }
  const padded = base32Decode('MZXW6YTB====');
  assertEq(DEC.decode(padded), 'fooba', 'base32Decode handles padding');
}

console.log('\n── 21: TOTP/HOTP RFC 6238 test vectors ──');
{
  const seed = ENC.encode('12345678901234567890');
  const vectors = [[59,'94287082'],[1111111109,'07081804'],[1111111111,'14050471'],[1234567890,'89005924'],[2000000000,'69279037']];
  for (const [time, expected] of vectors) {
    const t = Math.floor(time / 30);
    const code = await hmacOTP(seed, t, 8, 'SHA-1');
    assertEq(code, expected, `TOTP SHA-1 t=${time}`);
  }
}

console.log('\n── 22: HOTP counter increment ──');
{
  const secret = ENC.encode('12345678901234567890');
  const codes = [];
  for (let c = 0; c < 5; c++) codes.push(await hmacOTP(secret, c, 6, 'SHA-1'));
  const unique = new Set(codes);
  assert(unique.size === codes.length, 'HOTP sequential counters produce unique codes');
}

console.log('\n── 23: deriveSeedBytes modes ──');
{
  const hex = 'a'.repeat(64);
  const raw = await deriveSeedBytes(hex, 'raw');
  assertEq(toHex(raw), hex, 'deriveSeedBytes raw mode');

  const autoRaw = await deriveSeedBytes(hex, 'pbkdf2');
  assertEq(toHex(autoRaw), hex, 'deriveSeedBytes auto-detects hex64');

  const bip39 = await deriveSeedBytes('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', 'bip39', '');
  assert(bip39.length === 32, 'deriveSeedBytes bip39 produces 32 bytes');

  const pbkdf2_1 = await deriveSeedBytes('test passphrase', 'pbkdf2', 'encalc');
  const pbkdf2_2 = await deriveSeedBytes('test passphrase', 'pbkdf2', 'encalc');
  assertEq(pbkdf2_1, pbkdf2_2, 'deriveSeedBytes pbkdf2 deterministic');

  const pbkdf2_diff = await deriveSeedBytes('test passphrase', 'pbkdf2', 'other');
  assert(toHex(pbkdf2_1) !== toHex(pbkdf2_diff), 'deriveSeedBytes different salt → different output');
}

console.log('\n── 24: autoDetect format detection ──');
{
  assertEq(autoDetect('aabb'), 'hex', 'detects hex');
  assertEq(autoDetect('aa bb cc'), 'hex', 'detects spaced hex');
  assertEq(autoDetect('-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----'), 'pem', 'detects PEM');
  assertEq(autoDetect('SGVsbG8='), 'base64', 'detects base64');
  assertEq(autoDetect('hello world!'), 'utf8', 'detects utf8');
  assertEq(autoDetect('aab'), 'base64', 'odd-length pure-alphanum → base64');
}

console.log('\n── 25: kpTweak scalar range ──');
{
  const pub = Pt.BASE.multiply(42n).toBytes();
  const names = ['a', 'b', 'test', 'very long name '.repeat(20), '\x00\x01\x02'];
  for (const name of names) {
    const tw = kpTweak(pub, name);
    assert(tw.scalar >= 0n, `tweak scalar non-negative for "${name.slice(0,10)}"`);
    assert(tw.scalar < (1n << 256n), `tweak scalar < 2^256 for "${name.slice(0,10)}"`);
    assert(tw.pub.length === 32, `tweak pub is 32 bytes for "${name.slice(0,10)}"`);
  }
}

console.log('\n── 26: kpSign with binary message ──');
{
  const scalar = leToBI(fromHex('deadbeef'.repeat(8))) % L;
  const pub = Pt.BASE.multiply(scalar).toBytes();
  const binMsg = new Uint8Array([0, 1, 2, 255, 254, 253]);
  const sig = await kpSign(scalar, binMsg);
  assert(sig.length === 64, 'binary msg signature is 64 bytes');
  assert(kpVerify(pub, binMsg, sig), 'binary msg signature verifies');
}

console.log('\n── 27: kpVerify edge cases ──');
{
  const scalar = leToBI(fromHex('cafe'.repeat(16))) % L;
  const pub = Pt.BASE.multiply(scalar).toBytes();
  const sig = await kpSign(scalar, 'test');
  assert(!kpVerify(pub, 'test', new Uint8Array(63)), 'rejects 63-byte signature');
  assert(!kpVerify(pub, 'test', new Uint8Array(65)), 'rejects 65-byte signature');
  assert(!kpVerify(new Uint8Array(32), 'test', sig), 'rejects zeroed pub key');
  const wrongPub = Pt.BASE.multiply(999n).toBytes();
  assert(!kpVerify(wrongPub, 'test', sig), 'rejects wrong pub key');
}

console.log('\n── 28: Key derivation path consistency ──');
{
  const seed = fromHex('0102030405060708091011121314151617181920212223242526272829303132');
  const scalar = leToBI(seed) % L;
  const pub = Pt.BASE.multiply(scalar).toBytes();

  const d1 = kpFullDerive(pub, scalar, 'a');
  const d2 = kpFullDerive(d1.pub, d1.scalar, 'b');

  const d_ab = (() => {
    let cp = pub, cs = scalar;
    for (const seg of ['a','b']) { const d = kpFullDerive(cp, cs, seg); cp=d.pub; cs=d.scalar; }
    return { pub: cp, scalar: cs };
  })();

  assertEq(d2.pub, d_ab.pub, 'step-by-step == loop derivation pub');
  assert(d2.scalar === d_ab.scalar, 'step-by-step == loop derivation scalar');

  const d_ba = kpFullDerive(kpFullDerive(pub, scalar, 'b').pub, kpFullDerive(pub, scalar, 'b').scalar, 'a');
  assert(toHex(d2.pub) !== toHex(d_ba.pub), 'a/b != b/a (path order matters)');
}

console.log('\n── 29: AES-GCM key sizes ──');
{
  for (const size of [16, 32]) {
    const key = webcrypto.getRandomValues(new Uint8Array(size));
    const ct = await aesGCMEncrypt(key, 'test');
    const pt = await aesGCMDecrypt(key, ct);
    assert(pt === 'test', `AES-GCM with ${size*8}-bit key`);
  }
  try {
    const badKey = webcrypto.getRandomValues(new Uint8Array(15));
    await aesGCMEncrypt(badKey, 'test');
    assert(false, 'should reject 15-byte key');
  } catch { assert(true, 'rejects invalid AES key size'); }
}

console.log('\n── 30: PBKDF2 password-based AES round-trip ──');
{
  async function pbkdf2Key(pass, salt) {
    const b = await SC.importKey('raw', ENC.encode(pass), {name:'PBKDF2'}, false, ['deriveKey']);
    return SC.deriveKey({name:'PBKDF2',salt:ENC.encode(salt),hash:'SHA-256',iterations:100000}, b, {name:'AES-GCM',length:256}, true, ['encrypt','decrypt']);
  }
  const salt = toHex(webcrypto.getRandomValues(new Uint8Array(8)));
  const k = await pbkdf2Key('mypassword', salt);
  const raw = new Uint8Array(await SC.exportKey('raw', k));
  const ct = await aesGCMEncrypt(raw, 'secret data');
  const pt = await aesGCMDecrypt(raw, ct);
  assert(pt === 'secret data', 'PBKDF2 → AES-GCM round-trip');

  const k2 = await pbkdf2Key('wrongpassword', salt);
  const raw2 = new Uint8Array(await SC.exportKey('raw', k2));
  try { await aesGCMDecrypt(raw2, ct); assert(false, 'wrong password should fail'); }
  catch { assert(true, 'PBKDF2 wrong password rejects'); }
}

console.log('\n── 31: ECDH key exchange ──');
{
  const alice = await SC.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const bob = await SC.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const shared_ab = await SC.deriveBits({name:'ECDH',public:bob.publicKey},alice.privateKey,256);
  const shared_ba = await SC.deriveBits({name:'ECDH',public:alice.publicKey},bob.privateKey,256);
  assertEq(shared_ab, shared_ba, 'ECDH shared secret matches both sides');
  const eve = await SC.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const shared_ae = await SC.deriveBits({name:'ECDH',public:eve.publicKey},alice.privateKey,256);
  assert(toHex(shared_ab) !== toHex(shared_ae), 'ECDH different peer → different secret');
}

console.log('\n── 32: Tree-path encryption round-trip ──');
{
  const seedHex = 'deadbeefcafebabe0102030405060708090a0b0c0d0e0f101112131415161718';
  const seedBytes = fromHex(seedHex);
  let scalar = leToBI(seedBytes) % L, pub = Pt.BASE.multiply(scalar).toBytes();
  for (const seg of ['app','encryption']) { const d = kpFullDerive(pub, scalar, seg); pub=d.pub; scalar=d.scalar; }
  const keyBytes = pub.slice(0, 32);
  const ct = await aesGCMEncrypt(keyBytes, 'tree-encrypted');
  const pt = await aesGCMDecrypt(keyBytes, ct);
  assert(pt === 'tree-encrypted', 'tree-path derived key encrypts/decrypts');
}

console.log(`\n${'═'.repeat(52)}`);
console.log(`  ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
