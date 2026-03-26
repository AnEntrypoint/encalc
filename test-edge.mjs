import { ed25519 } from '/tmp/node_modules/@noble/curves/ed25519.js';
import { blake2b } from '/tmp/node_modules/@noble/hashes/blake2.js';
import { sha512 } from '/tmp/node_modules/@noble/hashes/sha2.js';
import { webcrypto } from 'node:crypto';

const SC = webcrypto.subtle;
const ENC = new TextEncoder();
const DEC = new TextDecoder();
const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('');
const fromHex = h => { const s = h.replace(/\s/g,''); if (!s) return new Uint8Array(0); return new Uint8Array(s.match(/.{2}/g).map(b=>parseInt(b,16))); };
const toB64 = b => Buffer.from(b).toString('base64');
const fromB64 = s => Uint8Array.from(Buffer.from(s, 'base64'));
const isHex64 = s => /^[0-9a-f]{64}$/i.test(s.trim());
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
async function kpSign(scalar, msg) {
  const nb = typeof msg==='string' ? ENC.encode(msg) : msg;
  const pubBytes = Pt.BASE.multiply(scalar).toBytes();
  const scalarBytes = biToLE(scalar, 32);
  const r = leToBI(blake2b(new Uint8Array([...scalarBytes, ...nb]), {dkLen:64})) % L;
  const R = Pt.BASE.multiply(r).toBytes();
  const kBytes = new Uint8Array(await SC.digest('SHA-512', new Uint8Array([...R, ...pubBytes, ...nb])));
  const k = leToBI(kBytes) % L;
  return new Uint8Array([...R, ...biToLE((r + k * scalar) % L, 32)]);
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
async function hmacOTP(secret, counter, digits, alg) {
  const key = await SC.importKey('raw', secret, { name: 'HMAC', hash: alg }, false, ['sign']);
  const buf = new ArrayBuffer(8); const dv = new DataView(buf);
  dv.setUint32(0, Math.floor(counter / 0x100000000)); dv.setUint32(4, counter >>> 0);
  const hmac = new Uint8Array(await SC.sign('HMAC', key, buf));
  const off = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[off]&0x7f)<<24|(hmac[off+1]<<16)|(hmac[off+2]<<8)|hmac[off+3]) % (10**digits);
  return code.toString().padStart(digits, '0');
}
function base32Decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  s = s.replace(/[=\s-]/g,'').toUpperCase(); let bits = '';
  for (const c of s) { const i = A.indexOf(c); if (i >= 0) bits += i.toString(2).padStart(5, '0'); }
  const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(out);
}
function base32Encode(bytes) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  let out = ''; for (let i = 0; i < bits.length; i += 5) out += A[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
}
function autoDetect(s) {
  if (/^[0-9a-f\s]+$/i.test(s) && s.replace(/\s/g,'').length%2===0) return 'hex';
  if (s.includes('-----BEGIN')) return 'pem';
  if (/^[A-Za-z0-9+/=]+$/.test(s)) return 'base64';
  return 'utf8';
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
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
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

let passed = 0, failed = 0;
function assert(c, l) { if (c) { console.log(`  ✓ ${l}`); passed++; } else { console.error(`  ✗ FAIL: ${l}`); failed++; } }
function assertEq(a, b, l) { const sa=typeof a==='string'?a:toHex(a), sb=typeof b==='string'?b:toHex(b);
  if(sa!==sb) console.error(`    got:      ${sa}\n    expected: ${sb}`); assert(sa===sb, l); }

console.log('\n══ Edge case + integration tests ══\n');

console.log('── 47: fromHex edge cases ──');
{
  assertEq(fromHex(''), new Uint8Array(0), 'fromHex empty → 0 bytes');
  assertEq(fromHex('  '), new Uint8Array(0), 'fromHex whitespace-only → 0 bytes');
  assertEq(fromHex('ab'), fromHex('ab'), 'fromHex single byte');
  assertEq(fromHex('ab cd ef'), fromHex('abcdef'), 'fromHex strips spaces');
  assert(fromHex('abc').length === 1, 'fromHex odd-length truncates');
  assertEq(toHex(fromHex('abc')), 'ab', 'fromHex odd drops last nibble');
  assert(fromHex('zz')[0] === 0, 'fromHex invalid chars → NaN→0');
  assertEq(toHex(fromHex('00ff')), '00ff', 'fromHex preserves leading zero byte');
}

console.log('\n── 48: base32 edge cases ──');
{
  assert(base32Decode('').length === 0, 'base32Decode empty');
  assert(base32Decode('!!!@@@').length === 0, 'base32Decode invalid chars → empty');
  assertEq(base32Decode('mzxw6ytboi'), base32Decode('MZXW6YTBOI'), 'base32Decode case-insensitive');
  assertEq(base32Decode('MZ-XW-6Y'), base32Decode('MZXW6Y'), 'base32Decode strips dashes');
  assertEq(base32Decode('MZXW6==='), base32Decode('MZXW6'), 'base32Decode strips padding');
  const rnd = webcrypto.getRandomValues(new Uint8Array(20));
  assertEq(base32Decode(base32Encode(rnd)), rnd, 'base32 random 20B round-trip');
  const rnd2 = webcrypto.getRandomValues(new Uint8Array(1));
  assertEq(base32Decode(base32Encode(rnd2)), rnd2, 'base32 1-byte round-trip');
  const rnd3 = webcrypto.getRandomValues(new Uint8Array(100));
  assertEq(base32Decode(base32Encode(rnd3)), rnd3, 'base32 100-byte round-trip');
}

console.log('\n── 49: autoDetect edge cases ──');
{
  assertEq(autoDetect(''), 'utf8', 'autoDetect empty → utf8');
  assertEq(autoDetect('00'), 'hex', 'autoDetect "00" → hex');
  assertEq(autoDetect('aabb'), 'hex', 'autoDetect even hex → hex');
  assertEq(autoDetect('0'), 'base64', 'autoDetect single digit → base64');
  assertEq(autoDetect('GG'), 'base64', 'autoDetect non-hex alpha → base64');
  assertEq(autoDetect('Hello!'), 'utf8', 'autoDetect with punctuation → utf8');
  assertEq(autoDetect('ab cd'), 'hex', 'autoDetect spaced hex → hex');
  assertEq(autoDetect('-----BEGIN X-----\ndata'), 'pem', 'autoDetect PEM');
  assertEq(autoDetect('日本語'), 'utf8', 'autoDetect CJK → utf8');
}

console.log('\n── 50: esc edge cases ──');
{
  assertEq(esc(''), '', 'esc empty');
  assertEq(esc('🔐'), '🔐', 'esc emoji passthrough');
  assertEq(esc('日本語'), '日本語', 'esc CJK passthrough');
  assertEq(esc('<div>🔐</div>'), '&lt;div&gt;🔐&lt;/div&gt;', 'esc mixed HTML+emoji');
  assertEq(esc('a&b<c>d"e\'f'), 'a&amp;b&lt;c&gt;d&quot;e&#39;f', 'esc all 5 chars at once');
  assertEq(esc(undefined), 'undefined', 'esc undefined coercion');
  assertEq(esc(0), '0', 'esc falsy number');
}

console.log('\n── 51: parseOTPAuth edge cases ──');
{
  const p1 = parseOTPAuth('otpauth://totp/X?secret=ABC&algorithm=SHA512');
  assertEq(p1.alg, 'SHA-512', 'OTP SHA-512 alg');
  const p2 = parseOTPAuth('otpauth://totp/X?issuer=Y');
  assertEq(p2.secret, '', 'OTP missing secret → empty');
  assertEq(p2.issuer, 'Y', 'OTP issuer present');
  const p3 = parseOTPAuth('otpauth://totp/X?secret=ABC&foo=bar&image=http://x');
  assertEq(p3.secret, 'ABC', 'OTP ignores extra params');
  const p4 = parseOTPAuth('otpauth://hotp/X?secret=ABC&counter=0');
  assertEq(p4.type, 'hotp', 'OTP hotp with counter=0');
  assert(p4.counter === 0, 'OTP counter=0');
  assert(parseOTPAuth('http://example.com') !== null, 'non-otpauth URL parses (type=hotp fallback)');
}

console.log('\n── 52: TOTP time-window verification ──');
{
  const secret = ENC.encode('12345678901234567890');
  const period = 30;
  const baseTime = 1000000000;
  const step = Math.floor(baseTime / period);
  async function verifyAt(code, time) {
    for (let off = -1; off <= 1; off++) {
      const t = Math.floor(time / period) + off;
      if (await hmacOTP(secret, t, code.length, 'SHA-1') === code) return { valid: true, window: off };
    }
    return { valid: false };
  }
  const cur = await hmacOTP(secret, step, 6, 'SHA-1');
  const prev = await hmacOTP(secret, step - 1, 6, 'SHA-1');
  const next = await hmacOTP(secret, step + 1, 6, 'SHA-1');
  const old = await hmacOTP(secret, step - 2, 6, 'SHA-1');
  const future = await hmacOTP(secret, step + 2, 6, 'SHA-1');
  const r1 = await verifyAt(cur, baseTime);
  assert(r1.valid && r1.window === 0, 'TOTP current period accepted (w=0)');
  const r2 = await verifyAt(prev, baseTime);
  assert(r2.valid && r2.window === -1, 'TOTP previous period accepted (w=-1)');
  const r3 = await verifyAt(next, baseTime);
  assert(r3.valid && r3.window === 1, 'TOTP next period accepted (w=+1)');
  assert(!(await verifyAt(old, baseTime)).valid, 'TOTP 2 periods ago rejected');
  assert(!(await verifyAt(future, baseTime)).valid, 'TOTP 2 periods ahead rejected');
  assert(!(await verifyAt('000000', baseTime)).valid, 'TOTP wrong code rejected');
}

console.log('\n── 53: Empty message signing ──');
{
  const scalar = leToBI(fromHex('deadbeef'.repeat(8))) % L;
  const pub = Pt.BASE.multiply(scalar).toBytes();
  const sigStr = await kpSign(scalar, '');
  assert(sigStr.length === 64, 'kpSign empty string → 64B');
  assert(kpVerify(pub, '', sigStr), 'kpVerify empty string accepts');
  const sigBytes = await kpSign(scalar, new Uint8Array(0));
  assert(sigBytes.length === 64, 'kpSign empty Uint8Array → 64B');
  assert(kpVerify(pub, new Uint8Array(0), sigBytes), 'kpVerify empty bytes accepts');
  assertEq(sigStr, sigBytes, 'empty string === empty bytes signature');
  const sigX = await kpSign(scalar, 'x');
  assert(toHex(sigStr) !== toHex(sigX), 'empty differs from non-empty');
}

console.log('\n── 54: Full integration chain ──');
{
  const seedBytes = await deriveSeedBytes('my secret passphrase', 'pbkdf2', 'encalc');
  let scalar = leToBI(seedBytes) % L, pub = Pt.BASE.multiply(scalar).toBytes();
  for (const seg of ['app', 'signing']) { const d = kpFullDerive(pub, scalar, seg); pub=d.pub; scalar=d.scalar; }
  const msg = 'important document v1';
  const sig = await kpSign(scalar, msg);
  assert(kpVerify(pub, msg, sig), 'chain: sign→verify ok');
  assert(!kpVerify(pub, msg+'x', sig), 'chain: tampered msg rejects');
  const encKey = pub.slice(0, 32);
  const ct = await aesGCMEncrypt(encKey, 'confidential');
  assertEq(await aesGCMDecrypt(encKey, ct), 'confidential', 'chain: encrypt→decrypt ok');
  const seed2 = await deriveSeedBytes('wrong passphrase', 'pbkdf2', 'encalc');
  let s2 = leToBI(seed2) % L, p2 = Pt.BASE.multiply(s2).toBytes();
  for (const seg of ['app', 'signing']) { const d = kpFullDerive(p2, s2, seg); p2=d.pub; s2=d.scalar; }
  assert(!kpVerify(p2, msg, sig), 'chain: wrong passphrase → sig rejects');
  try { await aesGCMDecrypt(p2.slice(0,32), ct); assert(false, 'wrong key'); }
  catch { assert(true, 'chain: wrong passphrase → decrypt rejects'); }
  const sigPath = await kpSign(scalar, msg);
  const pubFromScalar = Pt.BASE.multiply(scalar).toBytes();
  assertEq(pub, pubFromScalar, 'chain: derived pub matches scalar→pub');
}

console.log('\n── 55: deriveSeedBytes edge cases ──');
{
  const ws = await deriveSeedBytes('  ' + 'a'.repeat(64) + '  ', 'raw');
  assertEq(toHex(ws), 'a'.repeat(64), 'deriveSeedBytes trims whitespace');
  const empty = await deriveSeedBytes('passphrase', 'pbkdf2', '');
  assert(empty.length === 32, 'deriveSeedBytes empty salt → 32 bytes');
  const salt1 = await deriveSeedBytes('passphrase', 'pbkdf2', 'a');
  const salt2 = await deriveSeedBytes('passphrase', 'pbkdf2', 'b');
  assert(toHex(salt1) !== toHex(salt2), 'deriveSeedBytes different salts differ');
}

console.log('\n── 56: biToLE / leToBI edge cases ──');
{
  assert(leToBI(new Uint8Array(0)) === 0n, 'leToBI empty → 0n');
  assert(leToBI(new Uint8Array([1])) === 1n, 'leToBI [1] → 1n');
  assert(leToBI(new Uint8Array([0, 1])) === 256n, 'leToBI [0,1] → 256n');
  assertEq(biToLE(0n, 4), new Uint8Array(4), 'biToLE 0n → zeros');
  assertEq(biToLE(255n, 1), new Uint8Array([255]), 'biToLE 255n,1 → [ff]');
  const maxU256 = (1n << 256n) - 1n;
  assertEq(biToLE(maxU256, 32), new Uint8Array(32).fill(255), 'biToLE max u256');
  const rt = 123456789012345678901234567890n;
  assert(leToBI(biToLE(rt, 32)) === rt, 'biToLE/leToBI large round-trip');
}

console.log(`\n${'═'.repeat(52)}`);
console.log(`  ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
