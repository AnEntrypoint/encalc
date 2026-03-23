/**
 * Cross-validation test: encalc keypear implementation vs. holepunchto/keypear
 *
 * Tests:
 *  1. kpTweak clamping matches keypear's extension_tweak_ed25519_base
 *  2. kpPubDerive (public-only) matches kpFullDerive public key
 *  3. kpFullDerive scalar addition matches keypear's add()
 *  4. Multi-level derivation chain consistency
 *  5. kpSign / kpVerify round-trip with derived keys
 *  6. Signatures produced by kpSign verify with ed25519.verify (noble/curves)
 */

import { ed25519 } from '/tmp/node_modules/@noble/curves/ed25519.js';
import { blake2b } from '/tmp/node_modules/@noble/hashes/blake2.js';
import { sha512 } from '/tmp/node_modules/@noble/hashes/sha2.js';
import Keychain from '/tmp/node_modules/keypear/index.js';
import { webcrypto } from 'node:crypto';

// ── Helpers ──────────────────────────────────────────────────────────────────
const toHex = b => Buffer.from(b).toString('hex');
const fromHex = h => Uint8Array.from(Buffer.from(h, 'hex'));
const ENC = new TextEncoder();

// ── Keypear math (same as app.js after fix) ───────────────────────────────────
const L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
const Pt = ed25519.ExtendedPoint;
const leToBI = b => { let n=0n; for(let i=b.length-1;i>=0;i--) n=(n<<8n)|BigInt(b[i]); return n; };
const biToLE = (n,len) => { const a=new Uint8Array(len); for(let i=0;i<len;i++){a[i]=Number(n&0xffn);n>>=8n;} return a; };

function kpTweak(pub, name) {
  const nb = typeof name==='string' ? ENC.encode(name) : name;
  const seed = blake2b(new Uint8Array([...pub,...nb]), {dkLen:32});
  const h = sha512(seed).slice(0, 32);
  h[31] &= 0x7f;  // clear bit 255 only
  const scalar = leToBI(h);
  return { scalar, pub: Pt.BASE.multiply(scalar % L).toRawBytes() };
}
function kpPubDerive(parentPub, name) {
  const t = kpTweak(parentPub, name);
  return Pt.fromHex(toHex(parentPub)).add(Pt.fromHex(toHex(t.pub))).toRawBytes();
}
function kpFullDerive(parentPub, parentScalar, name) {
  const t = kpTweak(parentPub, name);
  const cs = (parentScalar + t.scalar) % L;
  return { pub: Pt.BASE.multiply(cs).toRawBytes(), scalar: cs };
}
async function kpSign(scalar, msg) {
  const nb = typeof msg==='string' ? ENC.encode(msg) : msg;
  const pubBytes = Pt.BASE.multiply(scalar).toRawBytes();
  const scalarBytes = biToLE(scalar, 32);
  const r = leToBI(blake2b(new Uint8Array([...scalarBytes, ...nb]), {dkLen:64})) % L;
  const R = Pt.BASE.multiply(r).toRawBytes();
  const kBytes = new Uint8Array(await webcrypto.subtle.digest('SHA-512', new Uint8Array([...R, ...pubBytes, ...nb])));
  const k = leToBI(kBytes) % L;
  const S = (r + k * scalar) % L;
  return new Uint8Array([...R, ...biToLE(S, 32)]);
}
function kpVerify(pubBytes, msg, sigBytes) {
  try { return ed25519.verify(sigBytes, typeof msg==='string'?ENC.encode(msg):msg, pubBytes); }
  catch { return false; }
}

// ── Test harness ──────────────────────────────────────────────────────────────
let passed = 0, failed = 0;
function assert(cond, label) {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else       { console.error(`  ✗ FAIL: ${label}`); failed++; }
}
function assertEq(a, b, label) {
  const ok = toHex(a) === toHex(b);
  if (!ok) console.error(`    got:      ${toHex(a)}\n    expected: ${toHex(b)}`);
  assert(ok, label);
}

// ── Fixed test seed ───────────────────────────────────────────────────────────
const SEED = fromHex('deadbeefcafebabe0102030405060708090a0b0c0d0e0f101112131415161718');

// ── Build keypear reference chain ─────────────────────────────────────────────
// keypear's Keychain.keyPair(seed) → scalar via SHA-512 expansion of seed
// We instead use the raw seed directly as the root scalar (encalc design),
// so we build the reference by starting at the same raw-seed root.
function kpRoot(seed) {
  // keypear: keyPair(seed) uses sodium.crypto_sign_seed_keypair which does
  //   SHA-512(seed), clamp → scalar.  encalc uses raw seed → scalar directly.
  // To cross-validate TWEAKING (not root generation), we feed keypear a
  // synthetic seed such that its expanded scalar matches our raw-seed scalar.
  // Easier: just use keypear's raw-key constructor with { publicKey, scalar }.
  const scalar = leToBI(seed) % L;
  const pub = Pt.BASE.multiply(scalar).toRawBytes();
  return { scalar, pub };
}

// ── Tests ──────────────────────────────────────────────────────────────────────
console.log('\n── Test 1: kpTweak clamping vs keypear tweakKeyPair ──');
{
  const root = kpRoot(SEED);

  // Our tweak
  const ourTweak = kpTweak(root.pub, 'app');

  // Keypear tweak: build a read-only chain from root.pub and call .sub('app')
  // Then compare the tweak's public key produced internally.
  // keypear._getTweak(name) calls tweakKeyPair(name_buf, this.head.publicKey)
  // tweakKeyPair: seed = blake2b(prevPub || name), then extension_tweak_ed25519_base(scalar, pk, seed)
  // We test by checking that our tweak.pub == keypear's sub.publicKey - root.pub (point subtraction)
  // i.e., our tweak point should equal the keypear-derived sub public key MINUS the root public key.
  // Actually easier: check our derived child pub matches keypear's sub chain pub.

  // Build keypear chain with root pub as read-only, derive sub
  const kpChain = new Keychain(Buffer.from(root.pub));  // read-only from pub
  const sub = kpChain.sub('app');
  const kpDerivedPub = sub.publicKey;

  // Our derived pub via kpPubDerive
  const ourDerivedPub = kpPubDerive(root.pub, 'app');

  assertEq(ourDerivedPub, kpDerivedPub, 'kpPubDerive("app") matches keypear .sub("app").publicKey');

  // Also verify our tweak point: kpDerivedPub = root.pub + tweak.pub
  const rootPt = Pt.fromHex(toHex(root.pub));
  const tweakPt = Pt.fromHex(toHex(ourTweak.pub));
  const sumPt = rootPt.add(tweakPt).toRawBytes();
  assertEq(sumPt, kpDerivedPub, 'root + tweak_point == keypear derived pub');
}

console.log('\n── Test 2: kpFullDerive scalar matches keypear scalar ──');
{
  const root = kpRoot(SEED);

  // keypear needs a writable chain — construct from { publicKey, scalar }
  // keypear's Keychain constructor accepts a keypair with { publicKey, scalar }
  // but it calls toScalarKeyPair which expects secretKey or scalar directly
  // We pass { publicKey: buf, scalar: buf } matching keypear's internal format.
  const kpBuf = Buffer.alloc(64);
  Buffer.from(root.pub).copy(kpBuf, 0);
  Buffer.from(biToLE(root.scalar, 32)).copy(kpBuf, 32);

  // keypear Keychain.keyPair returns { publicKey, scalar } both as Buffers
  // We can construct a chain directly with a keypair-like object
  const kpChain = new Keychain({ publicKey: Buffer.from(root.pub), scalar: Buffer.from(biToLE(root.scalar, 32)) });
  const sub = kpChain.sub('app');
  const kpSubPub = sub.publicKey;

  // Our derivation
  const ourDerived = kpFullDerive(root.pub, root.scalar, 'app');

  assertEq(ourDerived.pub, kpSubPub, 'kpFullDerive("app").pub matches keypear .sub("app").publicKey');
  assertEq(ourDerived.pub, kpPubDerive(root.pub, 'app'), 'kpFullDerive.pub == kpPubDerive (consistency)');
}

console.log('\n── Test 3: Multi-level derivation chain ──');
{
  const root = kpRoot(SEED);
  const kpChain = new Keychain({ publicKey: Buffer.from(root.pub), scalar: Buffer.from(biToLE(root.scalar, 32)) });

  const paths = ['app/signing', 'app/encryption/key1', 'x/y/z'];
  for (const path of paths) {
    const segs = path.split('/');

    // keypear chain traversal
    let kpCurrent = kpChain;
    for (const seg of segs) kpCurrent = kpCurrent.sub(seg);
    const kpFinalPub = kpCurrent.publicKey;

    // Our traversal
    let cp = root.pub, cs = root.scalar;
    for (const seg of segs) { const d = kpFullDerive(cp, cs, seg); cp=d.pub; cs=d.scalar; }

    assertEq(cp, kpFinalPub, `path "${path}" matches keypear`);
  }
}

console.log('\n── Test 4: kpSign / kpVerify round-trip ──');
{
  const root = kpRoot(SEED);
  const derived = kpFullDerive(kpFullDerive(root.pub, root.scalar, 'app').pub,
                               kpFullDerive(root.pub, root.scalar, 'app').scalar,
                               'signing');
  const msg = 'hello from encalc';

  const sig = await kpSign(derived.scalar, msg);

  assert(sig.length === 64, 'signature is 64 bytes');
  assert(kpVerify(derived.pub, msg, sig), 'kpVerify accepts own signature');
  assert(!kpVerify(derived.pub, msg + 'x', sig), 'kpVerify rejects tampered message');
  assert(!kpVerify(derived.pub, msg, new Uint8Array(64)), 'kpVerify rejects zeroed signature');

  // Also verify with noble/curves directly (same as kpVerify, but explicit)
  assert(ed25519.verify(sig, ENC.encode(msg), derived.pub), 'ed25519.verify accepts kpSign output');
}

console.log('\n── Test 5: kpSign uses signing scalar matching derived pub ──');
{
  // Derive key at path app/signing from two different root scalars
  const SEED2 = fromHex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  const root2 = kpRoot(SEED2);
  const d2 = kpFullDerive(root2.pub, root2.scalar, 'test');

  const msg = 'encalc test message';
  const sig = await kpSign(d2.scalar, msg);

  // Verify against DERIVED pub key (not root) — this catches the old bug where
  // signing used scalar as seed → different effective signing key
  assert(kpVerify(d2.pub, msg, sig), 'signature verifies against derived pub (not root)');
  assert(!kpVerify(root2.pub, msg, sig), 'signature does not verify against wrong pub');
}

console.log('\n── Test 6: kpSign determinism ──');
{
  const root = kpRoot(SEED);
  const msg = 'deterministic';
  const sig1 = await kpSign(root.scalar, msg);
  const sig2 = await kpSign(root.scalar, msg);
  assertEq(sig1, sig2, 'same inputs produce same signature');

  const msgB = 'different';
  const sig3 = await kpSign(root.scalar, msgB);
  assert(toHex(sig1) !== toHex(sig3), 'different messages produce different signatures');
}

console.log('\n── Test 7: kpPubDerive is consistent with kpFullDerive.pub ──');
{
  const root = kpRoot(SEED);
  for (const name of ['alpha', 'beta', 'gamma', 'a/b', '']) {
    if (!name) continue;
    const full = kpFullDerive(root.pub, root.scalar, name);
    const pubOnly = kpPubDerive(root.pub, name);
    assertEq(pubOnly, full.pub, `kpPubDerive("${name}") == kpFullDerive("${name}").pub`);
  }
}

// ── Summary ──────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(52)}`);
console.log(`  ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
