const C = crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

function show(id) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  const idx = ['keygen','encrypt','mnemonic','keypair','derive'].indexOf(id);
  document.querySelectorAll('.tab')[idx].classList.add('active');
}

function outBox(id, content, label) {
  const d = document.getElementById(id);
  d.innerHTML = '';
  if (Array.isArray(content)) {
    content.forEach(([lbl, val]) => {
      const b = document.createElement('div');
      b.className = 'section';
      b.innerHTML = `<label>${lbl}</label><div class="out">${val}<button class="sec cp" onclick="cp(this,'${val}')">copy</button></div>`;
      d.appendChild(b);
    });
  } else {
    d.innerHTML = `<div class="out">${content}</div>`;
  }
}

function errBox(id, msg) {
  document.getElementById(id).innerHTML = `<div class="err">${msg}</div>`;
}

function cp(btn, val) {
  navigator.clipboard.writeText(val).then(() => { btn.textContent = 'copied!'; setTimeout(() => btn.textContent = 'copy', 1500); });
}

function toHex(buf) { return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join(''); }
function fromHex(h) { return new Uint8Array(h.match(/.{2}/g).map(b => parseInt(b,16))); }

function toPem(type, buf) {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
  return `-----BEGIN ${type}-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END ${type}-----`;
}

async function genKey() {
  const alg = document.getElementById('kg-alg').value;
  try {
    let rows = [];
    if (alg.startsWith('AES')) {
      const len = alg === 'AES-256' ? 256 : 128;
      const k = await C.generateKey({name:'AES-GCM',length:len},true,['encrypt','decrypt']);
      const raw = await C.exportKey('raw', k);
      rows = [['AES Key (hex)', toHex(raw)]];
    } else if (alg.startsWith('RSA')) {
      const len = alg === 'RSA-4096' ? 4096 : 2048;
      const k = await C.generateKey({name:'RSA-OAEP',modulusLength:len,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
      const pub = await C.exportKey('spki', k.publicKey);
      const priv = await C.exportKey('pkcs8', k.privateKey);
      rows = [['Public Key (PEM)', toPem('PUBLIC KEY', pub)], ['Private Key (PEM)', toPem('PRIVATE KEY', priv)]];
    } else if (alg.startsWith('ECDH')) {
      const curve = alg === 'ECDH-P384' ? 'P-384' : 'P-256';
      const k = await C.generateKey({name:'ECDH',namedCurve:curve},true,['deriveKey','deriveBits']);
      const pub = await C.exportKey('spki', k.publicKey);
      const priv = await C.exportKey('pkcs8', k.privateKey);
      rows = [['Public Key (PEM)', toPem('PUBLIC KEY', pub)], ['Private Key (PEM)', toPem('PRIVATE KEY', priv)]];
    } else {
      const k = await C.generateKey({name:'Ed25519'},true,['sign','verify']);
      const pub = await C.exportKey('spki', k.publicKey);
      const priv = await C.exportKey('pkcs8', k.privateKey);
      rows = [['Public Key (PEM)', toPem('PUBLIC KEY', pub)], ['Private Key (PEM)', toPem('PRIVATE KEY', priv)]];
    }
    outBox('kg-out', rows);
  } catch(e) { errBox('kg-out', e.message); }
}

function updateEncUI() {
  const m = document.getElementById('enc-mode').value;
  document.getElementById('enc-key-label').textContent = m === 'aes-pass' ? 'Password' : (m === 'aes-key' ? 'AES Key (hex)' : 'Public Key PEM (encrypt) / Private Key PEM (decrypt)');
}

async function aesKeyFromPass(pass, salt) {
  const base = await C.importKey('raw', enc.encode(pass), {name:'PBKDF2'}, false, ['deriveKey']);
  return C.deriveKey({name:'PBKDF2',salt,hash:'SHA-256',iterations:100000}, base, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
}

async function doEncrypt() {
  const mode = document.getElementById('enc-mode').value;
  const keyVal = document.getElementById('enc-key').value;
  const plain = document.getElementById('enc-input').value;
  if (!plain || !keyVal) return errBox('enc-out', 'Input and key/password required');
  try {
    let result;
    if (mode === 'aes-pass') {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const k = await aesKeyFromPass(keyVal, salt);
      const ct = await C.encrypt({name:'AES-GCM',iv}, k, enc.encode(plain));
      const out = new Uint8Array(salt.length + iv.length + ct.byteLength);
      out.set(salt,0); out.set(iv,16); out.set(new Uint8Array(ct),28);
      result = btoa(String.fromCharCode(...out));
    } else if (mode === 'aes-key') {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const k = await C.importKey('raw', fromHex(keyVal.replace(/\s/g,'')), {name:'AES-GCM'}, false, ['encrypt']);
      const ct = await C.encrypt({name:'AES-GCM',iv}, k, enc.encode(plain));
      const out = new Uint8Array(12 + ct.byteLength);
      out.set(iv,0); out.set(new Uint8Array(ct),12);
      result = btoa(String.fromCharCode(...out));
    } else {
      const pem = keyVal.replace(/-----[^-]+-----|\s/g,'');
      const der = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
      const k = await C.importKey('spki', der, {name:'RSA-OAEP',hash:'SHA-256'}, false, ['encrypt']);
      const ct = await C.encrypt({name:'RSA-OAEP'}, k, enc.encode(plain));
      result = btoa(String.fromCharCode(...new Uint8Array(ct)));
    }
    outBox('enc-out', [['Ciphertext (base64)', result]]);
  } catch(e) { errBox('enc-out', e.message); }
}

async function doDecrypt() {
  const mode = document.getElementById('enc-mode').value;
  const keyVal = document.getElementById('enc-key').value;
  const b64 = document.getElementById('enc-input').value.trim();
  if (!b64 || !keyVal) return errBox('enc-out', 'Input and key/password required');
  try {
    let plain;
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    if (mode === 'aes-pass') {
      const salt = bytes.slice(0,16), iv = bytes.slice(16,28), ct = bytes.slice(28);
      const k = await aesKeyFromPass(keyVal, salt);
      plain = dec.decode(await C.decrypt({name:'AES-GCM',iv}, k, ct));
    } else if (mode === 'aes-key') {
      const iv = bytes.slice(0,12), ct = bytes.slice(12);
      const k = await C.importKey('raw', fromHex(keyVal.replace(/\s/g,'')), {name:'AES-GCM'}, false, ['decrypt']);
      plain = dec.decode(await C.decrypt({name:'AES-GCM',iv}, k, ct));
    } else {
      const pem = keyVal.replace(/-----[^-]+-----|\s/g,'');
      const der = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
      const k = await C.importKey('pkcs8', der, {name:'RSA-OAEP',hash:'SHA-256'}, false, ['decrypt']);
      plain = dec.decode(await C.decrypt({name:'RSA-OAEP'}, k, bytes));
    }
    outBox('enc-out', [['Plaintext', plain]]);
  } catch(e) { errBox('enc-out', e.message); }
}

function genMnemonic() {
  const count = parseInt(document.getElementById('mn-count').value);
  const bytes = crypto.getRandomValues(new Uint8Array(count === 24 ? 32 : 16));
  const bits = Array.from(bytes).map(b => b.toString(2).padStart(8,'0')).join('');
  const words = [];
  for (let i = 0; i < count; i++) words.push(BIP39[parseInt(bits.slice(i*11,(i+1)*11),2) % 2048]);
  document.getElementById('mn-words').value = words.join(' ');
}

async function mnToSeed() {
  const words = document.getElementById('mn-words').value.trim();
  const pass = document.getElementById('mn-pass').value;
  if (!words) return errBox('mn-out', 'Enter a mnemonic');
  try {
    const mnemonic = enc.encode('mnemonic' + pass);
    const base = await C.importKey('raw', enc.encode(words), {name:'PBKDF2'}, false, ['deriveBits']);
    const bits = await C.deriveBits({name:'PBKDF2',hash:'SHA-512',salt:mnemonic,iterations:2048}, base, 512);
    const hex = toHex(bits);
    outBox('mn-out', [['Seed (512-bit hex)', hex]]);
  } catch(e) { errBox('mn-out', e.message); }
}

async function seedToKeypair() {
  const raw = document.getElementById('kp-input').value.trim();
  const alg = document.getElementById('kp-alg').value;
  if (!raw) return errBox('kp-out', 'Enter a passphrase or hex seed');
  try {
    const isHex = /^[0-9a-f]{64}$/i.test(raw);
    const seedBytes = isHex ? fromHex(raw) : await (async () => {
      const base = await C.importKey('raw', enc.encode(raw), {name:'PBKDF2'}, false, ['deriveBits']);
      return new Uint8Array(await C.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:enc.encode('encalc-seed'),iterations:100000}, base, 256));
    })();

    let rows = [['Seed (hex)', toHex(seedBytes)]];
    const hkdfBase = await C.importKey('raw', seedBytes, {name:'HKDF'}, false, ['deriveBits']);
    if (alg === 'Ed25519') {
      const skBits = await C.deriveBits({name:'HKDF',hash:'SHA-256',salt:enc.encode('encalc-ed25519'),info:enc.encode('sk')}, hkdfBase, 256);
      const pair = await C.generateKey({name:'Ed25519'}, true, ['sign','verify']);
      const pub = await C.exportKey('spki', pair.publicKey);
      const priv = await C.exportKey('pkcs8', pair.privateKey);
      rows.push(['Derived SK material (hex)', toHex(skBits)]);
      rows.push(['Public Key (PEM)', toPem('PUBLIC KEY', pub)]);
      rows.push(['Private Key (PEM)', toPem('PRIVATE KEY', priv)]);
      rows.push(['Public Key (hex)', toHex(pub.slice(-32))]);
    } else {
      const dhBits = await C.deriveBits({name:'HKDF',hash:'SHA-256',salt:enc.encode('encalc-ecdh'),info:enc.encode('dh')}, hkdfBase, 256);
      const pair = await C.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveKey','deriveBits']);
      const pub = await C.exportKey('spki', pair.publicKey);
      const priv = await C.exportKey('pkcs8', pair.privateKey);
      rows.push(['Derived DH material (hex)', toHex(dhBits)]);
      rows.push(['Public Key (PEM)', toPem('PUBLIC KEY', pub)]);
      rows.push(['Private Key (PEM)', toPem('PRIVATE KEY', priv)]);
    }
    outBox('kp-out', rows);
  } catch(e) { errBox('kp-out', e.message); }
}

document.getElementById('dv-mech').addEventListener('change', () => {
  document.getElementById('dv-pbkdf2-opts').style.display =
    document.getElementById('dv-mech').value === 'pbkdf2' ? 'flex' : 'none';
});

async function deriveKey() {
  const seedRaw = document.getElementById('dv-seed').value.trim();
  const mech = document.getElementById('dv-mech').value;
  const info = document.getElementById('dv-info').value.trim() || 'default';
  if (!seedRaw) return errBox('dv-out', 'Enter a seed or passphrase');
  try {
    const isHex = /^[0-9a-f]{32,}$/i.test(seedRaw);
    const seedBytes = isHex ? fromHex(seedRaw) : enc.encode(seedRaw);
    let rows = [];

    if (mech === 'hkdf') {
      const base = await C.importKey('raw', seedBytes, {name:'HKDF'}, false, ['deriveBits']);
      const bits = await C.deriveBits({name:'HKDF',hash:'SHA-256',salt:enc.encode('encalc'),info:enc.encode(info)}, base, 256);
      rows = [['Derived Key (HKDF-SHA256)', toHex(bits)],['Info string', info]];
    } else if (mech === 'pbkdf2') {
      const salt = document.getElementById('dv-salt').value || 'encalc';
      const iter = parseInt(document.getElementById('dv-iter').value) || 100000;
      const base = await C.importKey('raw', seedBytes, {name:'PBKDF2'}, false, ['deriveBits']);
      const bits = await C.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:enc.encode(salt),iterations:iter}, base, 256);
      rows = [['Derived Key (PBKDF2-SHA256)', toHex(bits)],['Salt', salt],['Iterations', String(iter)]];
    } else {
      const segments = info.split('/').filter(Boolean);
      let currentBytes = seedBytes;
      const treeRows = [['Root seed', toHex(currentBytes)]];
      for (const seg of segments) {
        const base = await C.importKey('raw', currentBytes, {name:'HKDF'}, false, ['deriveBits']);
        const bits = await C.deriveBits({name:'HKDF',hash:'SHA-256',salt:enc.encode('keypear-tree'),info:enc.encode(seg)}, base, 256);
        currentBytes = new Uint8Array(bits);
        treeRows.push([`→ ${seg}`, toHex(currentBytes)]);
      }
      rows = treeRows;
    }
    outBox('dv-out', rows);
  } catch(e) { errBox('dv-out', e.message); }
}
