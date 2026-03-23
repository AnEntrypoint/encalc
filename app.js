import { ed25519 } from 'https://cdn.jsdelivr.net/npm/@noble/curves@1.8.1/esm/ed25519.js';
import { blake2b } from 'https://cdn.jsdelivr.net/npm/@noble/hashes@1.8.0/esm/blake2.js';
import { sha512 } from 'https://cdn.jsdelivr.net/npm/@noble/hashes@1.8.0/esm/sha2.js';

// ── Primitives ───────────────────────────────────────────────────────────────
const SC = crypto.subtle, ENC = new TextEncoder(), DEC = new TextDecoder();
const $ = id => document.getElementById(id);
const toHex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('');
const fromHex = h => { const s = h.replace(/\s/g,''); return new Uint8Array(s.match(/.{2}/g).map(b=>parseInt(b,16))); };
const toB64  = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const toPem  = (t,b) => `-----BEGIN ${t}-----\n${toB64(b).match(/.{1,64}/g).join('\n')}\n-----END ${t}-----`;
const fromPem = p => fromB64(p.replace(/-----[^-]+-----|\s/g,''));
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
const isHex64 = s => /^[0-9a-f]{64}$/i.test(s.trim());

// ── Keypear math ─────────────────────────────────────────────────────────────
const L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
const Pt = ed25519.ExtendedPoint;
const leToBI = b => { let n=0n; for(let i=b.length-1;i>=0;i--) n=(n<<8n)|BigInt(b[i]); return n; };
const biToLE = (n,len) => { const a=new Uint8Array(len); for(let i=0;i<len;i++){a[i]=Number(n&0xffn);n>>=8n;} return a; };

function kpTweak(pub, name) {
  const nb = typeof name==='string' ? ENC.encode(name) : name;
  // keypear: tweakKeyPair = blake2b(pub||name) → extension_tweak_ed25519_base(scalar, pk, seed)
  // extension_tweak_ed25519_base does SHA-512(seed), takes first 32 bytes,
  // then clamps bits 254-255 only (no cofactor byte[0] &= 0xf8 — tweaks don't need it)
  const seed = blake2b(new Uint8Array([...pub,...nb]), {dkLen:32});
  const h = sha512(seed).slice(0, 32);
  h[31] &= 0x7f;  // clear bit 255 (mirrors extension_tweak_ed25519_base exactly)
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
  // Deterministic nonce: BLAKE2b(scalar || msg) — avoids needing a seed prefix
  const r = leToBI(blake2b(new Uint8Array([...scalarBytes, ...nb]), {dkLen:64})) % L;
  const R = Pt.BASE.multiply(r).toRawBytes();
  // Challenge: SHA-512(R || pubKey || msg) mod L — must match ed25519.verify internals
  const kBytes = new Uint8Array(await crypto.subtle.digest('SHA-512', new Uint8Array([...R, ...pubBytes, ...nb])));
  const k = leToBI(kBytes) % L;
  const S = (r + k * scalar) % L;
  return new Uint8Array([...R, ...biToLE(S, 32)]);
}
function kpVerify(pubBytes, msg, sigBytes) {
  try { return ed25519.verify(sigBytes, typeof msg==='string'?ENC.encode(msg):msg, pubBytes); }
  catch { return false; }
}

// ── State ─────────────────────────────────────────────────────────────────────
const STATE = {
  masterHex: null,
  tree: null,         // { nodeMap: {id: node}, rootId: 'root' }
  selectedNode: null,
  clips: [null, null, null], // { label, value }
};

function saveSt() {
  try { localStorage.setItem('encalc', JSON.stringify({
    masterHex: STATE.masterHex,
    clips: STATE.clips,
    treePaths: $('tree-paths').value,
    treeSeed: $('tree-seed').value,
  })); } catch {}
}

function loadSt() {
  try {
    const d = JSON.parse(localStorage.getItem('encalc') || 'null');
    if (!d) return;
    if (d.masterHex) { STATE.masterHex = d.masterHex; applyMaster(d.masterHex); }
    if (d.clips) { STATE.clips = d.clips; d.clips.forEach((c,i) => c && renderClip(i)); }
    if (d.treePaths) $('tree-paths').value = d.treePaths;
    if (d.treeSeed) $('tree-seed').value = d.treeSeed;
  } catch {}
}

// ── UI core ───────────────────────────────────────────────────────────────────
const PANELS = ['seed','mnemonic','keygen','tree','derive','encrypt','sign','dh','hash','convert','random'];

function show(id) {
  PANELS.forEach(p => { $(p).classList.toggle('on', p===id); });
  document.querySelectorAll('.ni').forEach(el => el.classList.toggle('on', el.id==='nav-'+id));
}

function switchTab(panel, tab) {
  const base = panel+'-';
  // tab buttons
  const tbContainer = $(`${panel}-tabs`) || document.querySelector(`#${panel} .tabs`);
  if (tbContainer) tbContainer.querySelectorAll('.tab').forEach((t,i) => {
    const tbs = tbContainer.querySelectorAll('.tab');
    t.classList.remove('on');
    if (t.getAttribute('onclick') && t.getAttribute('onclick').includes(`'${tab}'`)) t.classList.add('on');
  });
  // panels
  document.querySelectorAll(`[id^="${base}"]`).forEach(el => {
    if (el.classList.contains('tab-body')) el.classList.toggle('on', el.id === base+tab);
  });
}

const _vals = {};
let _vk = 0;
function _storeVal(v) { const k = 'v'+(++_vk); _vals[k]=v; return k; }

function outRows(id, rows) {
  $(id).innerHTML = `<div class="out-area">${rows.map(r => {
    if (!r) return '';
    const [lbl, val, ...meta] = r;
    const cls = meta.includes('secret') ? ' secret' : meta.includes('neutral') ? ' neutral' : meta.includes('plain') ? ' plain' : '';
    const targets = meta.filter(m => m && m!=='secret' && m!=='neutral' && m!=='plain');
    const k = _storeVal(val);
    return `<div class="ob${cls}">
      <div class="ob-hd">
        <span class="ob-lbl">${esc(lbl)}</span>
        <div class="ob-acts">
          ${targets.map(t=>`<button onclick="_pipe('${k}','${esc(t)}')">→ ${esc(t.split(',')[0].split('-').slice(-1)[0])}</button>`).join('')}
          <button onclick="_pin('${k}','${esc(lbl)}')">📌</button>
          <button onclick="_cp(this,'${k}')">copy</button>
        </div>
      </div>
      <pre>${esc(val)}</pre>
    </div>`;
  }).join('')}</div>`;
}
function _pipe(k, targets) { pipe(_vals[k], targets); }
function _pin(k, label)    { pin(_vals[k], label); }
function _cp(btn, k)       { cp(btn, _vals[k]); }

function errOut(id, msg) { $(id).innerHTML = `<div class="err-box">⚠ ${esc(msg)}</div>`; }
function okOut(id, msg)  { $(id).innerHTML = `<div class="ok-box">✓ ${esc(msg)}</div>`; }
function infoOut(id, msg){ $(id).innerHTML = `<div class="info-box">${esc(msg)}</div>`; }
function clearOut(id)    { $(id).innerHTML = ''; }

function setBusy(btnEl, on) {
  if (typeof btnEl === 'string') btnEl = document.querySelector(`[onclick="${btnEl}"]`);
  if (!btnEl) return;
  if (on) { btnEl._saved = btnEl.innerHTML; btnEl.innerHTML = '<span class="spin"></span>'; btnEl.disabled = true; }
  else { btnEl.innerHTML = btnEl._saved || btnEl.innerHTML; btnEl.disabled = false; }
}

function cp(btn, val) {
  navigator.clipboard.writeText(val).then(() => { btn.textContent='✓'; setTimeout(()=>btn.textContent='copy',1500); });
}

function pipe(val, targets) {
  targets.split(',').forEach(t => { const el=$(t); if(el){ el.value=val; el.dispatchEvent(new Event('input')); }});
}

function pin(val, label) {
  const slot = STATE.clips.findIndex(c=>!c);
  const idx = slot===-1 ? 2 : slot;
  STATE.clips[idx] = { label: label.slice(0,20), value: val };
  renderClip(idx);
  saveSt();
}

function renderClip(i) {
  const c = STATE.clips[i];
  const pill = $(`clip${i}`);
  const val = $(`clip${i}-val`);
  if (c) {
    pill.classList.add('filled');
    val.textContent = c.value.slice(0,12)+'…';
    pill.title = c.label+': '+c.value.slice(0,32)+'…';
  } else {
    pill.classList.remove('filled');
    val.textContent = 'empty';
    pill.title = '';
  }
}

function useClip(i) {
  const c = STATE.clips[i];
  if (!c) return;
  navigator.clipboard.writeText(c.value).then(() => {
    const v = $(`clip${i}-val`);
    const prev = v.textContent; v.textContent = '✓ copied'; setTimeout(()=>v.textContent=prev, 1200);
  });
}

function copyMaster() {
  if (STATE.masterHex) navigator.clipboard.writeText(STATE.masterHex);
}

// ── Seed derivation ───────────────────────────────────────────────────────────
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

function applyMaster(hex) {
  STATE.masterHex = hex;
  // header pill
  const pill = $('active-key-pill');
  pill.classList.add('has-key');
  $('akp-text').textContent = hex.slice(0,10)+'…'+hex.slice(-6);
  // seed panel
  $('sn1').classList.add('done'); $('sn2').classList.add('done');
  $('seed-status-box').className = 'ok-box'; $('seed-status-box').textContent = '✓ Master seed is set.';
  $('seed-next').style.display = 'flex';
  $('seed-hex-display').textContent = hex;
  $('kp-seed').value = hex;
  $('nb-seed').textContent = 'set'; $('nb-seed').className = 'badge ready';
  $('nb-tree').textContent = 'ready'; $('nb-tree').className = 'badge ready';
  saveSt();
}

// ── SEED panel ────────────────────────────────────────────────────────────────
async function setMaster() {
  const raw = $('ms-input').value.trim();
  const kdf = $('ms-kdf').value, salt = $('ms-salt').value;
  if (!raw) return errOut('ms-out','Enter a passphrase, mnemonic, or hex seed');
  const btn = document.querySelector('[onclick="setMaster()"]');
  setBusy(btn, true);
  try {
    const bytes = await deriveSeedBytes(raw, kdf, salt);
    const hex = toHex(bytes);
    applyMaster(hex);
    outRows('ms-out', [['Master Seed', hex, 'neutral', 'kp-seed,tree-seed,tp-seed,ci-seed,hkdf-ikm']]);
  } catch(e) { errOut('ms-out', e.message); }
  setBusy(btn, false);
}

function genRandSeed() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  $('ms-input').value = toHex(bytes);
  $('ms-kdf').value = 'raw';
  setMaster();
}

async function deriveRootKeypair() {
  const seedHex = $('kp-seed').value.trim() || STATE.masterHex;
  if (!seedHex) return errOut('kp-out','Set master seed first');
  try {
    const bytes = fromHex(seedHex);
    const scalar = leToBI(bytes) % L;
    const pub = Pt.BASE.multiply(scalar).toRawBytes();
    outRows('kp-out', [
      ['Root Public Key (hex)',  toHex(pub), 'neutral', 'pub-derive-parent,vf-pk'],
      ['Root Private Scalar',   toHex(biToLE(scalar,32)), 'secret', 'sg-privkey'],
    ]);
    $('root-kp-badge').textContent = 'derived'; $('root-kp-badge').className = 'badge green';
  } catch(e) { errOut('kp-out', e.message); }
}

// ── MNEMONIC ──────────────────────────────────────────────────────────────────
function countWords() {
  const words = $('mn-words').value.trim().split(/\s+/).filter(Boolean);
  $('mn-word-count').textContent = words.length ? `${words.length} words` : '';
}

function genMnemonic() {
  const count = +$('mn-count').value;
  const bytes = crypto.getRandomValues(new Uint8Array(count===24?32:16));
  const bits = Array.from(bytes).map(b=>b.toString(2).padStart(8,'0')).join('');
  const words = Array.from({length:count}, (_,i) => BIP39[parseInt(bits.slice(i*11,(i+1)*11),2)%2048]);
  const phrase = words.join(' ');
  $('mn-words').value = phrase; countWords();
  outRows('mn-gen-out', [['Mnemonic ('+count+' words)', phrase, 'mn-words,ms-input']]);
}

async function mnToSeed() {
  const words = $('mn-words').value.trim();
  const pass  = $('mn-pass').value;
  if (!words) return errOut('mn-out','Enter mnemonic words');
  try {
    const b = await SC.importKey('raw',ENC.encode(words),{name:'PBKDF2'},false,['deriveBits']);
    const bits = await SC.deriveBits({name:'PBKDF2',hash:'SHA-512',salt:ENC.encode('mnemonic'+pass),iterations:2048},b,512);
    const hex = toHex(new Uint8Array(bits)).slice(0,64);
    outRows('mn-out', [['BIP39 Seed (256-bit hex)', hex, 'neutral', 'ms-input,kp-seed,tree-seed,tp-seed,hkdf-ikm']]);
  } catch(e) { errOut('mn-out', e.message); }
}

async function mnToMaster() {
  const words = $('mn-words').value.trim();
  const pass  = $('mn-pass').value;
  if (!words) return errOut('mn-out','Enter mnemonic words');
  try {
    const b = await SC.importKey('raw',ENC.encode(words),{name:'PBKDF2'},false,['deriveBits']);
    const bits = await SC.deriveBits({name:'PBKDF2',hash:'SHA-512',salt:ENC.encode('mnemonic'+pass),iterations:2048},b,256);
    const hex = toHex(new Uint8Array(bits));
    applyMaster(hex);
    $('ms-input').value = words; $('ms-kdf').value = 'bip39';
    outRows('mn-out', [['Master Seed set from mnemonic', hex, 'neutral']]);
  } catch(e) { errOut('mn-out', e.message); }
}

// ── KEY GENERATOR ─────────────────────────────────────────────────────────────
const KG_HINTS = {
  'AES-256': 'Generates 32 random bytes for AES-256-GCM symmetric encryption.',
  'AES-128': 'Generates 16 random bytes for AES-128-GCM symmetric encryption.',
  'RSA-2048': 'Generates RSA keypair. RSA-4096 is slower but stronger.',
  'RSA-4096': 'Generating RSA-4096 takes a few seconds — please wait.',
  'ECDH-P256': 'Elliptic-curve Diffie-Hellman keypair for key exchange.',
  'Ed25519': 'Ed25519 keypair for signing/verification.',
};
function kgAlgChange() { $('kg-hint').textContent = KG_HINTS[$('kg-alg').value] || ''; }

async function genKey() {
  const alg = $('kg-alg').value;
  const btn = $('kg-btn');
  setBusy(btn, true);
  try {
    let rows = [];
    if (alg.startsWith('AES')) {
      const k = await SC.generateKey({name:'AES-GCM',length:alg==='AES-256'?256:128},true,['encrypt','decrypt']);
      rows = [['AES Key (hex)', toHex(await SC.exportKey('raw',k)), 'neutral', 'ek-key']];
    } else if (alg.startsWith('RSA')) {
      const len = alg==='RSA-4096'?4096:2048;
      const k = await SC.generateKey({name:'RSA-OAEP',modulusLength:len,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
      rows = [['Public Key (PEM)', toPem('PUBLIC KEY',await SC.exportKey('spki',k.publicKey)), 'neutral', 'er-key'],
              ['Private Key (PEM)', toPem('PRIVATE KEY',await SC.exportKey('pkcs8',k.privateKey)), 'secret', 'er-key']];
    } else if (alg==='ECDH-P256') {
      const k = await SC.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveKey','deriveBits']);
      rows = [['Public Key (PEM)', toPem('PUBLIC KEY',await SC.exportKey('spki',k.publicKey)), 'neutral', 'dh-theirpub'],
              ['Private Key (PEM)', toPem('PRIVATE KEY',await SC.exportKey('pkcs8',k.privateKey)), 'secret', 'dh-mypriv']];
    } else {
      const k = await SC.generateKey({name:'Ed25519'},true,['sign','verify']);
      const pub = await SC.exportKey('spki',k.publicKey);
      rows = [['Public Key (hex)', toHex(pub).slice(-64), 'neutral', 'vf-pk'],
              ['Private Key (PEM)', toPem('PRIVATE KEY',await SC.exportKey('pkcs8',k.privateKey)), 'secret']];
    }
    outRows('kg-out', rows);
  } catch(e) { errOut('kg-out', e.message); }
  setBusy(btn, false);
}

// ── KEY TREE ──────────────────────────────────────────────────────────────────
const NW=192, NH=60, GX=44, GY=14;

async function buildTree() {
  const raw = $('tree-seed').value.trim() || STATE.masterHex;
  if (!raw) { errOut('nd-body','Set a master seed first (Seed panel)'); return; }
  const pathStr = $('tree-paths').value.trim();
  const paths = pathStr ? pathStr.split(',').map(s=>s.trim()).filter(Boolean) : ['app/signing','app/encryption'];

  const seedBytes = isHex64(raw) ? fromHex(raw) : await deriveSeedBytes(raw,'pbkdf2');
  const rootScalar = leToBI(seedBytes) % L;
  const rootPub = Pt.BASE.multiply(rootScalar).toRawBytes();

  const nm = {};
  const mk = (id, name, pub, scalar, pid) => {
    nm[id] = { id, name, pub, scalar, parentId: pid, children: [], showKey: false };
    if (pid && nm[pid]) nm[pid].children.push(id);
  };
  mk('root', raw.length>18 ? raw.slice(0,16)+'…' : raw, rootPub, rootScalar, null);

  for (const path of paths) {
    let cp = rootPub, cs = rootScalar, pid = 'root';
    for (const seg of path.split('/').filter(Boolean)) {
      const nid = pid+'/'+seg;
      if (!nm[nid]) { const d = kpFullDerive(cp, cs, seg); mk(nid, seg, d.pub, d.scalar, pid); cp=d.pub; cs=d.scalar; }
      else { cp=nm[nid].pub; cs=nm[nid].scalar; }
      pid = nid;
    }
  }
  STATE.tree = { nodeMap: nm }; STATE.selectedNode = null;
  renderTree();
  saveSt();
}

function treeReset() { STATE.tree=null; STATE.selectedNode=null; $('tree-svg').innerHTML=''; $('nd-path').textContent='click a node'; $('nd-body').innerHTML='<div class="info-box">Select a node in the tree to inspect its keys.</div>'; }
function treeShowAll() { if(!STATE.tree) return; Object.values(STATE.tree.nodeMap).forEach(n=>n.showKey=true); renderTree(); }
function treeHideAll() { if(!STATE.tree) return; Object.values(STATE.tree.nodeMap).forEach(n=>n.showKey=false); renderTree(); }

function renderTree() {
  const nm = STATE.tree?.nodeMap;
  if (!nm) return;
  const svg = $('tree-svg');
  svg.innerHTML = '';

  // Layout
  const depth = id => { let d=0,n=nm[id]; while(n.parentId){d++;n=nm[n.parentId];} return d; };
  Object.keys(nm).forEach(id => nm[id]._d = depth(id));

  const slots = id => {
    const n = nm[id];
    if (!n.children.length) { n._s = slots._cur++; return; }
    n.children.forEach(c => slots(c));
    const fc = nm[n.children[0]], lc = nm[n.children[n.children.length-1]];
    n._s = (fc._s + lc._s) / 2;
  };
  slots._cur = 0; slots('root');
  const totalSlots = slots._cur;

  const px = n => n._d*(NW+GX)+12;
  const py = n => n._s*(NH+GY)+12;
  const svgW = Math.max(760, (Math.max(...Object.values(nm).map(n=>n._d))+1)*(NW+GX)+24);
  const svgH = Math.max(280, totalSlots*(NH+GY)+24);
  svg.setAttribute('width', svgW); svg.setAttribute('height', svgH);

  const ns = s => document.createElementNS('http://www.w3.org/2000/svg', s);

  const draw = id => {
    const n = nm[id]; if (!n) return;
    n.children.forEach(cid => {
      const c = nm[cid]; if(!c) return;
      const path = ns('path');
      const x1=px(n)+NW, y1=py(n)+NH/2, x2=px(c), y2=py(c)+NH/2, mx=(x1+x2)/2;
      path.setAttribute('d', `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`);
      path.setAttribute('class','edge'); svg.appendChild(path);
      draw(cid);
    });

    const x=px(n), y=py(n), sel=STATE.selectedNode===id;
    const g = ns('g');
    g.setAttribute('class', `nd${id==='root'?' root':''}${sel?' sel':''}`);
    g.setAttribute('transform', `translate(${x},${y})`);
    g.style.cursor = 'pointer';

    const rect = ns('rect');
    rect.setAttribute('width',NW); rect.setAttribute('height',NH); rect.setAttribute('rx',6);
    g.appendChild(rect);

    const pubHex = toHex(n.pub);
    const keyStr = n.showKey ? pubHex.slice(0,26)+'…' : pubHex.slice(0,8)+'…'+pubHex.slice(-4);

    [['t-name', 10, 19, n.name.length>22?n.name.slice(0,20)+'…':n.name],
     ['t-key',  10, 34, keyStr],
     ['t-info', 10, 48, n.children.length ? `${n.children.length} child${n.children.length>1?'ren':''}`:'leaf node'],
    ].forEach(([cls,x,y,txt]) => {
      const t = ns('text'); t.setAttribute('class',cls); t.setAttribute('x',x); t.setAttribute('y',y);
      t.textContent = txt; g.appendChild(t);
    });

    g.addEventListener('click', () => selectTreeNode(id));
    svg.appendChild(g);

    // Show + button only on hovered/selected or leaf
    const bg = ns('g'); bg.setAttribute('class','add-btn');
    bg.setAttribute('transform',`translate(${x+NW-10},${y+NH/2-10})`);
    const c2 = ns('circle'); c2.setAttribute('cx',10); c2.setAttribute('cy',10); c2.setAttribute('r',8);
    const t2 = ns('text'); t2.setAttribute('x',10); t2.setAttribute('y',11); t2.textContent='+';
    bg.appendChild(c2); bg.appendChild(t2);
    bg.addEventListener('click', e => { e.stopPropagation(); selectTreeNode(id); promptAddChild(id); });
    svg.appendChild(bg);
  };
  draw('root');
  $('tree-canvas').style.minHeight = (svgH+16)+'px';
}

function selectTreeNode(id) {
  STATE.selectedNode = id;
  renderTree();
  const n = STATE.tree.nodeMap[id];
  if (!n) return;
  $('nd-path').textContent = id;
  const pubHex = toHex(n.pub);
  const scHex  = toHex(biToLE(n.scalar,32));
  $('nd-body').innerHTML = `
    <div class="btn-row" style="flex-wrap:wrap;gap:4px">
      <button class="sm" onclick="promptAddChild('${esc(id)}')">+ Add Child</button>
      <button class="sm g" onclick="STATE.tree.nodeMap['${esc(id)}'].showKey=!STATE.tree.nodeMap['${esc(id)}'].showKey;renderTree()">Toggle Key</button>
    </div>
    <div class="out-area">
      <div class="ob neutral"><div class="ob-hd"><span class="ob-lbl">Public Key</span><div class="ob-acts">
        <button onclick="pipe('${esc(pubHex)}','pub-derive-parent,vf-pk')">→ Use</button>
        <button onclick="pin('${esc(pubHex)}','${esc(id)} pubkey')">📌</button>
        <button onclick="cp(this,'${esc(pubHex)}')">copy</button>
      </div></div><pre>${esc(pubHex)}</pre></div>
      <div class="ob secret"><div class="ob-hd"><span class="ob-lbl">Private Scalar ⚠</span><div class="ob-acts">
        <button onclick="pipe('${esc(scHex)}','sg-privkey')">→ Sign</button>
        <button onclick="pin('${esc(scHex)}','${esc(id)} scalar')">📌</button>
        <button onclick="cp(this,'${esc(scHex)}')">copy</button>
      </div></div><pre>${esc(scHex)}</pre></div>
    </div>
    <div class="divider"></div>
    <div class="btn-row" style="flex-wrap:wrap;gap:4px">
      <button class="sm g" onclick="signWithNode('${esc(id)}')">✍ Sign…</button>
      <button class="sm g" onclick="encryptToNode('${esc(id)}')">🔒 Encrypt to…</button>
      <button class="sm g" onclick="show('derive');$('tp-path').value='${esc(id.replace('root/',''))}';doTreePath()">🔗 Derive from…</button>
    </div>
  `;
}

function promptAddChild(parentId) {
  const name = window.prompt('Child node name:');
  if (!name) return;
  const parent = STATE.tree.nodeMap[parentId];
  const nid = parentId+'/'+name;
  if (STATE.tree.nodeMap[nid]) return;
  const d = kpFullDerive(parent.pub, parent.scalar, name);
  STATE.tree.nodeMap[nid] = { id:nid, name, pub:d.pub, scalar:d.scalar, parentId, children:[], showKey:false };
  parent.children.push(nid);
  renderTree();
  selectTreeNode(nid);
  saveSt();
}

function signWithNode(id) {
  const n = STATE.tree.nodeMap[id];
  if (!n) return;
  show('sign');
  $('sg-privkey').value = toHex(biToLE(n.scalar,32));
  switchTab('sign','sign-key');
  document.querySelectorAll('#sign .tabs .tab').forEach(t => {
    t.classList.toggle('on', t.getAttribute('onclick')?.includes('sign-key'));
  });
}

function encryptToNode(id) {
  const n = STATE.tree.nodeMap[id];
  if (!n) return;
  show('encrypt');
  $('etp-path').value = id.replace('root/','');
  switchTab('encrypt','aes-path');
}

async function pubOnlyDerive() {
  const parentHex = $('pub-derive-parent').value.trim();
  const name = $('pub-derive-name').value.trim();
  if (!parentHex || !name) return errOut('pub-derive-out','Enter parent public key and child name');
  try {
    const parentPub = fromHex(parentHex);
    const childPub = kpPubDerive(parentPub, name);
    outRows('pub-derive-out', [
      ['Child Public Key (pub-only derivation)', toHex(childPub), 'neutral', 'vf-pk,pub-derive-parent'],
    ]);
  } catch(e) { errOut('pub-derive-out', e.message); }
}

// ── DERIVE panel ─────────────────────────────────────────────────────────────
async function doHKDF() {
  const ikm = $('hkdf-ikm').value.trim();
  const info = $('hkdf-info').value, salt = $('hkdf-salt').value;
  const bits = +$('hkdf-len').value;
  if (!ikm) return errOut('hkdf-out','Enter key material');
  try {
    const ikmBytes = isHex64(ikm) ? fromHex(ikm) : ENC.encode(ikm);
    const base = await SC.importKey('raw', ikmBytes, {name:'HKDF'}, false, ['deriveBits']);
    const out = await SC.deriveBits({name:'HKDF',hash:'SHA-256',salt:ENC.encode(salt),info:ENC.encode(info)}, base, bits);
    outRows('hkdf-out', [['HKDF-SHA256 output ('+bits+' bits)', toHex(out), 'neutral', 'ek-key,etp-path']]);
  } catch(e) { errOut('hkdf-out', e.message); }
}

async function doPBKDF2() {
  const pass = $('pb-pass').value;
  const salt = $('pb-salt').value, iter = +$('pb-iter').value, bits = +$('pb-len').value;
  if (!pass) return errOut('pb-out','Enter a password');
  const btn = document.querySelector('[onclick="doPBKDF2()"]');
  setBusy(btn, true);
  try {
    const base = await SC.importKey('raw', ENC.encode(pass), {name:'PBKDF2'}, false, ['deriveBits']);
    const out = await SC.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:ENC.encode(salt),iterations:iter}, base, bits);
    outRows('pb-out', [['PBKDF2-SHA256 output', toHex(out), 'neutral', 'ek-key']]);
  } catch(e) { errOut('pb-out', e.message); }
  setBusy(btn, false);
}

async function doTreePath() {
  const seedRaw = $('tp-seed').value.trim() || STATE.masterHex;
  const path = $('tp-path').value.trim();
  if (!seedRaw) return errOut('tp-out','Set master seed or enter a seed');
  if (!path) return errOut('tp-out','Enter a derivation path');
  try {
    const seedBytes = isHex64(seedRaw) ? fromHex(seedRaw) : await deriveSeedBytes(seedRaw,'pbkdf2');
    let scalar = leToBI(seedBytes) % L;
    let pub = Pt.BASE.multiply(scalar).toRawBytes();
    const rows = [['root', toHex(pub), 'neutral']];
    for (const seg of path.split('/').filter(Boolean)) {
      const d = kpFullDerive(pub, scalar, seg);
      pub=d.pub; scalar=d.scalar;
      rows.push(['→ '+seg, toHex(pub), 'neutral', 'ek-key,pub-derive-parent,vf-pk']);
    }
    rows[rows.length-1].push('ek-key'); // make leaf key auto-pipeable
    outRows('tp-out', rows);
  } catch(e) { errOut('tp-out', e.message); }
}

async function doChainInspect() {
  const seedRaw = $('ci-seed').value.trim() || STATE.masterHex;
  const path = $('ci-path').value.trim();
  if (!seedRaw) return errOut('ci-out','Enter seed');
  try {
    const seedBytes = isHex64(seedRaw) ? fromHex(seedRaw) : await deriveSeedBytes(seedRaw,'pbkdf2');
    let scalar = leToBI(seedBytes) % L;
    let pub = Pt.BASE.multiply(scalar).toRawBytes();
    const rows = [['[root] Public Key', toHex(pub), 'neutral'], ['[root] Private Scalar', toHex(biToLE(scalar,32)), 'secret']];
    for (const seg of path.split('/').filter(Boolean)) {
      const tweak = kpTweak(pub, seg);
      rows.push([`  tweak("${seg}") scalar`, toHex(biToLE(tweak.scalar,32)), 'secret']);
      rows.push([`  tweak("${seg}") point`, toHex(tweak.pub), 'neutral']);
      const d = kpFullDerive(pub, scalar, seg);
      pub=d.pub; scalar=d.scalar;
      rows.push([`[${seg}] Public Key`, toHex(pub), 'neutral']);
      rows.push([`[${seg}] Private Scalar`, toHex(biToLE(scalar,32)), 'secret']);
    }
    outRows('ci-out', rows);
  } catch(e) { errOut('ci-out', e.message); }
}

// ── ENCRYPT ───────────────────────────────────────────────────────────────────
async function aesGCMEncrypt(keyBytes, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
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
async function pbkdf2Key(pass, salt) {
  const b = await SC.importKey('raw', ENC.encode(pass), {name:'PBKDF2'}, false, ['deriveKey']);
  return SC.deriveKey({name:'PBKDF2',salt:ENC.encode(salt),hash:'SHA-256',iterations:100000}, b, {name:'AES-GCM',length:256}, true, ['encrypt','decrypt']);
}

async function encAESPw(encrypt) {
  const pass = $('ep-pass').value, input = $('ep-input').value.trim();
  if (!pass||!input) return errOut('ep-out','Fill password and input');
  try {
    if (encrypt) {
      const salt = toHex(crypto.getRandomValues(new Uint8Array(8)));
      const k = await pbkdf2Key(pass, salt);
      const raw = await SC.exportKey('raw', k);
      const ct = await aesGCMEncrypt(new Uint8Array(raw), input);
      const combined = salt + ':' + ct;
      outRows('ep-out', [['Ciphertext (base64, salt:ct)', combined, 'neutral', 'ep-input,ek-input,etp-input']]);
    } else {
      const [salt, ct] = input.split(':');
      if (!ct) throw new Error('Expected format: salt:ciphertext');
      const k = await pbkdf2Key(pass, salt);
      const raw = await SC.exportKey('raw', k);
      const plain = await aesGCMDecrypt(new Uint8Array(raw), ct);
      outRows('ep-out', [['Plaintext', plain, 'plain']]);
    }
  } catch(e) { errOut('ep-out', e.message); }
}

async function encAESKey(encrypt) {
  const keyHex = $('ek-key').value.trim(), input = $('ek-input').value.trim();
  if (!keyHex||!input) return errOut('ek-out','Fill AES key and input');
  try {
    const keyBytes = fromHex(keyHex.replace(/\s/g,''));
    if (encrypt) {
      outRows('ek-out', [['Ciphertext (base64)', await aesGCMEncrypt(keyBytes, input), 'neutral', 'ek-input,ep-input']]);
    } else {
      outRows('ek-out', [['Plaintext', await aesGCMDecrypt(keyBytes, input), 'plain']]);
    }
  } catch(e) { errOut('ek-out', e.message); }
}

async function encAESPath(encrypt) {
  const path = $('etp-path').value.trim(), input = $('etp-input').value.trim();
  if (!STATE.masterHex) return errOut('etp-out','Set master seed first');
  if (!path||!input) return errOut('etp-out','Fill path and input');
  try {
    const seedBytes = fromHex(STATE.masterHex);
    let scalar = leToBI(seedBytes) % L, pub = Pt.BASE.multiply(scalar).toRawBytes();
    for (const seg of path.split('/').filter(Boolean)) { const d=kpFullDerive(pub,scalar,seg); pub=d.pub; scalar=d.scalar; }
    const keyBytes = pub.slice(0,32);
    if (encrypt) {
      outRows('etp-out', [
        ['Key path', path],
        ['Key used (hex)', toHex(keyBytes), 'neutral'],
        ['Ciphertext (base64)', await aesGCMEncrypt(keyBytes, input), 'neutral', 'etp-input,ep-input,ek-input'],
      ]);
    } else {
      outRows('etp-out', [
        ['Key path', path],
        ['Plaintext', await aesGCMDecrypt(keyBytes, input), 'plain'],
      ]);
    }
  } catch(e) { errOut('etp-out', e.message); }
}

async function encRSA(encrypt) {
  const keyPem = $('er-key').value.trim(), input = $('er-input').value.trim();
  if (!keyPem||!input) return errOut('er-out','Fill key and input');
  try {
    if (encrypt) {
      const k = await SC.importKey('spki', fromPem(keyPem), {name:'RSA-OAEP',hash:'SHA-256'}, false, ['encrypt']);
      const ct = await SC.encrypt({name:'RSA-OAEP'}, k, ENC.encode(input));
      outRows('er-out', [['Ciphertext (base64)', toB64(ct), 'neutral', 'er-input']]);
    } else {
      const k = await SC.importKey('pkcs8', fromPem(keyPem), {name:'RSA-OAEP',hash:'SHA-256'}, false, ['decrypt']);
      const bytes = fromB64(input);
      outRows('er-out', [['Plaintext', DEC.decode(await SC.decrypt({name:'RSA-OAEP'},k,bytes)), 'plain']]);
    }
  } catch(e) { errOut('er-out', e.message); }
}

// ── SIGN / VERIFY ─────────────────────────────────────────────────────────────
async function doSign() {
  const msg = $('sg-msg').value;
  if (!msg) return errOut('sg-out','Enter a message');

  const useKey = document.querySelector('#sign-sign-key.on');
  let scalar, pubHex;
  try {
    if (useKey) {
      const privHex = $('sg-privkey').value.trim();
      if (!privHex) return errOut('sg-out','Enter private scalar');
      scalar = leToBI(fromHex(privHex));
      pubHex = toHex(Pt.BASE.multiply(scalar).toRawBytes());
    } else {
      const path = $('sg-path').value.trim() || 'app/signing';
      if (!STATE.masterHex) return errOut('sg-out','Set master seed first');
      let s2 = leToBI(fromHex(STATE.masterHex)) % L;
      let p2 = Pt.BASE.multiply(s2).toRawBytes();
      for (const seg of path.split('/').filter(Boolean)) { const d=kpFullDerive(p2,s2,seg); p2=d.pub; s2=d.scalar; }
      scalar=s2; pubHex=toHex(p2);
    }
    const sig = await kpSign(scalar, msg);
    const sigHex = toHex(sig);
    $('vf-pk').value=pubHex; $('vf-sig').value=sigHex; $('vf-msg').value=msg;
    outRows('sg-out', [
      ['Public Key (hex)', pubHex, 'neutral', 'vf-pk'],
      ['Signature (hex)', sigHex, 'neutral', 'vf-sig'],
    ]);
  } catch(e) { errOut('sg-out', e.message); }
}

function doVerify() {
  const pkHex=$('vf-pk').value.trim(), sigHex=$('vf-sig').value.trim(), msg=$('vf-msg').value;
  if (!pkHex||!sigHex||!msg) return errOut('vf-out','Fill all fields');
  try {
    const ok = kpVerify(fromHex(pkHex), msg, fromHex(sigHex));
    if (ok) okOut('vf-out','✓ Signature is valid');
    else errOut('vf-out','✗ Signature is INVALID');
  } catch(e) { errOut('vf-out', e.message); }
}

// ── KEY EXCHANGE ──────────────────────────────────────────────────────────────
async function genECDH() {
  try {
    const k = await SC.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveKey','deriveBits']);
    const pub = await SC.exportKey('spki',k.publicKey);
    const priv = await SC.exportKey('pkcs8',k.privateKey);
    outRows('dh-gen-out', [
      ['My Public Key (PEM — share this)', toPem('PUBLIC KEY',pub), 'neutral'],
      ['My Private Key (PEM — keep secret)', toPem('PRIVATE KEY',priv), 'secret', 'dh-mypriv'],
    ]);
    $('dh-mypriv').value = toPem('PRIVATE KEY',priv);
  } catch(e) { errOut('dh-gen-out', e.message); }
}

async function deriveShared() {
  const myPrivPem=$('dh-mypriv').value.trim(), theirPubPem=$('dh-theirpub').value.trim();
  if (!myPrivPem||!theirPubPem) return errOut('dh-out','Fill both keys');
  try {
    const myPriv = await SC.importKey('pkcs8',fromPem(myPrivPem),{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
    const theirPub = await SC.importKey('spki',fromPem(theirPubPem),{name:'ECDH',namedCurve:'P-256'},false,[]);
    const shared = await SC.deriveBits({name:'ECDH',public:theirPub},myPriv,256);
    const sharedHex = toHex(shared);
    // Derive AES key from shared secret via HKDF
    const hkdfBase = await SC.importKey('raw',shared,{name:'HKDF'},false,['deriveBits']);
    const aesKey = await SC.deriveBits({name:'HKDF',hash:'SHA-256',salt:ENC.encode('encalc-ecdh'),info:ENC.encode('aes-256-gcm')},hkdfBase,256);
    outRows('dh-out', [
      ['Shared Secret (raw)', sharedHex, 'secret'],
      ['Derived AES Key (HKDF)', toHex(aesKey), 'neutral', 'ek-key'],
    ]);
  } catch(e) { errOut('dh-out', e.message); }
}

// ── HASH ─────────────────────────────────────────────────────────────────────
async function doHash() {
  const input = $('hs-input').value;
  const alg = $('hs-alg').value;
  if (!input) return errOut('hs-out','Enter input');
  try {
    let result;
    const bytes = ENC.encode(input);
    if (alg.startsWith('BLAKE2b')) {
      const len = alg==='BLAKE2b-512' ? 64 : 32;
      result = toHex(blake2b(bytes, {dkLen:len}));
    } else {
      result = toHex(await SC.digest(alg, bytes));
    }
    outRows('hs-out', [['Hash ('+alg+')', result, 'neutral']]);
  } catch(e) { errOut('hs-out', e.message); }
}

// ── FORMAT CONVERT ────────────────────────────────────────────────────────────
function doConvert() {
  const input = $('cv-input').value.trim();
  const from = $('cv-from').value;
  if (!input) return errOut('cv-out','Enter input');
  try {
    let bytes;
    const detected = from==='auto' ? autoDetect(input) : from;
    if (detected==='hex') bytes = fromHex(input.replace(/\s/g,''));
    else if (detected==='base64' || detected==='pem') bytes = fromB64(input.replace(/-----[^-]+-----|\s/g,''));
    else bytes = ENC.encode(input);

    outRows('cv-out', [
      ['Hex',    toHex(bytes), 'neutral'],
      ['Base64', toB64(bytes), 'neutral'],
      ['UTF-8',  DEC.decode(bytes), 'plain'],
      ['Bytes',  bytes.length+' bytes', 'neutral'],
    ]);
  } catch(e) { errOut('cv-out', e.message); }
}

function autoDetect(s) {
  if (/^[0-9a-f\s]+$/i.test(s) && s.replace(/\s/g,'').length%2===0) return 'hex';
  if (s.includes('-----BEGIN')) return 'pem';
  if (/^[A-Za-z0-9+/=]+$/.test(s)) return 'base64';
  return 'utf8';
}

// ── RANDOM ────────────────────────────────────────────────────────────────────
function genRandom() {
  const len = Math.min(4096, Math.max(1, +$('rnd-len').value || 32));
  const fmt = $('rnd-fmt').value;
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let val;
  if (fmt==='hex') val = toHex(bytes);
  else if (fmt==='base64') val = toB64(bytes);
  else val = Array.from(bytes).join(' ');
  outRows('rnd-out', [['Random ('+len+' bytes, '+fmt+')', val, 'neutral', 'ms-input,ek-key,hkdf-ikm']]);
}

// ── EXPORT / IMPORT ───────────────────────────────────────────────────────────
function exportState() {
  const data = JSON.stringify({
    masterHex: STATE.masterHex,
    clips: STATE.clips,
    treePaths: $('tree-paths').value,
    version: 1,
  }, null, 2);
  const blob = new Blob([data], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'encalc-session.json';
  a.click();
}

function importState() {
  const inp = document.createElement('input');
  inp.type = 'file'; inp.accept = '.json';
  inp.onchange = e => {
    const f = e.target.files[0]; if (!f) return;
    const r = new FileReader();
    r.onload = ev => {
      try {
        const d = JSON.parse(ev.target.result);
        if (d.masterHex) { applyMaster(d.masterHex); $('ms-input').value=d.masterHex; $('ms-kdf').value='raw'; }
        if (d.clips) { STATE.clips=d.clips; d.clips.forEach((c,i)=>c&&renderClip(i)); }
        if (d.treePaths) $('tree-paths').value = d.treePaths;
        saveSt();
      } catch(e) { alert('Invalid session file: '+e.message); }
    };
    r.readAsText(f);
  };
  inp.click();
}

function clearAll() {
  if (!confirm('Clear all session data?')) return;
  STATE.masterHex=null; STATE.tree=null; STATE.clips=[null,null,null];
  localStorage.removeItem('encalc');
  location.reload();
}

// ── Expose to HTML onclick ────────────────────────────────────────────────────
Object.assign(window, {
  show, switchTab, cp, pipe, pin, useClip, copyMaster, renderClip,
  _pipe, _pin, _cp, _vals,
  setMaster, genRandSeed, deriveRootKeypair,
  genMnemonic, mnToSeed, mnToMaster, countWords,
  kgAlgChange, genKey,
  buildTree, treeReset, treeShowAll, treeHideAll, renderTree,
  selectTreeNode, promptAddChild, signWithNode, encryptToNode, pubOnlyDerive,
  doHKDF, doPBKDF2, doTreePath, doChainInspect,
  encAESPw, encAESKey, encAESPath, encRSA,
  doSign, doVerify,
  genECDH, deriveShared,
  doHash, doConvert, genRandom,
  exportState, importState, clearAll,
  STATE,
});

// ── Init ──────────────────────────────────────────────────────────────────────
kgAlgChange();
loadSt();
