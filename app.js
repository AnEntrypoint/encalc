import { ed25519 } from 'https://cdn.jsdelivr.net/npm/@noble/curves@1.8.1/esm/ed25519.js';
import { blake2b } from 'https://cdn.jsdelivr.net/npm/@noble/hashes@1.8.0/esm/blake2.js';

const C = crypto.subtle, ENC = new TextEncoder(), DEC = new TextDecoder();
const $ = id => document.getElementById(id);
const toHex = b => Array.from(new Uint8Array(b instanceof ArrayBuffer ? b : b)).map(x=>x.toString(16).padStart(2,'0')).join('');
const fromHex = h => Uint8Array.from(h.match(/.{2}/g).map(b=>parseInt(b,16)));
const toPem = (t,b) => `-----BEGIN ${t}-----\n${btoa(String.fromCharCode(...new Uint8Array(b))).match(/.{1,64}/g).join('\n')}\n-----END ${t}-----`;
const parsePem = p => Uint8Array.from(atob(p.replace(/-----[^-]+-----|\s/g,'')), c=>c.charCodeAt(0));

// ── Keypear math (pure JS reimplementation) ────────────────────────────────
const L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
const Point = ed25519.Point;

function leToBI(bytes) { let n=0n; for(let i=bytes.length-1;i>=0;i--) n=(n<<8n)|BigInt(bytes[i]); return n; }
function biToLE(n,len) { const a=new Uint8Array(len); for(let i=0;i<len;i++){a[i]=Number(n&0xffn);n>>=8n;} return a; }

function kpTweak(parentPub, name) {
  const nb = typeof name==='string' ? ENC.encode(name) : name;
  const seed = blake2b(new Uint8Array([...parentPub,...nb]), {dkLen:32});
  const scalar = leToBI(seed) % L;
  const pub = Point.BASE.multiply(scalar).toBytes();
  return {scalar, pub};
}

function kpDerivePub(parentPub, name) {
  const t = kpTweak(parentPub, name);
  return Point.fromHex(toHex(parentPub)).add(Point.fromHex(toHex(t.pub))).toBytes();
}

function kpDeriveFull(parentPub, parentScalar, name) {
  const t = kpTweak(parentPub, name);
  const childScalar = (parentScalar + t.scalar) % L;
  const childPub = Point.BASE.multiply(childScalar).toBytes();
  return {pub: childPub, scalar: childScalar};
}

function kpSign(scalar, msg) {
  const nb = typeof msg==='string' ? ENC.encode(msg) : msg;
  const privBytes = biToLE(scalar, 32);
  const pubKey = Point.BASE.multiply(scalar).toBytes();
  return ed25519.sign(nb, privBytes);
}

function kpVerify(pubBytes, msg, sig) {
  const nb = typeof msg==='string' ? ENC.encode(msg) : msg;
  try { return ed25519.verify(sig, nb, pubBytes); } catch { return false; }
}

// ── Global state ────────────────────────────────────────────────────────────
const STATE = {
  masterHex: null,     // 32-byte hex
  rootPub: null,       // Uint8Array
  rootScalar: null,    // BigInt
  tree: null,          // tree nodes map
  selectedNode: null,
};

function setSeedStatus(hex) {
  STATE.masterHex = hex;
  const el = $('seed-status');
  const txt = $('seed-status-txt');
  el.className = 'seed-status active';
  txt.textContent = hex.slice(0,8)+'…'+hex.slice(-4);
}

// ── UI helpers ──────────────────────────────────────────────────────────────
function show(id) {
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('on'));
  document.querySelectorAll('.nv').forEach(n=>n.classList.remove('on'));
  $(id).classList.add('on');
  $('nav-'+id) && $('nav-'+id).classList.add('on');
}

function outRows(id, rows) {
  $(id).innerHTML = rows.map(([lbl,val,...targets])=>{
    const useTargets = targets.filter(Boolean);
    return `<div class="ob">
      <div class="ob-hd">
        <span class="ob-label">${esc(lbl)}</span>
        <span class="ob-actions">
          ${useTargets.map(t=>`<button onclick="pipe('${esc(val)}','${t}')">→ ${t.split(',').map(s=>s.split('-').pop()).join('/')}</button>`).join('')}
          <button onclick="cp(this,'${esc(val)}')">copy</button>
        </span>
      </div>
      <pre>${esc(val)}</pre>
    </div>`;
  }).join('');
}

function errOut(id, msg) { $(id).innerHTML = `<div class="err-box">⚠ ${esc(msg)}</div>`; }
function clearOut(id) { $(id).innerHTML=''; }

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }

function cp(btn, val) {
  navigator.clipboard.writeText(val).then(()=>{ btn.textContent='✓'; setTimeout(()=>btn.textContent='copy',1400); });
}

function pipe(val, targets) {
  targets.split(',').forEach(t=>{ const el=$(t); if(el) { el.value=val; el.dispatchEvent(new Event('change')); }});
}

// ── Seed derivation ─────────────────────────────────────────────────────────
async function deriveSeed(raw, kdf, salt) {
  if (kdf==='raw' || /^[0-9a-f]{64}$/i.test(raw)) return fromHex(raw.replace(/\s/g,'').slice(0,64));
  if (kdf==='bip39') {
    const base = await C.importKey('raw', ENC.encode(raw), {name:'PBKDF2'}, false, ['deriveBits']);
    const bits = await C.deriveBits({name:'PBKDF2',hash:'SHA-512',salt:ENC.encode('mnemonic'+(salt||'')),iterations:2048}, base, 256);
    return new Uint8Array(bits);
  }
  const base = await C.importKey('raw', ENC.encode(raw), {name:'PBKDF2'}, false, ['deriveBits']);
  return new Uint8Array(await C.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:ENC.encode(salt||'encalc'),iterations:100000}, base, 256));
}

async function treePathDerive(rootHex, path) {
  let pub = fromHex(rootHex), scalar = leToBI(pub) % L;
  // reconstruct scalar from seed bytes
  scalar = leToBI(fromHex(rootHex)) % L;
  pub = Point.BASE.multiply(scalar).toBytes();
  const nodes = [{name:'root', pub, scalar, path:''}];
  for (const seg of path.split('/').filter(Boolean)) {
    const {pub:cp, scalar:cs} = kpDeriveFull(nodes[nodes.length-1].pub, nodes[nodes.length-1].scalar, seg);
    nodes.push({name:seg, pub:cp, scalar:cs, path: nodes[nodes.length-1].path ? nodes[nodes.length-1].path+'/'+seg : seg});
  }
  return nodes;
}

// ── Master seed panel ───────────────────────────────────────────────────────
async function setMaster() {
  const raw = $('ms-input').value.trim();
  const kdf = $('ms-kdf').value;
  const salt = $('ms-salt').value;
  if (!raw) return errOut('ms-out','Enter a passphrase or seed');
  try {
    const bytes = await deriveSeed(raw, kdf, salt);
    const hex = toHex(bytes);
    setSeedStatus(hex);
    $('kp-seed').value = hex;
    $('kp-badge').textContent = 'ready'; $('kp-badge').className='badge green';
    outRows('ms-out', [['Master Seed (256-bit)', hex, 'kp-seed,tree-seed,ms-input']]);
  } catch(e) { errOut('ms-out', e.message); }
}

function genRandSeed() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  $('ms-input').value = toHex(bytes);
  $('ms-kdf').value = 'raw';
}

async function deriveRootKeypair() {
  const seedHex = $('kp-seed').value.trim() || STATE.masterHex;
  if (!seedHex) return errOut('kp-out','Set master seed first');
  try {
    const seedBytes = fromHex(seedHex);
    const type = $('kp-type').value;
    let rows;
    if (type==='keypear') {
      const scalar = leToBI(seedBytes) % L;
      const pub = Point.BASE.multiply(scalar).toBytes();
      STATE.rootPub = pub; STATE.rootScalar = scalar;
      rows = [
        ['Root Public Key (hex)', toHex(pub), 'vf-pk'],
        ['Root Scalar (hex) ⚠ keep secret', toHex(biToLE(scalar,32))],
      ];
    } else {
      const k = await C.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveKey','deriveBits']);
      const pub = await C.exportKey('spki',k.publicKey);
      const priv = await C.exportKey('pkcs8',k.privateKey);
      rows = [['Public Key (PEM)',toPem('PUBLIC KEY',pub),'enc-key'],['Private Key (PEM)',toPem('PRIVATE KEY',priv),'enc-key']];
    }
    outRows('kp-out', rows);
  } catch(e) { errOut('kp-out', e.message); }
}

async function quickEncrypt() {
  const masterHex = STATE.masterHex;
  if (!masterHex) return errOut('qe-out','Set master seed first');
  const path = $('qe-path').value.trim() || 'app/encryption';
  const plain = $('qe-plain').value;
  if (!plain) return errOut('qe-out','Enter plaintext');
  try {
    const nodes = await treePathDerive(masterHex, path);
    const leaf = nodes[nodes.length-1];
    const keyBytes = leaf.pub.slice(0,32);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const k = await C.importKey('raw', keyBytes, {name:'AES-GCM'}, false, ['encrypt']);
    const ct = await C.encrypt({name:'AES-GCM',iv}, k, ENC.encode(plain));
    const out = new Uint8Array(12+ct.byteLength); out.set(iv); out.set(new Uint8Array(ct),12);
    outRows('qe-out',[
      ['Path used', path],
      ['Key (hex)', toHex(keyBytes)],
      ['Ciphertext (base64)', btoa(String.fromCharCode(...out)), 'qe-plain,enc-input'],
    ]);
  } catch(e) { errOut('qe-out', e.message); }
}

async function quickDecrypt() {
  const masterHex = STATE.masterHex;
  if (!masterHex) return errOut('qe-out','Set master seed first');
  const path = $('qe-path').value.trim() || 'app/encryption';
  const b64 = $('qe-plain').value.trim();
  if (!b64) return errOut('qe-out','Enter base64 ciphertext');
  try {
    const nodes = await treePathDerive(masterHex, path);
    const keyBytes = nodes[nodes.length-1].pub.slice(0,32);
    const bytes = Uint8Array.from(atob(b64), c=>c.charCodeAt(0));
    const k = await C.importKey('raw', keyBytes, {name:'AES-GCM'}, false, ['decrypt']);
    const plain = DEC.decode(await C.decrypt({name:'AES-GCM',iv:bytes.slice(0,12)}, k, bytes.slice(12)));
    outRows('qe-out',[['Decrypted', plain]]);
  } catch(e) { errOut('qe-out', e.message); }
}

// ── Key Tree ─────────────────────────────────────────────────────────────────
const NW=190, NH=58, GAPX=40, GAPY=14;

async function buildTree() {
  const seedRaw = $('tree-seed').value.trim() || STATE.masterHex;
  if (!seedRaw) return alert('Set a master seed first');
  const pathStr = $('tree-paths').value.trim();
  const paths = pathStr ? pathStr.split(',').map(s=>s.trim()).filter(Boolean) : [];

  const seedBytes = /^[0-9a-f]{64}$/i.test(seedRaw) ? fromHex(seedRaw) : await deriveSeed(seedRaw,'pbkdf2','encalc');
  const seedHex = toHex(seedBytes);
  const rootScalar = leToBI(seedBytes) % L;
  const rootPub = Point.BASE.multiply(rootScalar).toBytes();

  const nodeMap = {};
  const mkNode = (id, name, pub, scalar, parentId) => {
    nodeMap[id] = {id, name, pub, scalar, parentId, children:[], showKey: false};
    if (parentId && nodeMap[parentId]) nodeMap[parentId].children.push(id);
  };
  mkNode('root', seedRaw.length>16 ? seedRaw.slice(0,14)+'…':seedRaw, rootPub, rootScalar, null);

  for (const path of paths) {
    let curPub = rootPub, curScalar = rootScalar, parentId = 'root';
    for (const seg of path.split('/').filter(Boolean)) {
      const nodeId = parentId+'/'+seg;
      if (!nodeMap[nodeId]) {
        const {pub,scalar} = kpDeriveFull(curPub, curScalar, seg);
        mkNode(nodeId, seg, pub, scalar, parentId);
        curPub=pub; curScalar=scalar;
      } else {
        curPub=nodeMap[nodeId].pub; curScalar=nodeMap[nodeId].scalar;
      }
      parentId = nodeId;
    }
  }
  STATE.tree = nodeMap; STATE.selectedNode = null;
  renderTree();
}

function treeReset() { STATE.tree=null; STATE.selectedNode=null; $('tree-svg').innerHTML=''; $('nd-panel').style.display='none'; }
function treeExpandAll() { if(!STATE.tree) return; Object.values(STATE.tree).forEach(n=>n.showKey=true); renderTree(); }
function treeCollapseKeys() { if(!STATE.tree) return; Object.values(STATE.tree).forEach(n=>n.showKey=false); renderTree(); }

function treeAddChild() {
  if (!STATE.selectedNode) return alert('Select a node first');
  $('nd-child-form').style.display='flex';
  $('nd-child-name').focus();
}

async function addChildToSelected() {
  const name = $('nd-child-name').value.trim();
  if (!name || !STATE.selectedNode || !STATE.tree) return;
  const parent = STATE.tree[STATE.selectedNode];
  const nodeId = STATE.selectedNode+'/'+name;
  if (STATE.tree[nodeId]) { $('nd-child-name').value=''; return; }
  const {pub,scalar} = kpDeriveFull(parent.pub, parent.scalar, name);
  STATE.tree[nodeId] = {id:nodeId, name, pub, scalar, parentId:STATE.selectedNode, children:[], showKey:false};
  parent.children.push(nodeId);
  $('nd-child-name').value='';
  $('nd-child-form').style.display='none';
  renderTree();
  selectNode(nodeId);
}

function renderTree() {
  const nodeMap = STATE.tree;
  if (!nodeMap) return;
  const svg = $('tree-svg');
  svg.innerHTML = '';

  const assignSlots = (id, slot) => {
    const n = nodeMap[id];
    if (!n) return slot;
    if (!n.children.length) { n._slot=slot; return slot+1; }
    let s=slot;
    n.children.forEach(c=>{ s=assignSlots(c,s); });
    const fc=nodeMap[n.children[0]], lc=nodeMap[n.children[n.children.length-1]];
    n._slot = (fc._slot+lc._slot)/2;
    return s;
  };
  const totalSlots = assignSlots('root',0);

  const depth = id => { let d=0,n=nodeMap[id]; while(n.parentId){d++;n=nodeMap[n.parentId];} return d; };
  Object.keys(nodeMap).forEach(id=>nodeMap[id]._depth=depth(id));

  const svgW = Math.max(800,(Math.max(...Object.values(nodeMap).map(n=>n._depth))+1)*(NW+GAPX)+24);
  const svgH = Math.max(260, totalSlots*(NH+GAPY)+24);
  svg.setAttribute('width',svgW); svg.setAttribute('height',svgH);

  const px = n => n._depth*(NW+GAPX)+12;
  const py = n => n._slot*(NH+GAPY)+12;

  const drawEdge = (p,c) => {
    const x1=px(p)+NW, y1=py(p)+NH/2, x2=px(c), y2=py(c)+NH/2;
    const mx=(x1+x2)/2;
    const path = document.createElementNS('http://www.w3.org/2000/svg','path');
    path.setAttribute('d',`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`);
    path.setAttribute('class','edge');
    svg.appendChild(path);
  };

  const drawNode = id => {
    const n = nodeMap[id];
    if (!n) return;
    n.children.forEach(cid=>{ drawEdge(n,nodeMap[cid]); drawNode(cid); });
    const x=px(n), y=py(n);
    const g = document.createElementNS('http://www.w3.org/2000/svg','g');
    g.setAttribute('class','nd'+(id==='root'?' root':'')+(STATE.selectedNode===id?' sel':''));
    g.setAttribute('transform',`translate(${x},${y})`);

    const rect = document.createElementNS('http://www.w3.org/2000/svg','rect');
    rect.setAttribute('width',NW); rect.setAttribute('height',NH);
    g.appendChild(rect);

    const t1 = document.createElementNS('http://www.w3.org/2000/svg','text');
    t1.setAttribute('class','lbl name'); t1.setAttribute('x',10); t1.setAttribute('y',19);
    t1.textContent = n.name.length>22?n.name.slice(0,20)+'…':n.name;
    g.appendChild(t1);

    const pubHex = toHex(n.pub);
    const keyStr = n.showKey ? pubHex.slice(0,20)+'…' : pubHex.slice(0,8)+'…'+pubHex.slice(-4);
    const t2 = document.createElementNS('http://www.w3.org/2000/svg','text');
    t2.setAttribute('class','lbl key'); t2.setAttribute('x',10); t2.setAttribute('y',36);
    t2.textContent = keyStr;
    g.appendChild(t2);

    const childCount = n.children.length;
    const t3 = document.createElementNS('http://www.w3.org/2000/svg','text');
    t3.setAttribute('class','lbl'); t3.setAttribute('x',10); t3.setAttribute('y',51);
    t3.textContent = childCount>0?`${childCount} child${childCount>1?'ren':''}  · click to inspect`:'leaf · click to inspect';
    g.appendChild(t3);

    g.addEventListener('click',()=>selectNode(id));
    svg.appendChild(g);

    // "+" add-child button
    const btnG = document.createElementNS('http://www.w3.org/2000/svg','g');
    btnG.setAttribute('class','add-n');
    btnG.setAttribute('transform',`translate(${x+NW+8},${y+NH/2-10})`);
    const c = document.createElementNS('http://www.w3.org/2000/svg','circle');
    c.setAttribute('cx',10); c.setAttribute('cy',10); c.setAttribute('r',9);
    const t = document.createElementNS('http://www.w3.org/2000/svg','text');
    t.setAttribute('x',10); t.setAttribute('y',11); t.textContent='+';
    btnG.appendChild(c); btnG.appendChild(t);
    btnG.addEventListener('click',e=>{ e.stopPropagation(); selectNode(id); $('nd-child-form').style.display='flex'; $('nd-child-name').focus(); });
    svg.appendChild(btnG);
  };

  drawNode('root');
  $('tree-wrap').style.minHeight = (svgH+8)+'px';
}

function selectNode(id) {
  STATE.selectedNode = id;
  renderTree();
  const n = STATE.tree[id];
  if (!n) return;
  const panel = $('nd-panel');
  panel.style.display='flex';

  $('nd-path').textContent = id==='root'?'root':id;
  const pubHex = toHex(n.pub);
  const isLeaf = n.children.length===0;

  $('nd-badges').innerHTML = `
    <span class="badge pub">public key</span>
    ${n.scalar!==null?'<span class="badge priv">private scalar</span>':''}
    ${isLeaf?'<span class="badge">leaf</span>':(''+n.children.length+' children')}
  `;

  $('nd-actions').innerHTML = `
    <button class="g sm" onclick="STATE.tree['${esc(id)}'].showKey=!STATE.tree['${esc(id)}'].showKey;renderTree()">Toggle Key</button>
    <button class="sm" onclick="$('nd-child-form').style.display='flex';$('nd-child-name').focus()">+ Child</button>
  `;

  const scalar = n.scalar !== null ? toHex(biToLE(n.scalar,32)) : null;
  $('nd-keys').innerHTML = [
    ['Public Key (hex)', pubHex, 'vf-pk,enc-key'],
    scalar ? ['Private Scalar (hex)', scalar, ''] : null,
    ['PubKey (short)', pubHex.slice(0,16)+'…'],
  ].filter(Boolean).map(([lbl,val,...targets])=>{
    const useTargets = targets.filter(t=>t);
    return `<div class="ob">
      <div class="ob-hd">
        <span class="ob-label">${esc(lbl)}</span>
        <span class="ob-actions">
          ${useTargets.map(t=>`<button onclick="pipe('${esc(val)}','${t}')">→ Use</button>`).join('')}
          <button onclick="cp(this,'${esc(val)}')">copy</button>
        </span>
      </div>
      <pre>${esc(val)}</pre>
    </div>`;
  }).join('');

  $('nd-child-form').style.display='none';
}

// ── Mnemonic ────────────────────────────────────────────────────────────────
function genMnemonic() {
  const count = +$('mn-count').value;
  const bytes = crypto.getRandomValues(new Uint8Array(count===24?32:16));
  const bits = Array.from(bytes).map(b=>b.toString(2).padStart(8,'0')).join('');
  const words = Array.from({length:count},(_,i)=>BIP39[parseInt(bits.slice(i*11,(i+1)*11),2)%2048]);
  const phrase = words.join(' ');
  $('mn-words').value = phrase;
  outRows('mn-gen-out',[['Generated mnemonic',phrase,'mn-words,ms-input']]);
}

async function mnToSeed() {
  const words = $('mn-words').value.trim();
  const pass = $('mn-pass').value;
  if (!words) return errOut('mn-out','Enter mnemonic words');
  try {
    const base = await C.importKey('raw',ENC.encode(words),{name:'PBKDF2'},false,['deriveBits']);
    const bits = await C.deriveBits({name:'PBKDF2',hash:'SHA-512',salt:ENC.encode('mnemonic'+pass),iterations:2048},base,512);
    const hex = toHex(new Uint8Array(bits)).slice(0,64);
    outRows('mn-out',[['Seed (256-bit hex)',hex,'ms-input,kp-seed,tree-seed']]);
  } catch(e) { errOut('mn-out', e.message); }
}

async function mnToMaster() {
  const words = $('mn-words').value.trim();
  const pass = $('mn-pass').value;
  if (!words) return errOut('mn-out','Enter mnemonic words');
  try {
    const base = await C.importKey('raw',ENC.encode(words),{name:'PBKDF2'},false,['deriveBits']);
    const bits = await C.deriveBits({name:'PBKDF2',hash:'SHA-512',salt:ENC.encode('mnemonic'+pass),iterations:2048},base,256);
    const hex = toHex(new Uint8Array(bits));
    setSeedStatus(hex);
    $('ms-input').value=hex; $('ms-kdf').value='raw'; $('kp-seed').value=hex;
    $('kp-badge').textContent='ready'; $('kp-badge').className='badge green';
    outRows('mn-out',[['Master seed set',hex]]);
  } catch(e) { errOut('mn-out', e.message); }
}

// ── Random Key Gen ──────────────────────────────────────────────────────────
async function genKey() {
  const alg = $('kg-alg').value;
  try {
    let rows;
    if (alg.startsWith('AES')) {
      const k = await C.generateKey({name:'AES-GCM',length:alg==='AES-256'?256:128},true,['encrypt','decrypt']);
      rows = [['AES Key (hex)', toHex(await C.exportKey('raw',k)), 'enc-key,qe-path']];
    } else if (alg.startsWith('RSA')) {
      const len = alg==='RSA-4096'?4096:2048;
      const k = await C.generateKey({name:'RSA-OAEP',modulusLength:len,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
      rows = [['Public Key (PEM)',toPem('PUBLIC KEY',await C.exportKey('spki',k.publicKey)),'enc-key'],
              ['Private Key (PEM)',toPem('PRIVATE KEY',await C.exportKey('pkcs8',k.privateKey)),'enc-key']];
    } else if (alg==='ECDH-P256') {
      const k = await C.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveKey','deriveBits']);
      rows = [['Public Key (PEM)',toPem('PUBLIC KEY',await C.exportKey('spki',k.publicKey)),'enc-key'],
              ['Private Key (PEM)',toPem('PRIVATE KEY',await C.exportKey('pkcs8',k.privateKey)),'enc-key']];
    } else {
      const k = await C.generateKey({name:'Ed25519'},true,['sign','verify']);
      rows = [['Public Key (hex)',toHex(await C.exportKey('spki',k.publicKey)),'vf-pk'],
              ['Private Key (PEM)',toPem('PRIVATE KEY',await C.exportKey('pkcs8',k.privateKey))]];
    }
    outRows('kg-out', rows);
  } catch(e) { errOut('kg-out', e.message); }
}

// ── Encrypt / Decrypt ───────────────────────────────────────────────────────
function updateEncUI() {
  const m=$('enc-mode').value;
  $('enc-key-lbl').textContent = m==='aes-pass'?'Password':m==='aes-key'?'AES Key (hex)':'PEM Key (pub=encrypt, priv=decrypt)';
}

async function doEncrypt() {
  const mode=$('enc-mode').value, key=$('enc-key').value, plain=$('enc-input').value;
  if (!plain||!key) return errOut('enc-out','Fill in key and text');
  try {
    let result;
    if (mode==='aes-pass') {
      const salt=crypto.getRandomValues(new Uint8Array(16)), iv=crypto.getRandomValues(new Uint8Array(12));
      const base=await C.importKey('raw',ENC.encode(key),{name:'PBKDF2'},false,['deriveKey']);
      const k=await C.deriveKey({name:'PBKDF2',salt,hash:'SHA-256',iterations:100000},base,{name:'AES-GCM',length:256},false,['encrypt']);
      const ct=await C.encrypt({name:'AES-GCM',iv},k,ENC.encode(plain));
      const out=new Uint8Array(28+ct.byteLength); out.set(salt); out.set(iv,16); out.set(new Uint8Array(ct),28);
      result=btoa(String.fromCharCode(...out));
    } else if (mode==='aes-key') {
      const iv=crypto.getRandomValues(new Uint8Array(12));
      const k=await C.importKey('raw',fromHex(key.replace(/\s/g,'')),{name:'AES-GCM'},false,['encrypt']);
      const ct=await C.encrypt({name:'AES-GCM',iv},k,ENC.encode(plain));
      const out=new Uint8Array(12+ct.byteLength); out.set(iv); out.set(new Uint8Array(ct),12);
      result=btoa(String.fromCharCode(...out));
    } else {
      const k=await C.importKey('spki',parsePem(key),{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt']);
      result=btoa(String.fromCharCode(...new Uint8Array(await C.encrypt({name:'RSA-OAEP'},k,ENC.encode(plain)))));
    }
    outRows('enc-out',[['Ciphertext (base64)',result,'enc-input,qe-plain']]);
  } catch(e) { errOut('enc-out',e.message); }
}

async function doDecrypt() {
  const mode=$('enc-mode').value, key=$('enc-key').value, b64=$('enc-input').value.trim();
  if (!b64||!key) return errOut('enc-out','Fill in key and ciphertext');
  try {
    const bytes=Uint8Array.from(atob(b64),c=>c.charCodeAt(0));
    let plain;
    if (mode==='aes-pass') {
      const base=await C.importKey('raw',ENC.encode(key),{name:'PBKDF2'},false,['deriveKey']);
      const k=await C.deriveKey({name:'PBKDF2',salt:bytes.slice(0,16),hash:'SHA-256',iterations:100000},base,{name:'AES-GCM',length:256},false,['decrypt']);
      plain=DEC.decode(await C.decrypt({name:'AES-GCM',iv:bytes.slice(16,28)},k,bytes.slice(28)));
    } else if (mode==='aes-key') {
      const k=await C.importKey('raw',fromHex(key.replace(/\s/g,'')),{name:'AES-GCM'},false,['decrypt']);
      plain=DEC.decode(await C.decrypt({name:'AES-GCM',iv:bytes.slice(0,12)},k,bytes.slice(12)));
    } else {
      const k=await C.importKey('pkcs8',parsePem(key),{name:'RSA-OAEP',hash:'SHA-256'},false,['decrypt']);
      plain=DEC.decode(await C.decrypt({name:'RSA-OAEP'},k,bytes));
    }
    outRows('enc-out',[['Plaintext',plain]]);
  } catch(e) { errOut('enc-out',e.message); }
}

// ── Sign / Verify ────────────────────────────────────────────────────────────
async function doSign() {
  const masterHex = STATE.masterHex;
  if (!masterHex) return errOut('sg-out','Set master seed first');
  const path = $('sg-path').value.trim() || 'app/signing';
  const msg = $('sg-msg').value;
  if (!msg) return errOut('sg-out','Enter a message');
  try {
    const nodes = await treePathDerive(masterHex, path);
    const leaf = nodes[nodes.length-1];
    const privBytes = biToLE(leaf.scalar, 32);
    const msgBytes = ENC.encode(msg);
    const sig = ed25519.sign(msgBytes, privBytes);
    const pubHex = toHex(leaf.pub);
    const sigHex = toHex(sig);
    $('vf-pk').value = pubHex; $('vf-sig').value = sigHex; $('vf-msg').value = msg;
    outRows('sg-out',[
      ['Signing key path', path],
      ['Public Key (hex)', pubHex, 'vf-pk'],
      ['Signature (hex)', sigHex, 'vf-sig'],
    ]);
  } catch(e) { errOut('sg-out',e.message); }
}

async function doVerify() {
  const pkHex=$('vf-pk').value.trim(), sigHex=$('vf-sig').value.trim(), msg=$('vf-msg').value;
  if (!pkHex||!sigHex||!msg) return errOut('vf-out','Fill all fields');
  try {
    const ok = kpVerify(fromHex(pkHex), msg, fromHex(sigHex));
    $('vf-out').innerHTML = ok
      ? '<div class="ob"><pre style="color:var(--green)">✓ Signature valid</pre></div>'
      : '<div class="err-box">✗ Invalid signature</div>';
  } catch(e) { errOut('vf-out',e.message); }
}

// expose globals called from HTML onclick
Object.assign(window, {
  show,pipe,cp,esc,
  setMaster,genRandSeed,deriveRootKeypair,quickEncrypt,quickDecrypt,
  buildTree,treeReset,treeExpandAll,treeCollapseKeys,treeAddChild,addChildToSelected,
  selectNode,renderTree,
  genMnemonic,mnToSeed,mnToMaster,
  genKey,updateEncUI,doEncrypt,doDecrypt,
  doSign,doVerify,
  STATE,
});
