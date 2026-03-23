const C = crypto.subtle, E = new TextEncoder(), D = new TextDecoder();
const $ = id => document.getElementById(id);
const toHex = b => Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('');
const fromHex = h => new Uint8Array(h.match(/.{2}/g).map(b=>parseInt(b,16)));
const toPem = (t,b) => `-----BEGIN ${t}-----\n${btoa(String.fromCharCode(...new Uint8Array(b))).match(/.{1,64}/g).join('\n')}\n-----END ${t}-----`;
const parsePem = p => Uint8Array.from(atob(p.replace(/-----[^-]+-----|\s/g,'')), c=>c.charCodeAt(0));

const PANELS = ['workflow','tree','mnemonic','keygen','encrypt','derive'];
function show(id) {
  PANELS.forEach(p => { $(p).classList.toggle('active', p===id); });
  document.querySelectorAll('.nav-item').forEach((el,i) => el.classList.toggle('active', PANELS[i]===id));
}

function outRows(id, rows) {
  $(id).innerHTML = rows.map(([lbl,val,useTarget])=>`
    <div style="margin-top:8px">
      <div class="out-block">
        <div class="out-label">${lbl}
          <span>
            ${useTarget?`<button class="use-btn" onclick="pipe('${escHtml(val)}','${useTarget}')">Use →</button>`:''}
            <button class="cp-btn" onclick="cp(this,'${escHtml(val)}')">copy</button>
          </span>
        </div>
        <pre>${escHtml(val)}</pre>
      </div>
    </div>`).join('');
}
function errOut(id, msg) { $(id).innerHTML = `<div class="err">⚠ ${escHtml(msg)}</div>`; }
function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }

function cp(btn, val) {
  navigator.clipboard.writeText(val).then(()=>{ btn.textContent='✓'; setTimeout(()=>btn.textContent='copy',1400); });
}

function pipe(val, targets) {
  targets.split(',').forEach(t => { const el=$(t); if(el) el.value=val; });
}

async function seedBytes(raw, kdf='pbkdf2', salt='encalc') {
  if (/^[0-9a-f]{64}$/i.test(raw)) return fromHex(raw);
  if (kdf==='hex') return fromHex(raw.replace(/\s/g,''));
  const base = await C.importKey('raw', E.encode(raw), {name:'PBKDF2'}, false, ['deriveBits']);
  return new Uint8Array(await C.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:E.encode(salt),iterations:100000}, base, 256));
}

async function hkdfDerive(bytes, info, salt='encalc') {
  const base = await C.importKey('raw', bytes, {name:'HKDF'}, false, ['deriveBits']);
  return new Uint8Array(await C.deriveBits({name:'HKDF',hash:'SHA-256',salt:E.encode(salt),info:E.encode(info)}, base, 256));
}

async function treeDerive(rootBytes, path) {
  let cur = rootBytes;
  const nodes = [{ path:'root', hex: toHex(cur) }];
  for (const seg of path.split('/').filter(Boolean)) {
    cur = await hkdfDerive(cur, seg, 'keypear-tree');
    nodes.push({ path: seg, hex: toHex(cur) });
  }
  return nodes;
}

// ─── WORKFLOW ───────────────────────────────────────────────────────────────

async function wfStep1() {
  const raw = $('wf-seed').value.trim();
  const kdf = $('wf-kdf').value;
  const salt = $('wf-salt').value || 'encalc';
  if (!raw) return errOut('wf-seed-out','Enter a seed or passphrase');
  try {
    const bytes = await seedBytes(raw, kdf, salt);
    const hex = toHex(bytes);
    $('wf-kp-seed').value = hex;
    $('wf-dk-seed').value = hex;
    outRows('wf-seed-out', [['Master Seed (256-bit hex)', hex, 'wf-kp-seed,wf-dk-seed']]);
  } catch(e) { errOut('wf-seed-out', e.message); }
}

async function wfStep2() {
  const raw = $('wf-kp-seed').value.trim();
  const alg = $('wf-kp-alg').value;
  if (!raw) return errOut('wf-kp-out','Derive master seed first (Step 1)');
  try {
    const bytes = await seedBytes(raw, 'hex');
    const rows = [['Seed used', toHex(bytes)]];
    if (alg === 'Ed25519') {
      const pair = await C.generateKey({name:'Ed25519'},true,['sign','verify']);
      const pub = await C.exportKey('spki', pair.publicKey);
      const priv = await C.exportKey('pkcs8', pair.privateKey);
      rows.push(['Public Key (PEM)', toPem('PUBLIC KEY',pub), 'enc-key']);
      rows.push(['Private Key (PEM)', toPem('PRIVATE KEY',priv), 'enc-key']);
      rows.push(['Public Key (hex)', toHex(pub.slice(-32))]);
    } else {
      const pair = await C.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveKey','deriveBits']);
      const pub = await C.exportKey('spki', pair.publicKey);
      const priv = await C.exportKey('pkcs8', pair.privateKey);
      rows.push(['Public Key (PEM)', toPem('PUBLIC KEY',pub), 'enc-key']);
      rows.push(['Private Key (PEM)', toPem('PRIVATE KEY',priv), 'enc-key']);
    }
    outRows('wf-kp-out', rows);
  } catch(e) { errOut('wf-kp-out', e.message); }
}

async function wfStep3() {
  const raw = $('wf-dk-seed').value.trim();
  const paths = $('wf-dk-paths').value.trim().split('\n').filter(Boolean);
  if (!raw) return errOut('wf-dk-out','Derive master seed first (Step 1)');
  try {
    const root = await seedBytes(raw, 'hex');
    const rows = [['Root', toHex(root)]];
    let firstChildHex = '';
    for (const path of paths) {
      const nodes = await treeDerive(root, path);
      const leaf = nodes[nodes.length-1].hex;
      if (!firstChildHex) firstChildHex = leaf;
      rows.push([path, leaf, 'wf-enc-key']);
    }
    if (firstChildHex) $('wf-enc-key').value = firstChildHex;
    outRows('wf-dk-out', rows);
  } catch(e) { errOut('wf-dk-out', e.message); }
}

async function wfToTree() {
  $('tree-seed').value = $('wf-dk-seed').value;
  $('tree-paths').value = $('wf-dk-paths').value.trim().split('\n').join(',');
  show('tree');
  await buildTree();
}

async function wfEncrypt() {
  const key = $('wf-enc-key').value.trim();
  const plain = $('wf-enc-plain').value;
  if (!key || !plain) return errOut('wf-enc-out','Fill in key and plaintext');
  try {
    const keyBytes = key.length === 64 ? fromHex(key) : new Uint8Array(await (async()=>{ const b=await seedBytes(key,'pbkdf2'); return b; })());
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const k = await C.importKey('raw', keyBytes, {name:'AES-GCM'}, false, ['encrypt']);
    const ct = await C.encrypt({name:'AES-GCM',iv}, k, E.encode(plain));
    const out = new Uint8Array(12+ct.byteLength); out.set(iv); out.set(new Uint8Array(ct),12);
    outRows('wf-enc-out', [['Ciphertext (base64, AES-GCM)', btoa(String.fromCharCode(...out)), 'enc-input']]);
  } catch(e) { errOut('wf-enc-out', e.message); }
}

async function wfDecrypt() {
  const key = $('wf-enc-key').value.trim();
  const b64 = $('wf-enc-plain').value.trim();
  if (!key || !b64) return errOut('wf-enc-out','Fill in key and ciphertext');
  try {
    const keyBytes = fromHex(key);
    const bytes = Uint8Array.from(atob(b64), c=>c.charCodeAt(0));
    const iv = bytes.slice(0,12), ct = bytes.slice(12);
    const k = await C.importKey('raw', keyBytes, {name:'AES-GCM'}, false, ['decrypt']);
    const plain = D.decode(await C.decrypt({name:'AES-GCM',iv}, k, ct));
    outRows('wf-enc-out', [['Decrypted plaintext', plain]]);
  } catch(e) { errOut('wf-enc-out', e.message); }
}

// ─── KEY TREE ────────────────────────────────────────────────────────────────

let treeState = { nodes: [], edges: [], expanded: {} };

async function buildTree() {
  const raw = $('tree-seed').value.trim() || 'default';
  const pathStr = $('tree-paths').value.trim();
  const paths = pathStr.split(',').map(s=>s.trim()).filter(Boolean);
  const root = await seedBytes(raw, raw.length===64&&/^[0-9a-f]+$/i.test(raw)?'hex':'pbkdf2');
  const rootHex = toHex(root);

  const nodeMap = {};
  const addNode = (id, label, hex, parentId) => {
    if (!nodeMap[id]) nodeMap[id] = { id, label, hex, children: [] };
    if (parentId && nodeMap[parentId]) nodeMap[parentId].children.push(id);
  };

  addNode('root', raw.length > 20 ? raw.slice(0,18)+'…' : raw, rootHex, null);

  for (const path of paths) {
    let cur = root, parentId = 'root';
    for (const seg of path.split('/').filter(Boolean)) {
      const nodeId = parentId+'/'+seg;
      cur = await hkdfDerive(cur, seg, 'keypear-tree');
      addNode(nodeId, seg, toHex(cur), parentId);
      parentId = nodeId;
    }
  }

  treeState = { nodeMap, rootHex, expanded: treeState.expanded };
  renderTree(nodeMap);
}

function expandAll() { treeState.expanded = {}; Object.keys(treeState.nodeMap||{}).forEach(k=>treeState.expanded[k]=true); renderTree(treeState.nodeMap); }
function collapseAll() { treeState.expanded = {}; renderTree(treeState.nodeMap); }

function renderTree(nodeMap) {
  if (!nodeMap) return;
  const svg = $('tree-svg');
  svg.innerHTML = '';
  const NW=200, NH=64, HX=24, HY=40, GAPX=30, GAPY=20;

  const layout = (id, depth, sibIdx, sibCount) => {
    const node = nodeMap[id];
    if (!node) return;
    node._depth = depth;
    node._sib = sibIdx;
    node._sibCount = sibCount;
    node.children.forEach((cid,i) => layout(cid, depth+1, i, node.children.length));
  };
  layout('root', 0, 0, 1);

  const posMap = {};
  const assignY = (id, ySlot) => {
    const node = nodeMap[id];
    if (!node) return ySlot;
    if (!node.children.length) { posMap[id] = { x: node._depth*(NW+GAPX)+16, y: ySlot*(NH+GAPY)+16 }; return ySlot+1; }
    let slot = ySlot;
    node.children.forEach(cid => { slot = assignY(cid, slot); });
    const firstChild = posMap[node.children[0]];
    const lastChild = posMap[node.children[node.children.length-1]];
    posMap[id] = { x: node._depth*(NW+GAPX)+16, y: (firstChild.y+lastChild.y)/2 };
    return slot;
  };
  const totalSlots = assignY('root', 0);

  const svgW = Math.max(860, (Object.values(nodeMap).reduce((m,n)=>Math.max(m,n._depth),0)+1)*(NW+GAPX)+16);
  const svgH = Math.max(300, totalSlots*(NH+GAPY)+32);
  svg.setAttribute('width', svgW);
  svg.setAttribute('height', svgH);

  const drawEdge = (x1,y1,x2,y2) => {
    const mid = (x1+NW+x2)/2;
    const path = document.createElementNS('http://www.w3.org/2000/svg','path');
    path.setAttribute('d',`M${x1+NW},${y1+NH/2} C${mid},${y1+NH/2} ${mid},${y2+NH/2} ${x2},${y2+NH/2}`);
    path.setAttribute('class','tree-edge');
    svg.appendChild(path);
  };

  const drawNode = (id) => {
    const node = nodeMap[id];
    if (!node) return;
    const {x,y} = posMap[id];
    const exp = treeState.expanded[id];
    const short = node.hex.slice(0,8)+'…'+node.hex.slice(-4);

    node.children.forEach(cid => { const c=posMap[cid]; if(c) drawEdge(x,y,c.x,c.y); });

    const g = document.createElementNS('http://www.w3.org/2000/svg','g');
    g.setAttribute('class','tree-node'+(id==='root'?' root':'')+(treeState.selected===id?' selected':''));
    g.setAttribute('transform',`translate(${x},${y})`);

    const rect = document.createElementNS('http://www.w3.org/2000/svg','rect');
    rect.setAttribute('width',NW); rect.setAttribute('height',NH); rect.setAttribute('rx',6);
    g.appendChild(rect);

    const t1 = document.createElementNS('http://www.w3.org/2000/svg','text');
    t1.setAttribute('x',10); t1.setAttribute('y',18);
    t1.setAttribute('class','node-label'); t1.textContent = node.label;
    g.appendChild(t1);

    const t2 = document.createElementNS('http://www.w3.org/2000/svg','text');
    t2.setAttribute('x',10); t2.setAttribute('y',36);
    t2.setAttribute('class','key-preview'); t2.textContent = exp ? node.hex.slice(0,24)+'…' : short;
    g.appendChild(t2);

    g.addEventListener('click', () => selectNode(id, nodeMap));
    svg.appendChild(g);
    node.children.forEach(drawNode);
  };
  drawNode('root');
}

function selectNode(id, nodeMap) {
  treeState.selected = id;
  treeState.expanded[id] = !treeState.expanded[id];
  renderTree(nodeMap || treeState.nodeMap);
  const node = (nodeMap||treeState.nodeMap)[id];
  if (!node) return;
  $('node-detail').style.display = 'flex';
  $('nd-content').innerHTML = `
    <div class="row" style="gap:6px;flex-wrap:wrap">
      <span class="badge blue">${id}</span>
    </div>` +
    [['Full key (hex)', node.hex, 'wf-dk-seed,wf-enc-key,dv-seed'],
     ['Short preview', node.hex.slice(0,16)+'…']].map(([lbl,val,target])=>`
    <div class="out-block" style="margin-top:8px">
      <div class="out-label">${lbl}
        <span>
          ${target?`<button class="use-btn" onclick="pipe('${escHtml(val)}','${target}')">Use in Workflow</button>`:''}
          <button class="cp-btn" onclick="cp(this,'${escHtml(val)}')">copy</button>
        </span>
      </div>
      <pre>${escHtml(val)}</pre>
    </div>`).join('');
}

// ─── MNEMONIC ────────────────────────────────────────────────────────────────

function genMnemonic() {
  const count = +$('mn-count').value;
  const bytes = crypto.getRandomValues(new Uint8Array(count===24?32:16));
  const bits = Array.from(bytes).map(b=>b.toString(2).padStart(8,'0')).join('');
  const words = Array.from({length:count},(_,i)=>BIP39[parseInt(bits.slice(i*11,(i+1)*11),2)%2048]);
  const phrase = words.join(' ');
  $('mn-words').value = phrase;
  outRows('mn-gen-out', [['Generated mnemonic', phrase, 'mn-words,wf-seed']]);
}

async function mnToSeed() {
  const words = $('mn-words').value.trim();
  const pass = $('mn-pass').value;
  if (!words) return errOut('mn-out','Enter mnemonic words');
  try {
    const base = await C.importKey('raw', E.encode(words), {name:'PBKDF2'}, false, ['deriveBits']);
    const bits = await C.deriveBits({name:'PBKDF2',hash:'SHA-512',salt:E.encode('mnemonic'+pass),iterations:2048}, base, 512);
    const hex = toHex(bits);
    $('wf-seed').value = hex; $('wf-kp-seed').value = hex.slice(0,64); $('wf-dk-seed').value = hex.slice(0,64);
    outRows('mn-out', [['Seed (512-bit hex)', hex, 'wf-seed,wf-kp-seed,wf-dk-seed,tree-seed,dv-seed']]);
  } catch(e) { errOut('mn-out', e.message); }
}

// ─── KEY GEN ─────────────────────────────────────────────────────────────────

async function genKey() {
  const alg = $('kg-alg').value;
  try {
    let rows = [];
    if (alg.startsWith('AES')) {
      const k = await C.generateKey({name:'AES-GCM',length:alg==='AES-256'?256:128},true,['encrypt','decrypt']);
      const raw = await C.exportKey('raw', k);
      rows = [['AES Key (hex)', toHex(raw), 'enc-key,wf-enc-key']];
    } else if (alg.startsWith('RSA')) {
      const len = alg==='RSA-4096'?4096:2048;
      const k = await C.generateKey({name:'RSA-OAEP',modulusLength:len,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
      const pub = await C.exportKey('spki', k.publicKey);
      const priv = await C.exportKey('pkcs8', k.privateKey);
      rows = [['Public Key (PEM)', toPem('PUBLIC KEY',pub), 'enc-key'], ['Private Key (PEM)', toPem('PRIVATE KEY',priv), 'enc-key']];
    } else {
      const isECDH = alg.startsWith('ECDH');
      const curve = alg==='ECDH-P384'?'P-384':'P-256';
      const k = isECDH
        ? await C.generateKey({name:'ECDH',namedCurve:curve},true,['deriveKey','deriveBits'])
        : await C.generateKey({name:'Ed25519'},true,['sign','verify']);
      const pub = await C.exportKey('spki', k.publicKey);
      const priv = await C.exportKey('pkcs8', k.privateKey);
      rows = [['Public Key (PEM)', toPem('PUBLIC KEY',pub), 'enc-key'], ['Private Key (PEM)', toPem('PRIVATE KEY',priv), 'enc-key']];
    }
    outRows('kg-out', rows);
  } catch(e) { errOut('kg-out', e.message); }
}

// ─── ENCRYPT / DECRYPT ───────────────────────────────────────────────────────

function updateEncUI() {
  const m = $('enc-mode').value;
  $('enc-key-label').textContent = m==='aes-pass'?'Password': m==='aes-key'?'AES Key (hex)':'PEM Key (public=encrypt, private=decrypt)';
}

async function aesKeyFromPass(pass, salt) {
  const base = await C.importKey('raw', E.encode(pass), {name:'PBKDF2'}, false, ['deriveKey']);
  return C.deriveKey({name:'PBKDF2',salt,hash:'SHA-256',iterations:100000}, base, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
}

async function doEncrypt() {
  const mode = $('enc-mode').value, key = $('enc-key').value, plain = $('enc-input').value;
  if (!plain||!key) return errOut('enc-out','Fill in both fields');
  try {
    let result;
    if (mode==='aes-pass') {
      const salt=crypto.getRandomValues(new Uint8Array(16)), iv=crypto.getRandomValues(new Uint8Array(12));
      const k=await aesKeyFromPass(key,salt), ct=await C.encrypt({name:'AES-GCM',iv},k,E.encode(plain));
      const out=new Uint8Array(28+ct.byteLength); out.set(salt); out.set(iv,16); out.set(new Uint8Array(ct),28);
      result=btoa(String.fromCharCode(...out));
    } else if (mode==='aes-key') {
      const iv=crypto.getRandomValues(new Uint8Array(12));
      const k=await C.importKey('raw',fromHex(key.replace(/\s/g,'')),{name:'AES-GCM'},false,['encrypt']);
      const ct=await C.encrypt({name:'AES-GCM',iv},k,E.encode(plain));
      const out=new Uint8Array(12+ct.byteLength); out.set(iv); out.set(new Uint8Array(ct),12);
      result=btoa(String.fromCharCode(...out));
    } else {
      const k=await C.importKey('spki',parsePem(key),{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt']);
      result=btoa(String.fromCharCode(...new Uint8Array(await C.encrypt({name:'RSA-OAEP'},k,E.encode(plain)))));
    }
    outRows('enc-out',[['Ciphertext (base64)', result, 'wf-enc-plain,enc-input']]);
  } catch(e) { errOut('enc-out', e.message); }
}

async function doDecrypt() {
  const mode=$('enc-mode').value, key=$('enc-key').value, b64=$('enc-input').value.trim();
  if (!b64||!key) return errOut('enc-out','Fill in both fields');
  try {
    const bytes=Uint8Array.from(atob(b64),c=>c.charCodeAt(0));
    let plain;
    if (mode==='aes-pass') {
      const k=await aesKeyFromPass(key,bytes.slice(0,16));
      plain=D.decode(await C.decrypt({name:'AES-GCM',iv:bytes.slice(16,28)},k,bytes.slice(28)));
    } else if (mode==='aes-key') {
      const k=await C.importKey('raw',fromHex(key.replace(/\s/g,'')),{name:'AES-GCM'},false,['decrypt']);
      plain=D.decode(await C.decrypt({name:'AES-GCM',iv:bytes.slice(0,12)},k,bytes.slice(12)));
    } else {
      const k=await C.importKey('pkcs8',parsePem(key),{name:'RSA-OAEP',hash:'SHA-256'},false,['decrypt']);
      plain=D.decode(await C.decrypt({name:'RSA-OAEP'},k,bytes));
    }
    outRows('enc-out',[['Plaintext', plain]]);
  } catch(e) { errOut('enc-out', e.message); }
}

// ─── DERIVE ──────────────────────────────────────────────────────────────────

function dvMechChange() {
  $('dv-pbkdf2-opts').style.display = $('dv-mech').value==='pbkdf2'?'flex':'none';
}

async function deriveKey() {
  const raw=$('dv-seed').value.trim(), mech=$('dv-mech').value, info=$('dv-info').value||'default';
  if (!raw) return errOut('dv-out','Enter a seed');
  try {
    const bytes = await seedBytes(raw, raw.length>=64&&/^[0-9a-f]+$/i.test(raw)?'hex':'pbkdf2');
    let rows=[];
    if (mech==='hkdf') {
      const out=await hkdfDerive(bytes,info);
      rows=[['Derived Key (HKDF-SHA256)', toHex(out), 'wf-enc-key,enc-key'],['Info',info]];
    } else if (mech==='pbkdf2') {
      const salt=$('dv-salt').value||'encalc', iter=+$('dv-iter').value||100000;
      const base=await C.importKey('raw',bytes,{name:'PBKDF2'},false,['deriveBits']);
      const out=new Uint8Array(await C.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:E.encode(salt),iterations:iter},base,256));
      rows=[['Derived Key (PBKDF2)', toHex(out), 'wf-enc-key,enc-key'],['Salt',salt],['Iterations',String(iter)]];
    } else {
      const nodes=await treeDerive(bytes,info);
      rows=nodes.map((n,i)=>[i===0?'Root':('→ '+n.path), n.hex, i===nodes.length-1?'wf-enc-key,enc-key':null]).filter(Boolean);
    }
    outRows('dv-out', rows);
  } catch(e) { errOut('dv-out', e.message); }
}
