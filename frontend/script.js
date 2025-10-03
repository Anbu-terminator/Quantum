// script.js — client-side decryption demo
async function fetchLatest(limit=10){
  const resp = await fetch('/api/latest?limit='+limit);
  return resp.json();
}

function hexToWordArray(hex) {
  return CryptoJS.enc.Hex.parse(hex);
}

function base64ToWordArray(b64) {
  return CryptoJS.enc.Base64.parse(b64);
}

function decryptWithKeyBase64(cipher_b64, key_hex, iv_hex){
  const keyWA = hexToWordArray(key_hex);
  const ivWA = hexToWordArray(iv_hex);
  const cipherWA = base64ToWordArray(cipher_b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ciphertext: cipherWA});
  const plainWA = CryptoJS.AES.decrypt(cipherParams, keyWA, { iv: ivWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  return plainWA.toString(CryptoJS.enc.Utf8);
}

async function renderList(){
  const arr = await fetchLatest(10);
  const list = document.getElementById('list');
  list.innerHTML = '';
  if(!arr || arr.length===0){ list.innerHTML = '<p>No ciphertexts yet.</p>'; return; }
  arr.forEach(item=>{
    const p = document.createElement('p');
    const t = new Date(item.ts*1000 || Date.now()).toLocaleString();
    p.innerHTML = `<strong>key_id</strong>: ${item.key_id || ''} <br><small class="muted">${t}</small>`;
    list.appendChild(p);
  });
}

document.getElementById('fetchKey').addEventListener('click', async ()=>{
  const token = document.getElementById('token').value.trim();
  if(!token){ alert('Enter token'); return; }
  try{
    const resp = await fetch(`/api/quantum_key?auth=${encodeURIComponent(token)}`);
    if(!resp.ok){ alert('Key fetch failed: '+resp.status); return; }
    const j = await resp.json();
    document.getElementById('keyInfo').innerText = `key_id: ${j.key_id}\nkey(hex): ${j.key}\niv(hex): ${j.iv}`;
    window._quantum_key = j; // store globally for decryptAll
  }catch(e){ alert('Error: '+e); }
});

document.getElementById('decryptAll').addEventListener('click', async ()=>{
  if(!window._quantum_key){ alert('Fetch quantum key first'); return; }
  const arr = await fetchLatest(10);
  const out = [];
  for(const item of arr){
    try{
      const pt = decryptWithKeyBase64(item.cipher_b64, window._quantum_key.key, item.iv);
      out.push({key_id:item.key_id, plaintext: pt, ts: item.ts});
    }catch(e){
      out.push({key_id:item.key_id, error: String(e)});
    }
  }
  document.getElementById('plaintext').innerText = JSON.stringify(out, null, 2);
});

renderList();
setInterval(renderList, 5000);
