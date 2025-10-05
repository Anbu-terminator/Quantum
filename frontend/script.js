// script.js
const API_BASE = window.location.origin;

function hexToWA(hex){ return CryptoJS.enc.Hex.parse(hex); }
function base64ToWA(b64){ return CryptoJS.enc.Base64.parse(b64); }

async function fetchLatest() {
  const r = await fetch(`${API_BASE}/api/latest`);
  if (!r.ok) throw new Error("latest fetch failed: " + r.status);
  return r.json();
}

function deriveSessionKeyHex(qkey_hex, nonce_hex){
  // qkey_hex and nonce_hex are hex strings
  const concat = CryptoJS.enc.Hex.parse(qkey_hex + nonce_hex);
  const sha = CryptoJS.SHA256(concat).toString(CryptoJS.enc.Hex);
  return sha.substring(0,32); // first 16 bytes
}

function decryptBase64AES_CBC(cipher_b64, key_hex, iv_hex){
  const keyWA = hexToWA(key_hex);
  const ivWA = hexToWA(iv_hex);
  const cipherWA = base64ToWA(cipher_b64);
  const params = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decrypted = CryptoJS.AES.decrypt(params, keyWA, { iv: ivWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  if(!decrypted || decrypted.sigBytes === 0) throw new Error("Decryption yielded no bytes");
  const txt = decrypted.toString(CryptoJS.enc.Utf8);
  if(!txt) throw new Error("Decrypted text is empty or not valid UTF-8");
  return txt;
}

function renderTable(rows){
  const tbody = document.querySelector("#data-table tbody");
  tbody.innerHTML = "";
  for(const r of rows){
    const s = r.sensor || {};
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${r.entry_id}</td><td>${r.created_at||"-"}</td>
      <td>${s.temperature!==undefined?Number(s.temperature).toFixed(2):"-"}</td>
      <td>${s.humidity!==undefined?Number(s.humidity).toFixed(2):"-"}</td>
      <td>${s.ir!==undefined?s.ir:"-"}</td>
      <td>${r.status||"-"}</td>`;
    tbody.appendChild(tr);
  }
}

document.getElementById('btnFetch').addEventListener('click', async () => {
  const token = document.getElementById('token').value.trim();
  const statusEl = document.getElementById('status');
  const outEl = document.getElementById('out');
  statusEl.textContent = "Fetching...";
  outEl.textContent = "";

  try{
    const feeds = await fetchLatest();
    const results = [];

    for(const f of feeds){
      if(!f.entry_id) continue;

      // validate token sent in field4
      if((f.field4||"").trim() !== token){
        results.push({ entry_id: f.entry_id, status: "bad_token" });
        continue;
      }

      const cipher_b64 = (f.field1||"").trim();
      const key_id = (f.field2||"").trim();
      const iv_hex = (f.field3||"").trim();
      const nonce_hex = (f.field5||"").trim();

      if(!cipher_b64 || !iv_hex || !nonce_hex){
        results.push({ entry_id: f.entry_id, status: "missing_fields" });
        continue;
      }

      if(!f.key_found || !f.qkey_hex){
        // exact QKey not present on server rotator — do not attempt decrypt
        results.push({ entry_id: f.entry_id, status: "key_not_found_on_server" });
        continue;
      }

      try{
        const qkey_hex = f.qkey_hex;
        const derived_hex = deriveSessionKeyHex(qkey_hex, nonce_hex);
        const plain = decryptBase64AES_CBC(cipher_b64, derived_hex, iv_hex);
        const sensor = JSON.parse(plain);
        results.push({ entry_id: f.entry_id, created_at: f.created_at, sensor, status: "ok", used_key_id: key_id });
      } catch(e){
        results.push({ entry_id: f.entry_id, status: "decrypt_error: " + (e.message || String(e)) });
      }
    }

    renderTable(results);
    outEl.textContent = JSON.stringify(results, null, 2);
    statusEl.textContent = `Fetched ${results.length} items`;
  } catch(err){
    statusEl.textContent = "Error: " + err;
    outEl.textContent = String(err);
  }
});
