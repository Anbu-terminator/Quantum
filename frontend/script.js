// script.js - frontend decryption with session-key derivation
const API_BASE = window.location.origin;

function hexToWordArray(hex) { return CryptoJS.enc.Hex.parse(hex); }
function base64ToWordArray(b64) { return CryptoJS.enc.Base64.parse(b64); }

async function fetchLatest() {
  const r = await fetch(`${API_BASE}/api/latest?limit=10`);
  if (!r.ok) throw new Error("latest fetch failed: " + r.status);
  return r.json();
}

async function fetchServerKey(token) {
  const r = await fetch(`${API_BASE}/api/server_key?auth=${encodeURIComponent(token)}`);
  if (!r.ok) {
    const txt = await r.text().catch(()=>"");
    throw new Error("Server key fetch failed: " + r.status + " " + txt);
  }
  return r.json();
}

async function fetchQuantumKey(token, key_id) {
  const r = await fetch(`${API_BASE}/api/quantum_key?auth=${encodeURIComponent(token)}&key_id=${encodeURIComponent(key_id)}`);
  if (!r.ok) {
    const txt = await r.text().catch(()=>"");
    throw new Error("Quantum key fetch failed: " + r.status + " " + txt);
  }
  return r.json();
}

function decryptServerAES(server_cipher_b64, server_key_hex, server_iv_hex) {
  const key = hexToWordArray(server_key_hex);
  const iv = hexToWordArray(server_iv_hex);
  const cipherWA = base64ToWordArray(server_cipher_b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decrypted = CryptoJS.AES.decrypt(cipherParams, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  return decrypted.toString(CryptoJS.enc.Utf8);
}

function deriveSessionKeyHex(qkey_hex, nonce_hex) {
  // treat hex strings as bytes: compute SHA256(qkey_bytes || nonce_bytes)
  const concatWA = CryptoJS.enc.Hex.parse(qkey_hex + nonce_hex);
  const hashHex = CryptoJS.SHA256(concatWA).toString(CryptoJS.enc.Hex);
  return hashHex.substring(0, 32); // first 16 bytes = 32 hex chars
}

function decryptOriginalWithDerivedKey(orig_cipher_b64, derived_key_hex, iv_hex) {
  const keyWA = hexToWordArray(derived_key_hex);
  const ivWA = hexToWordArray(iv_hex);
  const cipherWA = base64ToWordArray(orig_cipher_b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decrypted = CryptoJS.AES.decrypt(cipherParams, keyWA, { iv: ivWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  return decrypted.toString(CryptoJS.enc.Utf8);
}

function renderTable(results) {
  const tbody = document.querySelector("#data-table tbody");
  tbody.innerHTML = "";
  for (const item of results) {
    const tr = document.createElement("tr");
    const sensor = item.sensor_data || {};
    tr.innerHTML = `
      <td>${item.entry_id}</td>
      <td>${item.stored_at || "-"}</td>
      <td>${sensor.temperature !== undefined ? Number(sensor.temperature).toFixed(2) : "-"}</td>
      <td>${sensor.humidity !== undefined ? Number(sensor.humidity).toFixed(2) : "-"}</td>
      <td>${sensor.ir !== undefined ? sensor.ir : "-"}</td>
      <td>${item.error ? item.error : "-"}</td>
    `;
    tbody.appendChild(tr);
  }
}

document.getElementById('btnFetch').addEventListener('click', async () => {
  const token = document.getElementById('token').value.trim();
  const statusEl = document.getElementById('status');
  const outEl = document.getElementById('out');
  if (!token) { alert('Paste ESP_AUTH_TOKEN'); return; }

  statusEl.textContent = "Fetching latest...";
  outEl.textContent = "";

  try {
    const docs = await fetchLatest();
    if (!docs || docs.length === 0) {
      statusEl.textContent = "No stored items yet.";
      renderTable([]);
      return;
    }

    const serverKeyResp = await fetchServerKey(token);
    const serverKeyHex = serverKeyResp.server_key;

    const results = [];
    for (const item of docs) {
      try {
        // decrypt server layer
        const serverPlain = decryptServerAES(item.server_cipher_b64, serverKeyHex, item.server_iv_hex);
        const obj = JSON.parse(serverPlain); // { cipher_b64, key_id, iv, nonce, ... }

        // fetch quantum key
        const qResp = await fetchQuantumKey(token, obj.key_id);
        const qkey_hex = qResp.key; // hex string

        if (!obj.nonce) throw new Error("missing nonce");

        // derive session key hex
        const derived_hex = deriveSessionKeyHex(qkey_hex, obj.nonce);

        // decrypt original
        const finalPlain = decryptOriginalWithDerivedKey(obj.cipher_b64, derived_hex, obj.iv);
        results.push({
          entry_id: item.entry_id,
          stored_at: new Date(item.stored_at * 1000).toLocaleString(),
          sensor_data: JSON.parse(finalPlain)
        });
      } catch (e) {
        results.push({ entry_id: item.entry_id, error: String(e) });
      }
    }

    renderTable(results);
    statusEl.textContent = `Fetched ${results.length} records.`;
    outEl.textContent = JSON.stringify(results, null, 2);
  } catch (err) {
    statusEl.textContent = "Error: " + err;
    outEl.textContent = String(err);
    renderTable([]);
  }
});
