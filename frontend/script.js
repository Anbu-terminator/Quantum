// script.js - frontend decryption with table display
const API_BASE = window.location.origin;

function hexToWordArray(hex) { return CryptoJS.enc.Hex.parse(hex); }
function base64ToWordArray(b64) { return CryptoJS.enc.Base64.parse(b64); }

async function fetchLatest() {
  const r = await fetch(`${API_BASE}/api/latest?limit=10`);
  return r.json();
}

async function fetchServerKey(token) {
  const r = await fetch(`${API_BASE}/api/server_key?auth=${encodeURIComponent(token)}`);
  if (!r.ok) throw new Error("Server key fetch failed: " + r.status);
  return r.json();
}

async function fetchQuantumKey(token, key_id) {
  const r = await fetch(`${API_BASE}/api/quantum_key?auth=${encodeURIComponent(token)}&key_id=${encodeURIComponent(key_id)}`);
  if (!r.ok) throw new Error("Quantum key fetch failed: " + r.status);
  return r.json();
}

function decryptServerAES(server_cipher_b64, server_key_hex, server_iv_hex) {
  const key = hexToWordArray(server_key_hex);
  const iv = hexToWordArray(server_iv_hex);
  const cipherWA = base64ToWordArray(server_cipher_b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decrypted = CryptoJS.AES.decrypt(cipherParams, key, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  return decrypted.toString(CryptoJS.enc.Utf8);
}

function decryptQuantumCipher(orig_cipher_b64, quantum_key_hex, iv_hex) {
  const key = hexToWordArray(quantum_key_hex);
  const iv = hexToWordArray(iv_hex);
  const cipherWA = base64ToWordArray(orig_cipher_b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decrypted = CryptoJS.AES.decrypt(cipherParams, key, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  return decrypted.toString(CryptoJS.enc.Utf8);
}

// Render results in table
function renderTable(results) {
  const tbody = document.querySelector("#data-table tbody");
  tbody.innerHTML = "";
  results.forEach(item => {
    const tr = document.createElement("tr");
    const sensor = item.sensor_data || {};
    tr.innerHTML = `
      <td>${item.entry_id}</td>
      <td>${item.stored_at || "-"}</td>
      <td>${sensor.temperature !== undefined ? sensor.temperature.toFixed(2) : "-"}</td>
      <td>${sensor.humidity !== undefined ? sensor.humidity.toFixed(2) : "-"}</td>
      <td>${item.error || "-"}</td>
    `;
    tbody.appendChild(tr);
  });
}

document.getElementById('btnFetch').addEventListener('click', async () => {
  const token = document.getElementById('token').value.trim();
  const statusEl = document.getElementById('status');
  if (!token) { alert('Paste ESP_AUTH_TOKEN'); return; }

  statusEl.textContent = "Fetching latest...";
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
        const serverPlain = decryptServerAES(item.server_cipher_b64, serverKeyHex, item.server_iv_hex);
        const obj = JSON.parse(serverPlain);
        const qResp = await fetchQuantumKey(token, obj.key_id);
        const finalPlain = decryptQuantumCipher(obj.cipher_b64, qResp.key, obj.iv);
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
  } catch (err) {
    statusEl.textContent = "Error: " + err;
    renderTable([]);
  }
});
