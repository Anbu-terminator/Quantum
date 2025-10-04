// script.js (updated)
const API_BASE = window.location.origin;

function hexToWordArray(hex) { return CryptoJS.enc.Hex.parse(hex); }
function base64ToWordArray(b64) { return CryptoJS.enc.Base64.parse(b64); }

async function fetchLatest() {
  const r = await fetch(`${API_BASE}/api/latest?limit=20`);
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

function decryptServerAES_base64(server_cipher_b64, server_key_hex, server_iv_hex) {
  // base64 -> WordArray -> decrypt with hex key + hex iv
  const keyWA = hexToWordArray(server_key_hex);
  const ivWA = hexToWordArray(server_iv_hex);
  const cipherWA = base64ToWordArray(server_cipher_b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decryptedWA = CryptoJS.AES.decrypt(cipherParams, keyWA, { iv: ivWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  if (!decryptedWA || decryptedWA.sigBytes === 0) {
    throw new Error("Server unwrap produced empty/invalid bytes");
  }
  const txt = decryptedWA.toString(CryptoJS.enc.Utf8);
  if (!txt) throw new Error("Server unwrap yielded non-UTF8 or empty string");
  return txt;
}

function deriveSessionKeyHex(qkey_hex, nonce_hex) {
  // SHA256(qkey_bytes || nonce_bytes) and take first 16 bytes (32 hex chars)
  const concatWA = CryptoJS.enc.Hex.parse(qkey_hex + nonce_hex);
  const hashHex = CryptoJS.SHA256(concatWA).toString(CryptoJS.enc.Hex);
  return hashHex.substring(0, 32);
}

function decryptOriginalWithDerivedKey_base64(orig_cipher_b64, derived_key_hex, iv_hex) {
  const keyWA = hexToWordArray(derived_key_hex);
  const ivWA = hexToWordArray(iv_hex);
  const cipherWA = base64ToWordArray(orig_cipher_b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decryptedWA = CryptoJS.AES.decrypt(cipherParams, keyWA, { iv: ivWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  if (!decryptedWA || decryptedWA.sigBytes === 0) {
    throw new Error("Original unwrap produced empty/invalid bytes (likely wrong key/iv)");
  }
  const txt = decryptedWA.toString(CryptoJS.enc.Utf8);
  if (!txt) throw new Error("Original unwrap yielded non-UTF8 or empty string");
  return txt;
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
        // 1) Unwrap server encryption (server_cipher_b64 is base64 text)
        const serverPlain = decryptServerAES_base64(item.server_cipher_b64, serverKeyHex, item.server_iv_hex);
        const obj = JSON.parse(serverPlain); // obj: { cipher_b64, key_id, iv, nonce, qkey_hex, ... }

        // 2) Get qkey_hex: prefer qkey_hex embedded in stored original payload; fallback to API
        let qkey_hex = obj.qkey_hex;
        if (!qkey_hex || qkey_hex.length < 32) {
          if (!obj.key_id) throw new Error("no qkey_hex in server payload and no key_id to fetch");
          const qResp = await fetchQuantumKey(token, obj.key_id);
          qkey_hex = qResp.key;
        }

        if (!obj.nonce) throw new Error("missing nonce in stored payload");

        // 3) derive session key and decrypt original ciphertext (base64)
        const derived_hex = deriveSessionKeyHex(qkey_hex, obj.nonce);
        const finalPlain = decryptOriginalWithDerivedKey_base64(obj.cipher_b64, derived_hex, obj.iv);

        results.push({
          entry_id: item.entry_id,
          stored_at: new Date(item.stored_at * 1000).toLocaleString(),
          sensor_data: JSON.parse(finalPlain)
        });
      } catch (e) {
        // keep error message concise but include inner message
        results.push({ entry_id: item.entry_id, error: "Error: " + (e && e.message ? e.message : String(e)) });
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
