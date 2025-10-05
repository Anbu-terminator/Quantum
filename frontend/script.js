// script.js
const API_BASE = window.location.origin;

function hexToWordArray(hex) { return CryptoJS.enc.Hex.parse(hex); }
function base64ToWordArray(b64) { return CryptoJS.enc.Base64.parse(b64); }

async function fetchLatest() {
  const r = await fetch(`${API_BASE}/api/latest?limit=20`);
  if (!r.ok) throw new Error("latest fetch failed: " + r.status);
  return r.json();
}

function deriveSessionKeyHex(qkey_hex, nonce_hex) {
  const concatWA = CryptoJS.enc.Hex.parse(qkey_hex + nonce_hex);
  const hashHex = CryptoJS.SHA256(concatWA).toString(CryptoJS.enc.Hex);
  return hashHex.substring(0, 32);
}

function decryptBase64AES_CBC(cipher_b64, key_hex, iv_hex) {
  const keyWA = hexToWordArray(key_hex);
  const ivWA = hexToWordArray(iv_hex);
  const cipherWA = base64ToWordArray(cipher_b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decryptedWA = CryptoJS.AES.decrypt(cipherParams, keyWA, { iv: ivWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  if (!decryptedWA || decryptedWA.sigBytes === 0) throw new Error("Decryption produced no bytes");
  const txt = decryptedWA.toString(CryptoJS.enc.Utf8);
  if (!txt) throw new Error("Decrypted text is empty or not valid UTF-8");
  return txt;
}

function renderTable(results) {
  const tbody = document.querySelector("#data-table tbody");
  tbody.innerHTML = "";
  for (const item of results) {
    const tr = document.createElement("tr");
    const s = item.sensor || {};
    tr.innerHTML = `
      <td>${item.entry_id}</td>
      <td>${item.created_at || "-"}</td>
      <td>${s.temperature !== undefined ? Number(s.temperature).toFixed(2) : "-"}</td>
      <td>${s.humidity !== undefined ? Number(s.humidity).toFixed(2) : "-"}</td>
      <td>${s.ir !== undefined ? s.ir : "-"}</td>
      <td>${item.status || "-"}</td>
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
    const feeds = await fetchLatest();
    const results = [];

    for (const f of feeds) {
      if (!f.entry_id) continue;

      // verify token
      if ((f.field4 || "").trim() !== token) {
        results.push({ entry_id: f.entry_id, status: "bad_token" });
        continue;
      }

      const cipher_b64 = (f.field1 || "").trim();
      const iv_hex = (f.field3 || "").trim();
      const nonce_hex = (f.field5 || "").trim();
      const qkey_hex = f.qkey_hex;
      const key_used = f.key_used; // "exact" or "fallback" or null

      if (!cipher_b64 || !iv_hex || !nonce_hex) {
        results.push({ entry_id: f.entry_id, status: "missing_fields" });
        continue;
      }

      if (!qkey_hex) {
        results.push({ entry_id: f.entry_id, status: "no_key_available" });
        continue;
      }

      try {
        const derived_hex = deriveSessionKeyHex(qkey_hex, nonce_hex);
        const plain = decryptBase64AES_CBC(cipher_b64, derived_hex, iv_hex);
        const sensor = JSON.parse(plain);
        results.push({ entry_id: f.entry_id, created_at: f.created_at, sensor, status: `ok (${key_used||'unknown'})` });
      } catch (e) {
        results.push({ entry_id: f.entry_id, status: `decrypt_error (${key_used||'unknown'}): ${e.message || e}` });
      }
    }

    renderTable(results);
    outEl.textContent = JSON.stringify(results, null, 2);
    statusEl.textContent = `Processed ${results.length} entries.`;
  } catch (err) {
    statusEl.textContent = "Error: " + err;
    outEl.textContent = String(err);
  }
});
