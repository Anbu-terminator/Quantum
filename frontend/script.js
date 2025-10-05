// script.js - decrypt directly from ThingSpeak entries (client-side)
const API_BASE = window.location.origin;

function hexToWordArray(hex) { return CryptoJS.enc.Hex.parse(hex); }
function base64ToWordArray(b64) { return CryptoJS.enc.Base64.parse(b64); }

// fetch ThingSpeak entries via server proxy
async function fetchLatestFeeds() {
  const r = await fetch(`${API_BASE}/api/latest`);
  if (!r.ok) throw new Error("Fetch latest failed: " + r.status);
  return r.json();
}

async function fetchQuantumKey(token, key_id = "") {
  // if key_id provided, request that key, otherwise get current
  const url = `${API_BASE}/api/quantum_key?auth=${encodeURIComponent(token)}${key_id ? "&key_id="+encodeURIComponent(key_id):""}`;
  const r = await fetch(url);
  const text = await r.text();
  if (!r.ok) throw new Error("Quantum key fetch failed: " + r.status + " " + text);
  return JSON.parse(text);
}

// derive session key hex (first 16 bytes = 32 hex chars)
function deriveSessionKeyHex(qkey_hex, nonce_hex) {
  // qkey_hex and nonce_hex are hex strings representing raw bytes
  const concatWA = CryptoJS.enc.Hex.parse(qkey_hex + nonce_hex);
  const sha = CryptoJS.SHA256(concatWA).toString(CryptoJS.enc.Hex);
  return sha.substring(0, 32);
}

function decryptAESBase64WithHexKey(cipher_b64, key_hex, iv_hex) {
  const keyWA = hexToWordArray(key_hex);
  const ivWA = hexToWordArray(iv_hex);
  const cipherWA = base64ToWordArray(cipher_b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decryptedWA = CryptoJS.AES.decrypt(cipherParams, keyWA, { iv: ivWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  if (!decryptedWA || decryptedWA.sigBytes === 0) throw new Error("Decryption failed or produced zero bytes");
  const txt = decryptedWA.toString(CryptoJS.enc.Utf8);
  if (!txt) throw new Error("Decoded plaintext is empty or not valid UTF-8");
  return txt;
}

function renderTable(items) {
  const tbody = document.querySelector("#data-table tbody");
  tbody.innerHTML = "";
  for (const it of items) {
    const tr = document.createElement("tr");
    const s = it.sensor || {};
    tr.innerHTML = `
      <td>${it.entry_id}</td>
      <td>${it.created_at || "-"}</td>
      <td>${s.temperature !== undefined ? Number(s.temperature).toFixed(2) : "-"}</td>
      <td>${s.humidity !== undefined ? Number(s.humidity).toFixed(2) : "-"}</td>
      <td>${s.ir !== undefined ? s.ir : "-"}</td>
      <td>${it.status || "-"}</td>
    `;
    tbody.appendChild(tr);
  }
}

document.getElementById('btnFetch').addEventListener('click', async () => {
  const token = document.getElementById('token').value.trim();
  const statusEl = document.getElementById('status');
  const outEl = document.getElementById('out');
  if (!token) { alert("Paste ESP_AUTH_TOKEN"); return; }

  statusEl.textContent = "Fetching ThingSpeak...";
  outEl.textContent = "";

  try {
    const feeds = await fetchLatestFeeds();
    const results = [];

    for (const f of feeds) {
      // skip empty rows
      if (!f.entry_id) continue;

      // quick validation: token should match (the ESP included token in field4)
      if ((f.field4 || "").trim() !== token) {
        results.push({ entry_id: f.entry_id, status: "bad_token" });
        continue;
      }

      const cipher_b64 = (f.field1 || "").trim();
      const key_id = (f.field2 || "").trim();
      const iv_hex = (f.field3 || "").trim();
      const nonce_hex = (f.field5 || "").trim();

      if (!cipher_b64 || !iv_hex || !nonce_hex) {
        results.push({ entry_id: f.entry_id, status: "missing_fields" });
        continue;
      }

      try {
        // fetch quantum key (by id if provided; else get current)
        let qresp;
        try {
          qresp = await fetchQuantumKey(token, key_id || "");
        } catch (e) {
          // If key_id was requested and server returns 404, try getting current key as fallback
          if (key_id) {
            qresp = await fetchQuantumKey(token, ""); // try current
          } else {
            throw e;
          }
        }
        // qresp.key is hex string
        const qkey_hex = qresp.key;
        if (!qkey_hex) throw new Error("quantum key missing in response");

        // derive session key and decrypt
        const derived_hex = deriveSessionKeyHex(qkey_hex, nonce_hex);
        const plain = decryptAESBase64WithHexKey(cipher_b64, derived_hex, iv_hex);
        const sensor = JSON.parse(plain);

        results.push({
          entry_id: f.entry_id,
          created_at: f.created_at,
          sensor,
          status: "ok"
        });
      } catch (err) {
        results.push({ entry_id: f.entry_id, status: "decrypt_error: " + (err && err.message ? err.message : String(err)) });
      }
    }

    renderTable(results);
    statusEl.textContent = `Fetched ${results.length} feeds`;
    outEl.textContent = JSON.stringify(results, null, 2);
  } catch (err) {
    statusEl.textContent = "Error: " + err;
    outEl.textContent = String(err);
  }
});
