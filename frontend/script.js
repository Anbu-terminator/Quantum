// script.js - frontend decryption with table display
const API_BASE = window.location.origin;

function hexToWordArray(hex) { return CryptoJS.enc.Hex.parse(hex); }
function base64ToWordArray(b64) { return CryptoJS.enc.Base64.parse(b64); }

// Convert a CryptoJS WordArray to Uint8Array
function wordArrayToUint8Array(wordArray) {
  // Source adapted for reliability
  const words = wordArray.words;
  const sigBytes = wordArray.sigBytes;
  const u8 = new Uint8Array(sigBytes);
  let index = 0;
  for (let i = 0; i < words.length; i++) {
    let word = words[i];
    // write 4 bytes (big-endian) from word into u8 but don't overflow sigBytes
    for (let b = 3; b >= 0; b--) {
      if (index >= sigBytes) break;
      u8[index++] = (word >> (8 * b)) & 0xFF;
    }
  }
  return u8;
}

async function fetchLatest() {
  const r = await fetch(`${API_BASE}/api/latest?limit=10`);
  return r.json();
}

async function fetchServerKey(token) {
  const r = await fetch(`${API_BASE}/api/server_key?auth=${encodeURIComponent(token)}`);
  if (!r.ok) throw new Error("Server key fetch failed: " + r.status);
  return r.json();
}

async function fetchQuantumKey(token) {
  const r = await fetch(`${API_BASE}/api/quantum_key?auth=${encodeURIComponent(token)}`);
  if (!r.ok) throw new Error("Quantum key fetch failed: " + r.status);
  return r.json();
}

function decryptServerAES(server_cipher_b64, server_key_hex, server_iv_hex) {
  // server_key_hex -- 32 hex chars representing 16 bytes
  const key = hexToWordArray(server_key_hex);
  const iv = hexToWordArray(server_iv_hex);
  const cipherWA = base64ToWordArray(server_cipher_b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });

  const decryptedWA = CryptoJS.AES.decrypt(cipherParams, key, {
    iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });

  // Convert WordArray -> Uint8Array -> decode UTF-8 safely
  const bytes = wordArrayToUint8Array(decryptedWA);
  const decoder = new TextDecoder("utf-8");
  const txt = decoder.decode(bytes);
  return txt;
}

function decryptQuantumCipher(orig_cipher_b64, quantum_key_hex, iv_hex) {
  const key = hexToWordArray(quantum_key_hex);
  const iv = hexToWordArray(iv_hex);
  const cipherWA = base64ToWordArray(orig_cipher_b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });

  const decryptedWA = CryptoJS.AES.decrypt(cipherParams, key, {
    iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });

  const bytes = wordArrayToUint8Array(decryptedWA);
  const decoder = new TextDecoder("utf-8");
  const txt = decoder.decode(bytes);
  return txt;
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
      <td>${sensor.temperature ?? "-"}</td>
      <td>${sensor.humidity ?? "-"}</td>
      <td>${sensor.ir ?? "-"}</td>
      <td>${item.error ? `<pre style="color:#b00">${item.error}</pre>` : "OK"}</td>
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
    if (!serverKeyHex) throw new Error("server_key missing in response");

    const results = [];
    for (const item of docs) {
      try {
        // Decrypt the server-layer AES to obtain the payload JSON:
        // payload = { "cipher_b64": "...", "key_id":"...", "iv":"...", ... }
        const serverPlain = decryptServerAES(item.server_cipher_b64, serverKeyHex, item.server_iv_hex);
        let obj;
        try { obj = JSON.parse(serverPlain); }
        catch (e) { throw new Error("Server payload JSON parse error: " + e.message); }

        // Fetch the quantum key if needed (we pass the auth token)
        const qResp = await fetchQuantumKey(token);
        if (!qResp.key) throw new Error("quantum key missing from server");

        // Decrypt the inner (quantum) ciphertext using the quantum key + iv
        const finalPlain = decryptQuantumCipher(obj.cipher_b64, qResp.key, obj.iv);

        // finalPlain should be the sensor JSON
        results.push({
          entry_id: item.entry_id,
          stored_at: new Date(item.stored_at * 1000).toLocaleString(),
          sensor_data: JSON.parse(finalPlain)
        });
      } catch (e) {
        // Collect per-entry errors so the UI shows which entries failed and why
        console.error("Entry", item.entry_id, "decrypt error:", e);
        results.push({ entry_id: item.entry_id, error: String(e) });
      }
    }
    renderTable(results);
    statusEl.textContent = `Fetched ${results.length} records.`;
  } catch (err) {
    console.error(err);
    statusEl.textContent = "Error: " + err;
    renderTable([]);
  }
});
