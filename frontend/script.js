// script.js — stable AES decryption + UTF-8 fix
const API_BASE = window.location.origin;

// ---------- HELPERS ----------
function hexToWordArray(hex) {
  return CryptoJS.enc.Hex.parse(hex);
}
function base64ToWordArray(b64) {
  return CryptoJS.enc.Base64.parse(b64);
}

// --- SAFE WORDARRAY → BYTES ---
function wordArrayToUint8Array(wordArray) {
  const words = wordArray.words;
  let sigBytes = wordArray.sigBytes;
  // Defensive clamp
  if (!sigBytes || sigBytes < 0) sigBytes = words.length * 4;
  const u8 = new Uint8Array(sigBytes);
  let idx = 0;
  for (let i = 0; i < words.length && idx < sigBytes; i++) {
    const w = words[i];
    u8[idx++] = (w >> 24) & 0xff;
    if (idx >= sigBytes) break;
    u8[idx++] = (w >> 16) & 0xff;
    if (idx >= sigBytes) break;
    u8[idx++] = (w >> 8) & 0xff;
    if (idx >= sigBytes) break;
    u8[idx++] = w & 0xff;
  }
  return u8;
}

// Decode WordArray → string (handles binary safely)
function decodeUtf8FromWordArray(wa) {
  try {
    const bytes = wordArrayToUint8Array(wa);
    return new TextDecoder("utf-8").decode(bytes);
  } catch (e) {
    console.warn("UTF-8 decode fallback:", e);
    return "";
  }
}

// ---------- NETWORK ----------
async function fetchLatest() {
  const r = await fetch(`${API_BASE}/api/latest?limit=10`);
  return r.json();
}
async function fetchServerKey(token) {
  const r = await fetch(`${API_BASE}/api/server_key?auth=${encodeURIComponent(token)}`);
  if (!r.ok) throw new Error("Server key fetch failed");
  return r.json();
}
async function fetchQuantumKey(token) {
  const r = await fetch(`${API_BASE}/api/quantum_key?auth=${encodeURIComponent(token)}`);
  if (!r.ok) throw new Error("Quantum key fetch failed");
  return r.json();
}

// ---------- DECRYPT ----------
function decryptAES(cipher_b64, key_hex, iv_hex) {
  const key = hexToWordArray(key_hex);
  const iv = hexToWordArray(iv_hex);
  const cipher = base64ToWordArray(cipher_b64);
  const params = CryptoJS.lib.CipherParams.create({ ciphertext: cipher });
  const decryptedWA = CryptoJS.AES.decrypt(params, key, {
    iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });
  return decodeUtf8FromWordArray(decryptedWA);
}

// ---------- UI ----------
function renderTable(rows) {
  const tbody = document.querySelector("#data-table tbody");
  tbody.innerHTML = "";
  rows.forEach((r) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${r.entry_id}</td>
      <td>${r.stored_at || "-"}</td>
      <td>${r.sensor_data?.temperature ?? "-"}</td>
      <td>${r.sensor_data?.humidity ?? "-"}</td>
      <td>${r.sensor_data?.ir ?? "-"}</td>
      <td>${r.error ? `<pre style="color:#b00">${r.error}</pre>` : "OK"}</td>`;
    tbody.appendChild(tr);
  });
}

// ---------- MAIN ----------
document.getElementById("btnFetch").addEventListener("click", async () => {
  const token = document.getElementById("token").value.trim();
  const status = document.getElementById("status");
  if (!token) return alert("Enter ESP_AUTH_TOKEN first");

  status.textContent = "Fetching latest...";
  try {
    const docs = await fetchLatest();
    if (!docs || docs.length === 0) {
      renderTable([]);
      status.textContent = "No records yet";
      return;
    }

    const serverKeyObj = await fetchServerKey(token);
    const serverKeyHex = serverKeyObj.server_key;
    if (!serverKeyHex) throw new Error("Missing server key");

    const out = [];
    for (const item of docs) {
      try {
        const outerPlain = decryptAES(
          item.server_cipher_b64,
          serverKeyHex,
          item.server_iv_hex
        );
        const outerJSON = JSON.parse(outerPlain);
        const qResp = await fetchQuantumKey(token);
        const qKey = qResp.key;
        if (!qKey) throw new Error("Missing quantum key");
        const innerPlain = decryptAES(outerJSON.cipher_b64, qKey, outerJSON.iv);
        const sensor = JSON.parse(innerPlain);
        out.push({
          entry_id: item.entry_id,
          stored_at: new Date(item.stored_at * 1000).toLocaleString(),
          sensor_data: sensor,
        });
      } catch (e) {
        console.error("Decrypt fail", item.entry_id, e);
        out.push({ entry_id: item.entry_id, error: e.message || String(e) });
      }
    }

    renderTable(out);
    status.textContent = `Fetched ${out.length} entries`;
  } catch (e) {
    console.error(e);
    status.textContent = "Error: " + e.message;
    renderTable([]);
  }
});
