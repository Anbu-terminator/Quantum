// script.js - client-side: fetch server-stored server-encrypted blobs and decrypt client-side
const API_BASE = window.location.origin; // uses same host (http://quantum-5mo6.onrender.com)

function hexToWordArray(hex) { return CryptoJS.enc.Hex.parse(hex); }
function base64ToWordArray(b64) { return CryptoJS.enc.Base64.parse(b64); }

async function fetchLatest() {
  const r = await fetch(`${API_BASE}/api/latest?limit=10`);
  return r.json();
}

async function fetchServerKey(token) {
  const r = await fetch(`${API_BASE}/api/server_key?auth=${encodeURIComponent(token)}`);
  if (!r.ok) throw new Error("server_key fetch failed: " + r.status);
  return r.json();
}

async function fetchQuantumKey(token, key_id) {
  const r = await fetch(`${API_BASE}/api/quantum_key?auth=${encodeURIComponent(token)}&key_id=${encodeURIComponent(key_id)}`);
  if (!r.ok) throw new Error("quantum_key fetch failed: " + r.status);
  return r.json();
}

// decrypt server AES to get original JSON payload (which includes original cipher_b64, key_id, iv)
function decryptServerAES(server_cipher_b64, server_key_hex, server_iv_hex) {
  const key = hexToWordArray(server_key_hex);
  const iv = hexToWordArray(server_iv_hex);
  const cipherWA = base64ToWordArray(server_cipher_b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decryptedWA = CryptoJS.AES.decrypt(cipherParams, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  const plaintext = decryptedWA.toString(CryptoJS.enc.Utf8);
  return plaintext;
}

// decrypt original quantum-encrypted ciphertext (base64) using quantum key hex + iv hex
function decryptQuantumCipher(orig_cipher_b64, quantum_key_hex, iv_hex) {
  const key = hexToWordArray(quantum_key_hex);
  const iv = hexToWordArray(iv_hex);
  const cipherWA = base64ToWordArray(orig_cipher_b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decryptedWA = CryptoJS.AES.decrypt(cipherParams, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  return decryptedWA.toString(CryptoJS.enc.Utf8);
}

document.getElementById('btnFetch').addEventListener('click', async () => {
  const token = document.getElementById('token').value.trim();
  if (!token) { alert('Paste token'); return; }
  const outEl = document.getElementById('out');
  outEl.textContent = "Fetching latest...";
  try {
    const docs = await fetchLatest();
    if (!docs || docs.length === 0) { outEl.textContent = "No stored items yet."; return; }

    // fetch server key once
    const serverKeyResp = await fetchServerKey(token);
    const serverKeyHex = serverKeyResp.server_key;

    const results = [];
    for (const item of docs) {
      try {
        const splain = decryptServerAES(item.server_cipher_b64, serverKeyHex, item.server_iv_hex);
        // splain is JSON string containing cipher_b64, key_id, iv
        const obj = JSON.parse(splain);
        const quantumResp = await fetchQuantumKey(token, obj.key_id || "");
        const qkey = quantumResp.key;
        // decrypt original
        const finalPlain = decryptQuantumCipher(obj.cipher_b64, qkey, obj.iv);
        results.push({
          entry_id: item.entry_id,
          stored_at: new Date(item.stored_at * 1000).toLocaleString(),
          plaintext: JSON.parse(finalPlain)
        });
      } catch (e) {
        results.push({ entry_id: item.entry_id, error: String(e) });
      }
    }
    outEl.textContent = JSON.stringify(results, null, 2);
  } catch (err) {
    outEl.textContent = "Error: " + err;
  }
});
