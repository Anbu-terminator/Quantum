// script.js - browser decrypt pipeline
const API_BASE = "";

function hexToWordArray(hex) { return CryptoJS.enc.Hex.parse(hex); }
function base64ToWordArray(b64) { return CryptoJS.enc.Base64.parse(b64); }

async function fetchLatestStored(limit=10) {
  const r = await fetch(`/api/latest?limit=${limit}`);
  return r.json();
}
async function fetchServerKey(token) {
  const r = await fetch(`/api/server_key?auth=${encodeURIComponent(token)}`);
  if (!r.ok) throw new Error("server_key unauthorized");
  return r.json();
}
async function fetchQuantumKey(token, key_id) {
  const r = await fetch(`/api/quantum_key?auth=${encodeURIComponent(token)}&key_id=${encodeURIComponent(key_id)}`);
  if (!r.ok) throw new Error("quantum_key fetch failed");
  return r.json();
}

function decryptServerAES(s_b64, server_key_hex, server_iv_hex) {
  const key = hexToWordArray(server_key_hex);
  const iv = hexToWordArray(server_iv_hex);
  const cipherWA = base64ToWordArray(s_b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decrypted = CryptoJS.AES.decrypt(cipherParams, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  return decrypted.toString(CryptoJS.enc.Utf8);
}

function decryptQuantumCt(ct_field_str, qkey_hex) {
  // ct_field_str is "IVHEX.B64"
  if (!ct_field_str) return null;
  const parts = ct_field_str.split('.', 2);
  if (parts.length !== 2) return null;
  const ivHex = parts[0];
  const b64 = parts[1];
  const key = hexToWordArray(qkey_hex);
  const iv = hexToWordArray(ivHex);
  const cipherWA = base64ToWordArray(b64);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decrypted = CryptoJS.AES.decrypt(cipherParams, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  return decrypted.toString(CryptoJS.enc.Utf8);
}

document.getElementById('btnFetch').addEventListener('click', async () => {
  const token = document.getElementById('token').value.trim();
  const out = document.getElementById('out');
  if (!token) { alert('Paste ESP_AUTH_TOKEN'); return; }
  out.textContent = 'Fetching...';
  try {
    const stored = await fetchLatestStored(10);
    if (!stored || stored.length === 0) { out.textContent = 'No stored items'; return; }
    const serverKeyResp = await fetchServerKey(token);
    const serverKeyHex = serverKeyResp.server_key;

    const results = [];
    for (const item of stored) {
      try {
        const sPlain = decryptServerAES(item.server_cipher_b64, serverKeyHex, item.server_iv_hex);
        const obj = JSON.parse(sPlain);
        const qresp = await fetchQuantumKey(token, obj.key_id || "");
        const qkeyHex = qresp.key;
        const temp_plain = decryptQuantumCt(obj.cipher_b64 || "", qkeyHex); // NOTE: obj.cipher_b64 holds overall? per our server we used temp_ct etc
        // actually server stored temp_ct in record; parse accordingly:
        const rec = obj;
        const t = decryptQuantumCt(rec.temp_ct || "", qkeyHex);
        const h = decryptQuantumCt(rec.hum_ct || "", qkeyHex);
        const i = decryptQuantumCt(rec.ir_ct || "", qkeyHex);
        results.push({entry_id: item.entry_id, temperature: t, humidity: h, ir: i, received_at: rec.received_at});
      } catch (e) {
        results.push({entry_id: item.entry_id, error: String(e)});
      }
    }
    out.textContent = JSON.stringify(results, null, 2);
  } catch (e) {
    out.textContent = "Error: " + e;
  }
});
