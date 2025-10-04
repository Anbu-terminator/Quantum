// script.js - Decrypt sensor entries using session key derived exactly like the Arduino sketch
// Requirements: CryptoJS loaded on the page before this script

const API_BASE = window.location.origin; // adjust if server at different host

// ---------------------- Utilities ----------------------
function isHex(s) { return typeof s === "string" && /^[0-9a-fA-F]+$/.test(s); }
function isBase64(s) { return typeof s === "string" && /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.test(s.replace(/\s+/g,'')); }

function cleanHex(hex) { if (!hex) return ""; return hex.replace(/[^0-9a-fA-F]/g, ""); }
function hexToUint8(hex) {
  const h = cleanHex(hex);
  const n = Math.floor(h.length/2);
  const u = new Uint8Array(n);
  for (let i=0;i<n;i++) u[i] = parseInt(h.substr(i*2,2),16);
  return u;
}
function base64ToUint8(b64) {
  const bin = atob(b64);
  const u = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) u[i] = bin.charCodeAt(i);
  return u;
}
function utf8ToUint8(s) { return new TextEncoder().encode(s || ""); }

function keyStringToUint8(keyStr) {
  if (!keyStr) return null;
  keyStr = keyStr.trim();
  // if hex-like and long enough, use hex
  const cleaned = cleanHex(keyStr);
  if (cleaned.length >= 2 && cleaned.length === keyStr.length) {
    // looks hex
    return hexToUint8(cleaned);
  }
  // try base64
  if (isBase64(keyStr)) return base64ToUint8(keyStr);
  // fallback: treat as utf8
  return utf8ToUint8(keyStr);
}

// uint8array <-> CryptoJS WordArray
function uint8ToWordArray(u8) {
  const words = [];
  for (let i=0;i<u8.length;i+=4) {
    words.push(
      ((u8[i]||0) << 24) |
      ((u8[i+1]||0) << 16) |
      ((u8[i+2]||0) << 8) |
      ((u8[i+3]||0))
    );
  }
  return CryptoJS.lib.WordArray.create(words, u8.length);
}
function wordArrayToUint8(wa) {
  const words = wa.words || [];
  let sigBytes = wa.sigBytes;
  if (!sigBytes || sigBytes < 0) sigBytes = words.length * 4;
  const u8 = new Uint8Array(sigBytes);
  let idx = 0;
  for (let i=0;i<words.length && idx<sigBytes;i++) {
    const w = words[i];
    u8[idx++] = (w >> 24) & 0xff; if (idx>=sigBytes) break;
    u8[idx++] = (w >> 16) & 0xff; if (idx>=sigBytes) break;
    u8[idx++] = (w >> 8) & 0xff;  if (idx>=sigBytes) break;
    u8[idx++] = w & 0xff;         if (idx>=sigBytes) break;
  }
  return u8;
}
function decodeUtf8FromWordArray(wa) {
  try {
    const u8 = wordArrayToUint8(wa);
    return new TextDecoder("utf-8", { fatal: false }).decode(u8);
  } catch (e) {
    console.warn("UTF-8 decode fail", e);
    return "";
  }
}

// ---------------------- Crypto operations ----------------------
// derive SHA256(serverKeyBytes || nonceBytes) and return first16 bytes (Uint8Array)
async function deriveSessionKeyBytes(serverKeyUint8, nonceHex) {
  const nonceU8 = nonceHex ? hexToUint8(nonceHex) : new Uint8Array(0);
  const conc = new Uint8Array(serverKeyUint8.length + nonceU8.length);
  conc.set(serverKeyUint8, 0);
  conc.set(nonceU8, serverKeyUint8.length);
  const hash = await crypto.subtle.digest("SHA-256", conc.buffer);
  const hU8 = new Uint8Array(hash);
  return hU8.slice(0, 16);
}

// decrypt base64 ciphertext with a raw 16-byte session key (Uint8Array) and hex IV
function decryptWithSessionKeyB64(cipherB64, sessionKeyUint8, ivHex) {
  const keyWA = uint8ToWordArray(sessionKeyUint8);
  const ivWA = CryptoJS.enc.Hex.parse(cleanHex(ivHex || ""));
  const cipherWA = CryptoJS.enc.Base64.parse(cipherB64);
  const params = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decWA = CryptoJS.AES.decrypt(params, keyWA, {
    iv: ivWA,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  return { wa: decWA, text: decodeUtf8FromWordArray(decWA) };
}

// ---------------------- Server interaction ----------------------
async function fetchJson(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path} returned ${r.status}`);
  return r.json();
}
async function fetchLatest(limit=20) { return fetchJson(`${API_BASE}/api/latest?limit=${limit}`); }
async function fetchQuantumKey(authToken, kid) {
  // server expected: /api/quantum_key?auth=TOKEN&kid=KEYID
  const url = `${API_BASE}/api/quantum_key?auth=${encodeURIComponent(authToken)}${kid ? "&kid="+encodeURIComponent(kid) : ""}`;
  return fetchJson(url);
}

// ---------------------- UI render helpers ----------------------
function renderTable(rows) {
  const tbody = document.querySelector("#data-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  rows.forEach(r => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${r.entry_id ?? "-"}</td>
      <td>${r.stored_at ?? "-"}</td>
      <td>${r.sensor_data?.temperature ?? "-"}</td>
      <td>${r.sensor_data?.humidity ?? "-"}</td>
      <td>${r.sensor_data?.ir ?? "-"}</td>
      <td>${r.error ? `<pre style="color:#b00">${r.error}</pre>` : "OK"}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ---------------------- Main fetch & decrypt flow ----------------------
document.getElementById("btnFetch").addEventListener("click", async () => {
  const token = document.getElementById("token").value.trim();
  const status = document.getElementById("status");
  if (!token) { alert("Paste ESP_AUTH_TOKEN"); return; }
  status.textContent = "Fetching latest...";

  try {
    const docs = await fetchLatest(50);
    if (!Array.isArray(docs) || docs.length === 0) { renderTable([]); status.textContent = "No records"; return; }

    const quantumCache = {}; // kid -> serverKeyUint8 (first 16 bytes)
    const out = [];

    for (const item of docs) {
      const entryId = item.entry_id ?? item.entry ?? "-";
      try {
        // flexible mapping for fields (ThingSpeak / server may use field1..field5 or other names)
        const cipher_b64 = item.field1 || item.server_cipher_b64 || item.cipher_b64 || item.cipher || item.field_1;
        const key_id = item.field2 || item.key_id || item.kid || item.field_2;
        const ivHex = item.field3 || item.server_iv_hex || item.iv || item.ivHex || item.field_3;
        const nonceHex = item.field5 || item.nonce || item.nonceHex || item.field_5;

        if (!cipher_b64) throw new Error("No cipher (field1) found for entry");

        // key_id must exist; otherwise try to fetch latest quantum_key without kid
        const kid = (key_id || "").toString();

        // fetch quantum/server key for this kid (cache)
        let serverKeyUint8 = null;
        if (kid && quantumCache[kid]) {
          serverKeyUint8 = quantumCache[kid];
        } else {
          // fetch
          const qResp = await fetchQuantumKey(token, kid || "");
          // server may return key in many fields - try to find it
          let keyStr = qResp.key || qResp.key_hex || qResp.server_key || qResp.keyHex || qResp.serverKey || qResp.keyHexString || qResp.k;
          if (!keyStr && typeof qResp === "string") keyStr = qResp;
          if (!keyStr) throw new Error("quantum key not found in /api/quantum_key response");
          // convert to bytes and **trim to first 16 bytes** (Arduino used first 16 bytes)
          let keyU8 = keyStringToUint8(keyStr);
          if (!keyU8 || keyU8.length < 16) throw new Error("quantum key too short");
          // take first 16 bytes (Arduino used only first 16 bytes)
          const server16 = keyU8.slice(0, 16);
          serverKeyUint8 = server16;
          if (kid) quantumCache[kid] = serverKeyUint8;
        }

        // derive session key using serverKeyUint8 + nonceHex same way as Arduino
        if (!nonceHex) throw new Error("nonce (field5) missing - needed to derive session key");
        const sessionKey = await deriveSessionKeyBytes(serverKeyUint8, nonceHex);
        // use ivHex (field3) to decrypt; iv must be present
        if (!ivHex) throw new Error("iv (field3) missing");
        const final = decryptWithSessionKeyB64(cipher_b64, sessionKey, ivHex);
        if (!final || !final.text) throw new Error("Decryption produced empty plaintext");

        // parse JSON plaintext (sensor readings)
        let sensorJson;
        try {
          sensorJson = JSON.parse(final.text);
        } catch (e) {
          // sometimes non-printable padding bytes remain — try to find { ... } substring
          const s = final.text;
          const start = s.indexOf("{"), end = s.lastIndexOf("}");
          if (start !== -1 && end !== -1 && end > start) {
            const sub = s.substring(start, end+1);
            sensorJson = JSON.parse(sub);
          } else {
            throw new Error("Decrypted plaintext not valid JSON");
          }
        }

        out.push({ entry_id: entryId, stored_at: item.stored_at || "-", sensor_data: sensorJson });
      } catch (e) {
        console.error("Entry decrypt failed", entryId, e);
        out.push({ entry_id: entryId, stored_at: item.stored_at || "-", error: e.message || String(e) });
      }
    } // end for

    renderTable(out);
    status.textContent = `Processed ${out.length} entries`;
  } catch (err) {
    console.error(err);
    document.getElementById("status").textContent = "Error: " + (err.message || err);
    renderTable([]);
  }
});
