// script.js - robust decryption with multi-strategy fallbacks
// Dependencies: CryptoJS must be included in your HTML before this script.

const API_BASE = window.location.origin;

// ----------------- Utility: detect key formats & convert -----------------
function isHex(s){ return /^[0-9a-fA-F]+$/.test(s); }
function isBase64(s){ return /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.test(s); }

// convert hex string -> Uint8Array
function hexToUint8(hex) {
  const n = Math.floor(hex.length / 2);
  const u = new Uint8Array(n);
  for (let i = 0; i < n; i++) u[i] = parseInt(hex.substr(i*2, 2), 16);
  return u;
}
// convert base64 string -> Uint8Array
function base64ToUint8(b64) {
  const bin = atob(b64);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
// convert utf8 string -> Uint8Array
function utf8ToUint8(s) { return new TextEncoder().encode(s); }

// produce Uint8Array from key that may be hex/base64/plain
function keyToUint8(keyStr) {
  if (!keyStr) return null;
  keyStr = keyStr.trim();
  if (isHex(keyStr)) return hexToUint8(keyStr);
  if (isBase64(keyStr)) return base64ToUint8(keyStr);
  return utf8ToUint8(keyStr);
}

// produce CryptoJS WordArray from key string (hex/base64/utf8)
function keyToWordArray(keyStr) {
  if (!keyStr) return null;
  keyStr = keyStr.trim();
  if (isHex(keyStr)) return CryptoJS.enc.Hex.parse(keyStr);
  if (isBase64(keyStr)) return CryptoJS.enc.Base64.parse(keyStr);
  return CryptoJS.enc.Utf8.parse(keyStr);
}

// ----------------- Safe WordArray <-> Uint8Array conversions -----------------
function wordArrayToUint8Array(wordArray) {
  // Defensive: if sigBytes invalid, fall back to words.length*4
  const words = wordArray.words || [];
  let sigBytes = wordArray.sigBytes;
  if (!sigBytes || sigBytes < 0) sigBytes = words.length * 4;
  const u8 = new Uint8Array(sigBytes);
  let idx = 0;
  for (let i = 0; i < words.length && idx < sigBytes; i++) {
    const w = words[i];
    u8[idx++] = (w >> 24) & 0xff; if (idx >= sigBytes) break;
    u8[idx++] = (w >> 16) & 0xff; if (idx >= sigBytes) break;
    u8[idx++] = (w >> 8) & 0xff;  if (idx >= sigBytes) break;
    u8[idx++] = w & 0xff;         if (idx >= sigBytes) break;
  }
  return u8;
}
function uint8ArrayToWordArray(u8) {
  const words = [];
  for (let i = 0; i < u8.length; i += 4) {
    words.push(
      ((u8[i] || 0) << 24) |
      ((u8[i + 1] || 0) << 16) |
      ((u8[i + 2] || 0) << 8) |
      ((u8[i + 3] || 0))
    );
  }
  return CryptoJS.lib.WordArray.create(words, u8.length);
}

// ----------------- UTF-8 decode + JSON heuristic -----------------
function decodeUtf8FromWordArray(wa) {
  try {
    const u8 = wordArrayToUint8Array(wa);
    return new TextDecoder("utf-8", { fatal: false }).decode(u8);
  } catch (e) {
    console.warn("decodeUtf8FromWordArray failed:", e);
    return "";
  }
}

// Try parsing JSON with common fallbacks:
// 1) direct JSON.parse
// 2) trim BOM and whitespace
// 3) find first '{' and last '}' and parse substring
// 4) if string looks base64, decode and try parse
function tryParseJsonFlexible(s) {
  if (!s || typeof s !== "string") throw new Error("Empty string");
  // quick direct attempt
  try { return JSON.parse(s); } catch (e) { /* continue */ }

  // remove typical BOM
  s = s.replace(/^\uFEFF/, "").trim();

  try { return JSON.parse(s); } catch (e) { /* continue */ }

  // attempt to extract {...}
  const start = s.indexOf("{");
  const end = s.lastIndexOf("}");
  if (start !== -1 && end !== -1 && end > start) {
    const sub = s.substring(start, end + 1);
    try { return JSON.parse(sub); } catch (ee) { /* continue */ }
  }

  // check if s is base64 -> decode and try parse
  if (isBase64(s.replace(/\s+/g, ""))) {
    try {
      const dec = atob(s);
      return JSON.parse(dec);
    } catch (e) { /* continue */ }
  }

  throw new SyntaxError("Flexible JSON parse failed");
}

// ----------------- AES decryption helpers -----------------
function decryptAesWithKeyString(cipherB64, keyStr, ivHex) {
  if (!cipherB64) throw new Error("Missing cipherB64");
  const keyWA = keyToWordArray(keyStr);
  const ivWA = CryptoJS.enc.Hex.parse(ivHex || "");
  const cipherWA = CryptoJS.enc.Base64.parse(cipherB64);
  const params = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decWA = CryptoJS.AES.decrypt(params, keyWA, {
    iv: ivWA,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  return { wa: decWA, text: decodeUtf8FromWordArray(decWA) };
}

// decrypt using raw Uint8Array key (session key)
function decryptAesWithRawKey(cipherB64, rawKeyUint8, ivHex) {
  const keyWA = uint8ArrayToWordArray(rawKeyUint8);
  const ivWA = CryptoJS.enc.Hex.parse(ivHex || "");
  const cipherWA = CryptoJS.enc.Base64.parse(cipherB64);
  const params = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decWA = CryptoJS.AES.decrypt(params, keyWA, {
    iv: ivWA,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  return { wa: decWA, text: decodeUtf8FromWordArray(decWA) };
}

// derive session key: SHA256(serverKeyBytes || nonceBytes) -> first 16 bytes
async function deriveSessionKeyBytes(serverKeyStr, nonceHex) {
  const serverU8 = keyToUint8(serverKeyStr);
  const nonceU8 = nonceHex ? hexToUint8(nonceHex) : new Uint8Array(0);
  const concat = new Uint8Array(serverU8.length + nonceU8.length);
  concat.set(serverU8, 0);
  concat.set(nonceU8, serverU8.length);
  const hash = await crypto.subtle.digest("SHA-256", concat);
  const hU8 = new Uint8Array(hash);
  return hU8.slice(0, 16);
}

// ----------------- Network helpers -----------------
async function fetchJson(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path} failed: ${r.status}`);
  return r.json();
}
async function fetchLatest(limit=20) { return fetchJson(`${API_BASE}/api/latest?limit=${limit}`); }
async function fetchServerKey(authToken) { return fetchJson(`${API_BASE}/api/server_key?auth=${encodeURIComponent(authToken)}`); }
async function fetchQuantumKey(authToken, kid) {
  const url = `${API_BASE}/api/quantum_key?auth=${encodeURIComponent(authToken)}${kid ? "&kid="+encodeURIComponent(kid) : ""}`;
  return fetchJson(url);
}

// ----------------- UI render -----------------
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

// ----------------- Main: multi-strategy decrypt per entry -----------------
document.getElementById("btnFetch").addEventListener("click", async () => {
  const token = document.getElementById("token").value.trim();
  const status = document.getElementById("status");
  if (!token) { alert("Enter ESP_AUTH_TOKEN"); return; }
  status.textContent = "Fetching...";
  try {
    const docs = await fetchLatest(30);
    if (!Array.isArray(docs) || docs.length === 0) { renderTable([]); status.textContent = "No records"; return; }

    // fetch server key once (may be hex or base64 or utf8). If server returns nothing, some entries may still decrypt via session derive (if nonce present)
    let serverKeyResp = null;
    try { serverKeyResp = await fetchServerKey(token); } catch (e) { console.warn("server_key fetch failed:", e); serverKeyResp = null; }
    const serverKeyStr = serverKeyResp ? (serverKeyResp.server_key || serverKeyResp.key || serverKeyResp.key_hex || serverKeyResp.serverKey) : null;

    const quantumCache = {}; // cache quantum keys by kid

    const out = [];
    for (const item of docs) {
      const entryId = item.entry_id ?? item.entry ?? "-";
      try {
        // flexible field picking (ThingSpeak often returns field1..field5)
        const cipher_b64 = item.server_cipher_b64 || item.field1 || item.cipher_b64 || item.cipher || item.field_1;
        const ivHex = (item.server_iv_hex || item.field3 || item.ivHex || item.iv || item.field_3 || "").trim();
        const key_id = (item.key_id || item.field2 || item.kid || item.field_2 || "").trim();
        const nonceHex = (item.nonce || item.field5 || item.nonceHex || item.field_5 || "").trim();

        let success = false;
        // ---------- Strategy A: outer-layer decrypt by serverKey -> yields JSON wrapper { cipher_b64, iv, ... }
        if (serverKeyStr && cipher_b64 && ivHex) {
          try {
            const outer = decryptAesWithKeyString(cipher_b64, serverKeyStr, ivHex);
            // attempt flexible parse
            try {
              const parsedOuter = tryParseJsonFlexible(outer.text);
              // look for inner cipher fields
              const innerCipher = parsedOuter.cipher_b64 || parsedOuter.cipher || parsedOuter.data || parsedOuter.payload || parsedOuter.ciphertext;
              const innerIv = parsedOuter.iv || parsedOuter.ivHex || parsedOuter.server_iv || parsedOuter.inner_iv;
              const innerKeyId = parsedOuter.key_id || parsedOuter.kid || key_id || parsedOuter.keyId;
              if (!innerCipher || !innerIv) {
                throw new Error("Outer parsed but missing inner cipher/iv");
              }
              // get quantum key (try cache)
              let qKey = innerKeyId && quantumCache[innerKeyId] ? quantumCache[innerKeyId] : null;
              if (!qKey) {
                try {
                  const qresp = await fetchQuantumKey(token, innerKeyId || key_id);
                  qKey = qresp.key || qresp.key_hex || qresp.k || qresp.server_key || qresp.keyHex;
                  if (innerKeyId) quantumCache[innerKeyId] = qKey;
                } catch (qe) {
                  console.warn("quantum_key fetch failed (inner):", qe);
                }
              }
              if (!qKey) throw new Error("Quantum key missing for inner decrypt");
              const final = decryptAesWithKeyString(innerCipher, qKey, innerIv);
              const sensor = tryParseJsonFlexible(final.text);
              out.push({ entry_id: entryId, stored_at: item.stored_at || "-", sensor_data: sensor });
              success = true;
            } catch (outerParseErr) {
              // outer decrypt produced text but not a usable JSON wrapper
              console.warn("Outer-layer JSON parse failed or missing inner fields:", outerParseErr);
            }
          } catch (outerDecryptErr) {
            console.warn("Outer-layer decrypt failed:", outerDecryptErr);
          }
        }

        if (success) continue;

        // ---------- Strategy B: session-key derived (SHA256(serverKey||nonce) first 16 bytes)
        if (serverKeyStr && nonceHex && cipher_b64 && ivHex) {
          try {
            const sessionKeyBytes = await deriveSessionKeyBytes(serverKeyStr, nonceHex);
            const final = decryptAesWithRawKey(cipher_b64, sessionKeyBytes, ivHex);
            const sensor = tryParseJsonFlexible(final.text);
            out.push({ entry_id: entryId, stored_at: item.stored_at || "-", sensor_data: sensor });
            success = true;
          } catch (sessErr) {
            console.warn("Session-derive decrypt failed:", sessErr);
          }
        }
        if (success) continue;

        // ---------- Strategy C: maybe the field itself is direct ciphertext with quantum key (no server wrapper), try quantumKey directly
        if ((key_id || item.field2) && cipher_b64 && ivHex) {
          try {
            const kid = key_id || item.field2;
            let qKey = quantumCache[kid] || null;
            if (!qKey) {
              const qresp = await fetchQuantumKey(token, kid);
              qKey = qresp.key || qresp.key_hex || qresp.keyHex || qresp.key || qresp.server_key;
              quantumCache[kid] = qKey;
            }
            if (qKey) {
              const final = decryptAesWithKeyString(cipher_b64, qKey, ivHex);
              const sensor = tryParseJsonFlexible(final.text);
              out.push({ entry_id: entryId, stored_at: item.stored_at || "-", sensor_data: sensor });
              success = true;
            }
          } catch (cErr) {
            console.warn("Direct quantum-key decrypt failed:", cErr);
          }
        }
        if (success) continue;

        // ---------- Strategy D: try treat stored field as base64 plaintext JSON (debug)
        if (cipher_b64) {
          try {
            const maybePlain = atob(cipher_b64);
            const sensor = tryParseJsonFlexible(maybePlain);
            out.push({ entry_id: entryId, stored_at: item.stored_at || "-", sensor_data: sensor });
            success = true;
          } catch (dErr) { /* ignore */ }
        }
        if (success) continue;

        // if we reach here, nothing worked for this entry
        out.push({ entry_id: entryId, stored_at: item.stored_at || "-", error: "Unable to decrypt/parse (see console)" });
      } catch (entryErr) {
        console.error("Entry processing failed", entryId, entryErr);
        out.push({ entry_id: entryId, stored_at: item.stored_at || "-", error: String(entryErr) });
      }
    } // end for each doc

    renderTable(out);
    status.textContent = `Processed ${out.length} entries`;
  } catch (err) {
    console.error(err);
    document.getElementById("status").textContent = "Error: " + (err.message || err);
    renderTable([]);
  }
});
