// script.js — robust decryption supporting both workflow variants
// Dependencies: CryptoJS (include in your HTML) and browser TextDecoder + SubtleCrypto

const API_BASE = window.location.origin;

// ----- Helpers: CryptoJS conversions -----
function hexToWordArray(hex) { return CryptoJS.enc.Hex.parse(hex); }
function base64ToWordArray(b64) { return CryptoJS.enc.Base64.parse(b64); }
function wordArrayToUint8Array(wordArray) {
  const words = wordArray.words || [];
  let sigBytes = wordArray.sigBytes;
  if (!sigBytes || sigBytes < 0) sigBytes = words.length * 4;
  const out = new Uint8Array(sigBytes);
  let idx = 0;
  for (let i = 0; i < words.length && idx < sigBytes; i++) {
    const w = words[i];
    out[idx++] = (w >> 24) & 0xff;
    if (idx >= sigBytes) break;
    out[idx++] = (w >> 16) & 0xff;
    if (idx >= sigBytes) break;
    out[idx++] = (w >> 8) & 0xff;
    if (idx >= sigBytes) break;
    out[idx++] = w & 0xff;
  }
  return out;
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
function decodeUtf8FromWordArray(wa) {
  try {
    const u8 = wordArrayToUint8Array(wa);
    return new TextDecoder("utf-8").decode(u8);
  } catch (e) {
    console.warn("UTF-8 decode failed:", e);
    return "";
  }
}

// ----- Network helpers (adjust paths if your server uses different routes) -----
async function fetchLatest(limit = 10) {
  const r = await fetch(`${API_BASE}/api/latest?limit=${limit}`);
  if (!r.ok) throw new Error("Failed to fetch latest: " + r.status);
  return r.json();
}
async function fetchServerKey(authToken) {
  const r = await fetch(`${API_BASE}/api/server_key?auth=${encodeURIComponent(authToken)}`);
  if (!r.ok) throw new Error("Failed to fetch server key: " + r.status);
  return r.json();
}
async function fetchQuantumKey(authToken) {
  const r = await fetch(`${API_BASE}/api/quantum_key?auth=${encodeURIComponent(authToken)}`);
  if (!r.ok) throw new Error("Failed to fetch quantum key: " + r.status);
  return r.json();
}

// ----- AES decrypt using CryptoJS where keyHex and ivHex are hex strings -----
function decryptAesWithKeyHex(cipherB64, keyHex, ivHex) {
  const keyWA = hexToWordArray(keyHex);
  const ivWA = hexToWordArray(ivHex);
  const cipherWA = base64ToWordArray(cipherB64);
  const params = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decWA = CryptoJS.AES.decrypt(params, keyWA, {
    iv: ivWA,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  return { text: decodeUtf8FromWordArray(decWA), wa: decWA };
}

// ----- AES decrypt using a raw session key (Uint8Array) -----
function decryptAesWithRawKey(cipherB64, rawKeyUint8, ivHex) {
  const keyWA = uint8ArrayToWordArray(rawKeyUint8);
  const ivWA = hexToWordArray(ivHex);
  const cipherWA = base64ToWordArray(cipherB64);
  const params = CryptoJS.lib.CipherParams.create({ ciphertext: cipherWA });
  const decWA = CryptoJS.AES.decrypt(params, keyWA, {
    iv: ivWA,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  return { text: decodeUtf8FromWordArray(decWA), wa: decWA };
}

// ----- derive session key = SHA256(serverKeyBytes || nonceBytes) and return first 16 bytes (Uint8Array) -----
// serverKeyHex is hex for 16 bytes (32 hex chars) or more; nonceHex is hex string (16 bytes)
async function deriveSessionKeyBytes(serverKeyHex, nonceHex) {
  // convert hex → Uint8Array
  function hexToU8(hex) {
    const n = hex.length / 2;
    const u8 = new Uint8Array(n);
    for (let i = 0; i < n; ++i) u8[i] = parseInt(hex.substr(i * 2, 2), 16);
    return u8;
  }
  const serverKeyU8 = hexToU8(serverKeyHex);
  const nonceU8 = hexToU8(nonceHex);
  // concat
  const conc = new Uint8Array(serverKeyU8.length + nonceU8.length);
  conc.set(serverKeyU8, 0);
  conc.set(nonceU8, serverKeyU8.length);
  const hash = await crypto.subtle.digest("SHA-256", conc);
  const hashU8 = new Uint8Array(hash);
  // return first 16 bytes
  return hashU8.slice(0, 16);
}

// ----- UI render -----
function renderTable(rows) {
  const tbody = document.querySelector("#data-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  rows.forEach(r => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${r.entry_id}</td>
      <td>${r.stored_at || "-"}</td>
      <td>${r.sensor_data?.temperature ?? "-"}</td>
      <td>${r.sensor_data?.humidity ?? "-"}</td>
      <td>${r.sensor_data?.ir ?? "-"}</td>
      <td>${r.error ? `<pre style="color:#b00">${r.error}</pre>` : "OK"}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ----- Main fetch + decrypt routine with dual-strategy fallback -----
document.getElementById("btnFetch").addEventListener("click", async () => {
  const token = document.getElementById("token").value.trim();
  const status = document.getElementById("status");
  if (!token) { alert("Enter ESP_AUTH_TOKEN (token)"); return; }
  status.textContent = "Fetching...";

  try {
    const docs = await fetchLatest(20); // adjust limit as needed
    if (!Array.isArray(docs) || docs.length === 0) {
      status.textContent = "No records found.";
      renderTable([]);
      return;
    }
    // fetch server key (for server-layer AES wrapping). If your server requires different endpoint name adjust accordingly.
    const serverKeyResp = await fetchServerKey(token);
    const serverKeyHex = serverKeyResp.server_key; // expected 32 hex chars (16 bytes)
    if (!serverKeyHex) console.warn("Server key not provided by /api/server_key for token");

    const qKeyCache = {}; // cache quantum keys per key_id if needed

    const out = [];
    // Loop entries
    for (const item of docs) {
      try {
        // map fields — adapt if your /api/latest returns different field names
        // expected item.server_cipher_b64 (field1), item.key_id (field2), item.ivHex (field3), item.nonceHex (field5), item.stored_at (timestamp)
        const cipher_b64 = item.server_cipher_b64 || item.field1 || item.cipher_b64 || item.cipher; // try likely names
        const key_id = item.key_id || item.field2 || item.kid;
        const ivHex = item.server_iv_hex || item.field3 || item.ivHex || item.iv;
        const nonceHex = item.nonce || item.field5 || item.nonceHex;

        // Primary attempt: If serverKeyHex exists, try to decrypt outer server-layer (Scheme A)
        if (serverKeyHex && cipher_b64 && ivHex) {
          try {
            const outer = decryptAesWithKeyHex(cipher_b64, serverKeyHex, ivHex);
            // try parse JSON
            if (outer.text) {
              try {
                const parsed = JSON.parse(outer.text);
                // expected parsed contains inner cipher_b64 and iv, maybe also key_id
                if (parsed.cipher_b64 && parsed.iv) {
                  // we now need quantum key to decrypt parsed.cipher_b64
                  // fetch quantum key (server endpoint) — may require key_id in request if server supports it
                  let qKeyHex;
                  if (key_id && qKeyCache[key_id]) qKeyHex = qKeyCache[key_id];
                  else {
                    // call /api/quantum_key?auth=<token>&kid=<key_id> (server must accept kid param)
                    const qUrl = `${API_BASE}/api/quantum_key?auth=${encodeURIComponent(token)}${key_id ? "&kid=" + encodeURIComponent(key_id) : ""}`;
                    const qres = await fetch(qUrl);
                    if (!qres.ok) throw new Error("quantum key fetch failed: " + qres.status);
                    const qjson = await qres.json();
                    qKeyHex = qjson.key || qjson.key_hex || qjson.server_key || qjson.key_hex;
                    if (key_id) qKeyCache[key_id] = qKeyHex;
                  }
                  if (!qKeyHex) throw new Error("quantum key missing");
                  const final = decryptAesWithKeyHex(parsed.cipher_b64, qKeyHex, parsed.iv);
                  const sensorText = final.text;
                  const sensorJson = JSON.parse(sensorText);
                  out.push({ entry_id: item.entry_id || item.entry || "-", stored_at: item.stored_at || "-", sensor_data: sensorJson });
                  continue; // done with this entry
                }
              } catch (e) {
                // outer decrypted text wasn't JSON or inner structure unexpected — fall through to next strategy
                console.warn("Outer-layer JSON parse failed or missing inner fields:", e);
              }
            }
          } catch (e) {
            console.warn("Outer-layer decrypt failed for entry", item.entry_id, e);
            // fall through to scheme B
          }
        }

        // Fallback Strategy B: derive session key from serverKeyHex & nonceHex (if present) and decrypt cipher_b64 with that session key
        if (serverKeyHex && nonceHex && cipher_b64 && ivHex) {
          try {
            const sessionKeyBytes = await deriveSessionKeyBytes(serverKeyHex, nonceHex); // Uint8Array length 16
            const final = decryptAesWithRawKey(cipher_b64, sessionKeyBytes, ivHex);
            if (!final.text) throw new Error("Decryption yielded empty text");
            const sensorJson = JSON.parse(final.text);
            out.push({ entry_id: item.entry_id || item.entry || "-", stored_at: item.stored_at || "-", sensor_data: sensorJson });
            continue;
          } catch (e) {
            console.warn("Session-derive decrypt failed:", e);
          }
        }

        // Last-ditch attempt: treat field1 as base64 plaintext JSON (no encryption) — useful during debugging
        try {
          const maybePlain = atob(cipher_b64);
          try {
            const sensorJson = JSON.parse(maybePlain);
            out.push({ entry_id: item.entry_id || "-", stored_at: item.stored_at || "-", sensor_data: sensorJson });
            continue;
          } catch (e) {
            // not JSON
            throw e;
          }
        } catch (e) {
          // nothing more to try
        }

        // If we reached here, we failed to decrypt/parse — push error
        out.push({ entry_id: item.entry_id || "-", error: "Failed to decrypt / parse entry (see console)" });
      } catch (entryErr) {
        console.error("Entry", item.entry_id, "failed:", entryErr);
        out.push({ entry_id: item.entry_id || "-", error: String(entryErr) });
      }
    } // loop

    renderTable(out);
    status.textContent = `Fetched ${out.length} entries.`;
  } catch (err) {
    console.error(err);
    document.getElementById("status").textContent = "Error: " + (err.message || err);
    renderTable([]);
  }
});
