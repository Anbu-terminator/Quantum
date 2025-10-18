// frontend/script.js
// Configure your backend host (where server.py runs)
const BACKEND = location.origin; // if you host backend at same origin; otherwise set e.g. "http://192.168.1.100:5000"
const THINGSPEAK_CHANNEL = "3100917";
const THINGSPEAK_READ_KEY = "AT5M7WZ9WQX31AHN";
const THINGSPEAK_API = `https://api.thingspeak.com/channels/${THINGSPEAK_CHANNEL}/feeds.json?results=1`;

const statusEl = document.getElementById("status");
const tsRaw = document.getElementById("ts-raw");
const btn = document.getElementById("refresh");

async function fetchThingSpeak(){
  statusEl.textContent = "Fetching ThingSpeak..."
  const r = await fetch(THINGSPEAK_API);
  const data = await r.json();
  if(!data.feeds || data.feeds.length===0){
    tsRaw.textContent = "No feeds yet";
    statusEl.textContent = "";
    return null;
  }
  const feed = data.feeds[0];
  tsRaw.textContent = JSON.stringify(feed, null, 2);
  return feed;
}

async function decryptFeed(feed){
  // fields 1..5 store "ivhex:cipherhex"
  const fields = {
    field1: feed.field1 || "",
    field2: feed.field2 || "",
    field3: feed.field3 || "",
    field4: feed.field4 || "",
    field5: feed.field5 || ""
  };
  // To derive the session key we need the quantum_hex used by the ESP when encrypting.
  // We assume ESP obtains the quantum bytes from backend /quantum and uses that value.
  // So the ESP must store that quantum_hex in field1? If ESP does not publish quantum_hex to ThingSpeak
  // then we must have the ESP send quantum_hex to the backend the same way it requests it (recommended).
  // In this example we assume the ESP also wrote its quantum_hex into field1_metadata (or field1) — adapt as needed.
  // For safety: if field1 contains the encrypted payload and not quantum, the ESP must expose the quantum_hex to the server via another channel.
  // We'll try to detect if feed.field1 contains "q:" prefix for the quantum. If not present, attempt to fetch quantum from backend (not recommended).
  let quantum_hex = null;
  // If the ESP wrote a separate field for quantum, e.g. field1 contains "Q:<hex>" — adapt to your ESP.
  // For now we expect the frontend operator to paste quantum or the ESP to include the quantum in feed.entry_id (customize as needed).
  // If not found, ask backend to retrieve a fresh quantum (NOT ideal) — the correct approach: ESP should include the quantum_hex (or the backend should have provided it when the ESP requested quantum).
  // Attempt to auto-detect:
  if(fields.field1 && fields.field1.startsWith("Q:")){
    quantum_hex = fields.field1.slice(2);
    // Remove field1 so we only decrypt payload fields
    fields.field1 = ""; 
  } else {
    // fallback: request the backend for last quantum? (not secure). We'll request a fresh quantum and hope ESP used same — this is fragile.
    // Best practice: have the ESP store quantum_hex to a private endpoint or include it in ThingSpeak in a dedicated field.
    try {
      const qresp = await fetch(BACKEND + "/quantum?n=16");
      const qjson = await qresp.json();
      quantum_hex = qjson.quantum_hex;
    } catch(e){
      console.error(e);
    }
  }

  if(!quantum_hex){
    statusEl.textContent = "Unable to determine quantum_hex. ESP must publish it (recommended).";
    return;
  }

  statusEl.textContent = "Requesting decryption from backend...";
  const resp = await fetch(BACKEND + "/decrypt", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({quantum_hex, fields})
  });
  const j = await resp.json();
  if(j.decrypted){
    document.getElementById("f1").textContent = j.decrypted.field1 || "-";
    document.getElementById("f2").textContent = j.decrypted.field2 || "-";
    document.getElementById("f3").textContent = j.decrypted.field3 || "-";
    document.getElementById("f4").textContent = j.decrypted.field4 || "-";
    document.getElementById("f5").textContent = j.decrypted.field5 || "-";
    statusEl.textContent = "Decrypted";
  } else {
    statusEl.textContent = "Decryption failed: " + (j.error || "unknown");
  }
}

btn.addEventListener("click", async () => {
  const feed = await fetchThingSpeak();
  if(feed) await decryptFeed(feed);
});

// auto refresh on load
window.addEventListener("load", async () => {
  const feed = await fetchThingSpeak();
  if(feed) await decryptFeed(feed);
});
