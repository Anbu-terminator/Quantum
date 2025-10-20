// script.js — Q-SENSE Frontend (final stable version)

// --- CONFIG ---
const AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00";
const API_URL = "/api/latest?auth=" + AUTH_TOKEN;

// --- UTILITY HELPERS ---
function safeValue(v) {
  if (!v || v === "N/A" || v.trim() === "") return "--";
  return v;
}

function formatTime(ts) {
  if (!ts) return "--";
  const d = new Date(ts);
  return d.toLocaleString();
}

// --- UI UPDATE ---
function updateUI(decrypted, timestamp) {
  const fields = {
    "field1": "Quantum Key",
    "field2": "Temperature",
    "field3": "Humidity",
    "field4": "IR Sensor",
    "field5": "MAX30100"
  };

  // Assign each reading to its card or span
  document.getElementById("field1").textContent = safeValue(decrypted["Quantum Key"]);
  document.getElementById("field2").textContent = safeValue(decrypted["Temperature"]);
  document.getElementById("field3").textContent = safeValue(decrypted["Humidity"]);
  document.getElementById("field4").textContent = safeValue(decrypted["IR Sensor"]);
  document.getElementById("field5").textContent = safeValue(decrypted["MAX30100"]);

  // Timestamp
  const timeEl = document.getElementById("timestamp");
  if (timeEl) timeEl.textContent = "Last updated: " + formatTime(timestamp);

  // Status indicator
  const statusEl = document.getElementById("status");
  if (statusEl) {
    statusEl.textContent = "🟢 Connected ✔";
    statusEl.style.color = "limegreen";
  }
}

// --- ERROR HANDLER ---
function showError(errMsg) {
  console.error("Fetch error:", errMsg);
  const statusEl = document.getElementById("status");
  if (statusEl) {
    statusEl.textContent = "🔴 Error ❌ " + (errMsg || "");
    statusEl.style.color = "red";
  }
}

// --- DATA FETCHER ---
async function fetchData() {
  try {
    const resp = await fetch(API_URL);
    if (!resp.ok) throw new Error("Network Error: " + resp.status);
    const data = await resp.json();

    if (!data.ok) throw new Error("Backend Error");

    const decrypted = data.decrypted || {};
    updateUI(decrypted, data.timestamp);
  } catch (err) {
    showError(err.message);
  }
}

// --- INITIALIZE ---
document.addEventListener("DOMContentLoaded", () => {
  fetchData();
  setInterval(fetchData, 20000); // refresh every 20 sec
});
