// script.js — Improved Q-SENSE Frontend
const AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00";
const API_URL = "/api/latest?auth=" + AUTH_TOKEN;

// Format helper
function safeValue(v) {
  if (!v || v === "N/A" || v.trim() === "") return "--";
  return v;
}

// Format timestamp
function formatTime(ts) {
  if (!ts) return "--";
  const d = new Date(ts);
  return d.toLocaleString();
}

// Update DOM
function updateUI(decrypted, timestamp) {
  document.getElementById("field1").textContent = safeValue(decrypted["Quantum Key"]);
  document.getElementById("field2").textContent = safeValue(decrypted["Temperature"]);
  document.getElementById("field3").textContent = safeValue(decrypted["Humidity"]);
  document.getElementById("field4").textContent = safeValue(decrypted["IR Sensor"]);
  document.getElementById("field5").textContent = safeValue(decrypted["MAX30100"]);

  document.getElementById("timestamp").textContent =
    "Last updated: " + formatTime(timestamp);

  const statusEl = document.getElementById("status");
  statusEl.textContent = "Connected ✔";
  statusEl.style.color = "limegreen";
}

// Handle error
function showError(errMsg) {
  const statusEl = document.getElementById("status");
  statusEl.textContent = "Error ❌ " + (errMsg || "");
  statusEl.style.color = "red";
}

// Fetch from backend
async function fetchData() {
  try {
    const resp = await fetch(API_URL);
    if (!resp.ok) throw new Error("Network Error: " + resp.status);

    const data = await resp.json();
    if (!data.ok) throw new Error("Backend Error");

    updateUI(data.decrypted || {}, data.timestamp);
  } catch (err) {
    console.error("Fetch error:", err);
    showError(err.message);
  }
}

// Initial load
fetchData();

// Auto-refresh every 20 s (ThingSpeak limit)
setInterval(fetchData, 20000);
