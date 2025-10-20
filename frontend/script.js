// script.js — Final Enhanced Q-SENSE Dashboard
const AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00";
const API_URL = "/api/latest?auth=" + AUTH_TOKEN;

// Helper: clean and prettify value
function formatValue(label, v) {
  if (!v || v === "N/A" || v === "--" || v.trim() === "") return "--";

  v = v.trim();

  switch (label) {
    case "Temperature":
      // Add °C symbol if numeric
      return isNaN(v) ? v : `${parseFloat(v).toFixed(2)} °C`;

    case "Humidity":
      // Add % symbol if numeric
      return isNaN(v) ? v : `${parseFloat(v).toFixed(2)} %`;

    case "IR Sensor":
      // 1 or 0 as ON/OFF
      return v === "1" ? "ACTIVE 🔴" : "OFF ⚫";

    case "MAX30100":
      // If format is "bpm/spo2"
      if (v.includes("/")) {
        const [bpm, spo2] = v.split("/");
        return `${bpm.trim()} BPM / ${spo2.trim()} %SpO₂`;
      }
      return v;

    case "Quantum Key":
      // Keep only 32-hex-digit key visible
      const m = v.match(/[0-9a-fA-F]{32}/);
      return m ? m[0] : v;

    default:
      return v;
  }
}

// Helper: timestamp formatting
function formatTime(ts) {
  if (!ts) return "--";
  const d = new Date(ts);
  return d.toLocaleString();
}

// UI update function
function updateUI(decrypted, timestamp) {
  const fields = [
    ["Quantum Key", "field1"],
    ["Temperature", "field2"],
    ["Humidity", "field3"],
    ["IR Sensor", "field4"],
    ["MAX30100", "field5"],
  ];

  for (const [label, id] of fields) {
    const el = document.getElementById(id);
    if (el) el.textContent = formatValue(label, decrypted[label]);
  }

  document.getElementById("timestamp").textContent =
    "Last updated: " + formatTime(timestamp);

  const statusEl = document.getElementById("status");
  statusEl.textContent = "Connected ✔";
  statusEl.style.color = "limegreen";
}

// Error handler
function showError(errMsg) {
  const statusEl = document.getElementById("status");
  statusEl.textContent = "Error ❌ " + (errMsg || "");
  statusEl.style.color = "red";
}

// Fetch + update every 20 seconds
async function fetchData() {
  try {
    const resp = await fetch(API_URL);
    if (!resp.ok) throw new Error("Network error: " + resp.status);

    const data = await resp.json();
    if (!data.ok) throw new Error("Backend returned error");

    updateUI(data.decrypted || {}, data.timestamp);
  } catch (err) {
    console.error("Fetch error:", err);
    showError(err.message);
  }
}

// Initial load
fetchData();

// Auto-refresh every 20 s (ThingSpeak rate limit)
setInterval(fetchData, 20000);
