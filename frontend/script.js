const AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00";
const API_URL = "/api/latest?auth=" + AUTH_TOKEN;

function formatValue(label, v) {
  if (v === null || v === undefined) return "--";
  v = String(v).trim();
  if (v === "" || v === "N/A" || v === "--") return "--";

  switch (label) {
    case "Temperature":
      return isNaN(v) ? v : `${parseFloat(v).toFixed(2)} °C`;
    case "Humidity":
      return isNaN(v) ? v : `${parseFloat(v).toFixed(2)} %`;
    case "IR Sensor":
      return v === "1" ? "ACTIVE 🔴" : "OFF ⚫";
    case "MAX30100":
      if (v.includes("/")) {
        const [bpm, spo2] = v.split("/");
        return `${bpm.trim()} BPM / ${spo2.trim()} %SpO₂`;
      }
      return v;
    case "Quantum Key":
      const m = v.match(/[0-9a-fA-F]{32}/);
      return m ? m[0] : v;
    default:
      return v;
  }
}

function formatTime(ts) {
  if (!ts) return "--";
  const d = new Date(ts);
  return d.toLocaleString();
}

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
    if (!el) continue;

    const value = formatValue(label, decrypted[label]);
    el.textContent = value;

    // IR Sensor color cue
    if (label === "IR Sensor") {
      if (value.includes("ACTIVE")) {
        el.classList.add("active");
      } else {
        el.classList.remove("active");
      }
    }
  }

  document.getElementById("timestamp").textContent =
    "Last updated: " + formatTime(timestamp);

  const statusEl = document.getElementById("status");
  statusEl.textContent = "Connected ✔";
  statusEl.className = "status connected";
}

function showError(errMsg) {
  const statusEl = document.getElementById("status");
  statusEl.textContent = "Error ❌ " + (errMsg || "");
  statusEl.className = "status error";
}

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

fetchData();
setInterval(fetchData, 20000);
