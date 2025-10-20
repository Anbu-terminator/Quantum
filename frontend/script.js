const AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00";
const API_URL = `/api/latest?auth=${AUTH_TOKEN}`;

const el = id => document.getElementById(id);
const statusEl = el("status");
const tsEl = el("timestamp");
const fields = {
  "Quantum Key": el("field1"),
  "Temperature": el("field2"),
  "Humidity": el("field3"),
  "IR Sensor": el("field4"),
};

let labels = [], tempSeries = [], humSeries = [];
let chartT, chartH;

function safeStr(v) { return v == null ? "--" : String(v); }

function displayValue(label, v) {
  const node = fields[label];
  if (!node) return;
  if (v == null) { node.textContent = "--"; return; }

  if (label === "Quantum Key") {
    const s = String(v);
    const m = s.match(/[0-9a-fA-F]{16,64}/);
    node.textContent = m ? m[0].slice(-32) : s;
    return;
  }

  if (label === "Temperature") {
    node.textContent = typeof v === "number" ? `${v.toFixed(2)} °C` : safeStr(v);
    return;
  }

  if (label === "Humidity") {
    node.textContent = typeof v === "number" ? `${v.toFixed(2)} %` : safeStr(v);
    return;
  }

  if (label === "IR Sensor") {
    if (v === 1 || v === "1") {
      node.textContent = "ACTIVE";
      node.style.background = "#00ff88";
      node.style.color = "#000";
    } else if (v === 0 || v === "0") {
      node.textContent = "OFF";
      node.style.background = "#ff0055";
      node.style.color = "#fff";
    } else {
      node.textContent = safeStr(v);
      node.style.background = "#444";
      node.style.color = "#fff";
    }
  }
}

function initCharts() {
  const tctx = document.getElementById("chartTemp").getContext("2d");
  chartT = new Chart(tctx, {
    type: "line",
    data: { labels, datasets: [{ label: "Temperature (°C)", data: tempSeries, borderColor: "#ff4081", backgroundColor: "rgba(255,64,129,0.15)", tension: 0.3 }] },
    options: { responsive: true }
  });

  const hctx = document.getElementById("chartHum").getContext("2d");
  chartH = new Chart(hctx, {
    type: "line",
    data: { labels, datasets: [{ label: "Humidity (%)", data: humSeries, borderColor: "#00eaff", backgroundColor: "rgba(0,234,255,0.15)", tension: 0.3 }] },
    options: { responsive: true }
  });
}

async function fetchAndRender() {
  try {
    const res = await fetch(API_URL);
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || "Backend error");

    const s = data.decrypted || {};
    const ts = data.timestamp || new Date().toISOString();
    tsEl.textContent = "Last update: " + new Date(ts).toLocaleString();

    displayValue("Quantum Key", s["Quantum Key"]);
    displayValue("Temperature", s["Temperature"]);
    displayValue("Humidity", s["Humidity"]);
    displayValue("IR Sensor", s["IR Sensor"]);

    const label = new Date(ts).toLocaleTimeString();
    labels.push(label);
    tempSeries.push(s["Temperature"] ?? null);
    humSeries.push(s["Humidity"] ?? null);

    if (labels.length > 24) { labels.shift(); tempSeries.shift(); humSeries.shift(); }

    chartT.update();
    chartH.update();

    statusEl.textContent = "Connected ✓";
    statusEl.className = "status-bar ok";
  } catch (err) {
    console.error(err);
    statusEl.textContent = "Error connecting to backend";
    statusEl.className = "status-bar error";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  fetchAndRender();
  setInterval(fetchAndRender, 10000);
});
