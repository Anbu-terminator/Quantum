// script.js — paste into frontend/script.js
const AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00"; // must match config.ESP_AUTH_TOKEN
const API_URL = `/api/latest?auth=${AUTH_TOKEN}`;

// DOM
const el = id => document.getElementById(id);
const statusEl = el("status");
const tsEl = el("timestamp");
const fields = {
  "Quantum Key": el("field1"),
  "Temperature": el("field2"),
  "Humidity": el("field3"),
  "IR Sensor": el("field4"),
  "MAX30100": el("field5"),
};

// Charts (Chart.js must be loaded from CDN in index.html)
let labels = [], tempSeries = [], humSeries = [], bpmSeries = [], spo2Series = [];
let chartT, chartH, chartM;

function safeStr(v) { return v === null || v === undefined ? "--" : String(v); }

function displayValue(label, v) {
  const node = fields[label];
  if (!node) return;
  if (v == null) {
    node.textContent = "--";
    if (label === "IR Sensor") { node.style.background = '#cbd5e1'; node.style.color = '#000'; }
    return;
  }
  if (label === "Quantum Key") {
    const s = String(v);
    const m = s.match(/[0-9a-fA-F]{16,64}/);
    node.textContent = m ? m[0].slice(-32) : s;
    return;
  }
  if (label === "Temperature") {
    node.textContent = (typeof v === "number") ? `${v.toFixed(2)} °C` : safeStr(v);
    return;
  }
  if (label === "Humidity") {
    node.textContent = (typeof v === "number") ? `${v.toFixed(2)} %` : safeStr(v);
    return;
  }
  if (label === "IR Sensor") {
    if (v === 1 || v === "1") {
      node.textContent = "ACTIVE";
      node.style.background = "#10B981";
      node.style.color = "#fff";
      node.style.transform = "scale(1.05)";
    } else if (v === 0 || v === "0") {
      node.textContent = "OFF";
      node.style.background = "#EF4444";
      node.style.color = "#fff";
      node.style.transform = "scale(1)";
    } else {
      node.textContent = safeStr(v);
      node.style.background = "#cbd5e1";
      node.style.color = "#000";
      node.style.transform = "scale(1)";
    }
    return;
  }
  if (label === "MAX30100") {
    if (v && typeof v === "object" && "BPM" in v && "SpO2" in v) {
      node.textContent = `${v.BPM} BPM / ${v.SpO2} %SpO₂`;
    } else node.textContent = safeStr(v);
    return;
  }
  node.textContent = safeStr(v);
}

// Initialize charts
function initCharts() {
  const tctx = document.getElementById("chartTemp").getContext("2d");
  chartT = new Chart(tctx, {
    type: "line",
    data: { labels, datasets: [{ label: "Temperature (°C)", data: tempSeries, borderColor: "#FF7043", backgroundColor: "rgba(255,112,67,0.12)", tension:0.3 }]},
    options: { responsive:true }
  });

  const hctx = document.getElementById("chartHum").getContext("2d");
  chartH = new Chart(hctx, {
    type: "line",
    data: { labels, datasets: [{ label: "Humidity (%)", data: humSeries, borderColor: "#42A5F5", backgroundColor: "rgba(66,165,245,0.12)", tension:0.3 }]},
    options: { responsive:true }
  });

  const mctx = document.getElementById("chartMax").getContext("2d");
  chartM = new Chart(mctx, {
    type: "line",
    data: { labels, datasets: [
      { label: "BPM", data: bpmSeries, borderColor: "#66BB6A", backgroundColor: "rgba(102,187,106,0.12)", tension:0.3 },
      { label: "SpO2", data: spo2Series, borderColor: "#FFA726", backgroundColor: "rgba(255,167,38,0.12)", tension:0.3 }
    ]},
    options: { responsive:true }
  });
}

async function fetchAndRender() {
  try {
    const res = await fetch(API_URL);
    if (!res.ok) throw new Error("Network response " + res.status);
    const payload = await res.json();
    if (!payload.ok) throw new Error(payload.error || "backend error");

    const s = payload.decrypted || {};
    const ts = payload.timestamp || new Date().toISOString();
    tsEl.textContent = `Last update: ${new Date(ts).toLocaleString()}`;

    // Show values
    displayValue("Quantum Key", s["Quantum Key"]);
    displayValue("Temperature", s["Temperature"]);
    displayValue("Humidity", s["Humidity"]);
    displayValue("IR Sensor", s["IR Sensor"]);
    displayValue("MAX30100", s["MAX30100"]);

    // push to charts
    const label = new Date(ts).toLocaleTimeString();
    labels.push(label);
    tempSeries.push(typeof s["Temperature"] === "number" ? s["Temperature"] : null);
    humSeries.push(typeof s["Humidity"] === "number" ? s["Humidity"] : null);
    bpmSeries.push(s["MAX30100"] && s["MAX30100"].BPM ? s["MAX30100"].BPM : null);
    spo2Series.push(s["MAX30100"] && s["MAX30100"].SpO2 ? s["MAX30100"].SpO2 : null);

    if (labels.length > 24) { labels.shift(); tempSeries.shift(); humSeries.shift(); bpmSeries.shift(); spo2Series.shift(); }

    chartT.update(); chartH.update(); chartM.update();

    statusEl.textContent = "Connected ✓";
    statusEl.style.background = "linear-gradient(90deg,#dcfce7,#bbf7d0)";
  } catch (err) {
    console.error("Fetch error:", err);
    statusEl.textContent = "Error connecting to backend";
    statusEl.style.background = "linear-gradient(90deg,#fee2e2,#fecaca)";
  }
}

// init
initCharts();
fetchAndRender();
setInterval(fetchAndRender, 10000);
