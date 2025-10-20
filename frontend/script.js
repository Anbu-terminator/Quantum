// script.js
const AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00"; // <- set to same token as server
const API_URL = `/api/latest?auth=${AUTH_TOKEN}`;

const el = id => document.getElementById(id);
const statusEl = el("status");
const tsEl = el("timestamp");

const fieldMap = {
  "Quantum Key": el("field1"),
  "Temperature": el("field2"),
  "Humidity": el("field3"),
  "IR Sensor": el("field4"),
  "MAX30100": el("field5"),
};

// Chart datasets
let labels = [];
let tempSeries = [], humSeries = [], bpmSeries = [], spo2Series = [];
let chartTemp, chartHum, chartMax;

function fmtNumber(n, decimals=2){
  if (n === null || n === undefined) return "--";
  if (typeof n === "number") return n.toFixed(decimals);
  const v = Number(n);
  return isNaN(v) ? "--" : v.toFixed(decimals);
}

function displayValue(label, value){
  const node = fieldMap[label];
  if (!node) return;
  if (value === null || value === undefined) {
    node.textContent = "--";
    return;
  }

  if (label === "Quantum Key") {
    // show last 32 hex chars if looks hex
    const s = String(value);
    const hx = s.match(/[0-9a-fA-F]{16,64}/);
    node.textContent = hx ? hx[0].slice(-32) : s;
    return;
  }
  if (label === "Temperature") {
    node.textContent = (typeof value === "number") ? `${fmtNumber(value)} °C` : value;
    return;
  }
  if (label === "Humidity") {
    node.textContent = (typeof value === "number") ? `${fmtNumber(value)} %` : value;
    return;
  }
  if (label === "IR Sensor") {
    if (value === 1 || value === "1") {
      node.textContent = "ACTIVE";
      node.style.backgroundColor = "#10B981"; // green
      node.style.color = "#fff";
      node.style.transform = "scale(1.05)";
    } else if (value === 0 || value === "0") {
      node.textContent = "OFF";
      node.style.backgroundColor = "#EF4444"; // red
      node.style.color = "#fff";
      node.style.transform = "scale(1)";
    } else {
      node.textContent = "--";
      node.style.backgroundColor = "#cbd5e1";
      node.style.color = "#000";
      node.style.transform = "scale(1)";
    }
    return;
  }
  if (label === "MAX30100") {
    if (value && typeof value === "object" && "BPM" in value && "SpO2" in value) {
      node.textContent = `${value.BPM} BPM / ${value.SpO2} %SpO₂`;
    } else {
      node.textContent = String(value);
    }
    return;
  }
  node.textContent = String(value);
}

function initCharts(){
  const ctxT = document.getElementById("chartTemp").getContext("2d");
  chartTemp = new Chart(ctxT, {
    type: "line",
    data: { labels, datasets: [{ label: "Temperature (°C)", data: tempSeries, borderColor: "#FF7043", backgroundColor: "rgba(255,112,67,0.12)", tension:0.35 }]},
    options: { responsive:true, plugins:{legend:{display:true}} }
  });

  const ctxH = document.getElementById("chartHum").getContext("2d");
  chartHum = new Chart(ctxH, {
    type: "line",
    data: { labels, datasets: [{ label: "Humidity (%)", data: humSeries, borderColor: "#42A5F5", backgroundColor: "rgba(66,165,245,0.12)", tension:0.35 }]},
    options: { responsive:true, plugins:{legend:{display:true}} }
  });

  const ctxM = document.getElementById("chartMax").getContext("2d");
  chartMax = new Chart(ctxM, {
    type: "line",
    data: {
      labels,
      datasets: [
        { label: "BPM", data: bpmSeries, borderColor: "#66BB6A", backgroundColor: "rgba(102,187,106,0.12)", tension:0.35 },
        { label: "SpO2", data: spo2Series, borderColor: "#FFA726", backgroundColor: "rgba(255,167,38,0.12)", tension:0.35 }
      ]
    },
    options:{ responsive:true, plugins:{legend:{display:true}} }
  });
}

async function fetchAndRender(){
  try {
    const res = await fetch(API_URL);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const payload = await res.json();
    if (!payload.ok) throw new Error(payload.error || "backend error");

    const sensors = payload.decrypted || {};
    const ts = payload.timestamp || new Date().toISOString();
    tsEl.textContent = `Last update: ${new Date(ts).toLocaleString()}`;

    // Display values
    displayValue("Quantum Key", sensors["Quantum Key"]);
    displayValue("Temperature", sensors["Temperature"]);
    displayValue("Humidity", sensors["Humidity"]);
    displayValue("IR Sensor", sensors["IR Sensor"]);
    displayValue("MAX30100", sensors["MAX30100"]);

    // Push to charts
    const label = new Date(ts).toLocaleTimeString();
    labels.push(label);
    tempSeries.push( (typeof sensors["Temperature"] === "number") ? sensors["Temperature"] : null );
    humSeries.push( (typeof sensors["Humidity"] === "number") ? sensors["Humidity"] : null );
    bpmSeries.push( sensors["MAX30100"] && sensors["MAX30100"].BPM ? sensors["MAX30100"].BPM : null );
    spo2Series.push( sensors["MAX30100"] && sensors["MAX30100"].SpO2 ? sensors["MAX30100"].SpO2 : null );

    if (labels.length > 24) {
      labels.shift(); tempSeries.shift(); humSeries.shift(); bpmSeries.shift(); spo2Series.shift();
    }
    chartTemp.update(); chartHum.update(); chartMax.update();

    statusEl.textContent = "Connected ✓";
    statusEl.style.background = "linear-gradient(90deg,#dcfce7,#bbf7d0)";
  } catch (err) {
    console.error("fetch error", err);
    statusEl.textContent = "Error connecting to backend";
    statusEl.style.background = "linear-gradient(90deg,#fee2e2,#fecaca)";
  }
}

initCharts();
fetchAndRender();
setInterval(fetchAndRender, 10000); // update every 10s
