const AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00";
const API_URL = "/api/latest?auth=" + AUTH_TOKEN;

let tempChart, humidityChart, maxChart;
const tempData = [], humidityData = [], bpmData = [], spo2Data = [], labels = [];

function formatValue(label, v) {
  if (v === null || v === undefined || v === "--") return "--";
  switch (label) {
    case "Temperature": return `${parseFloat(v).toFixed(2)} °C`;
    case "Humidity": return `${parseFloat(v).toFixed(2)} %`;
    case "IR Sensor": return v === 1 ? "ACTIVE 🔴" : "OFF ⚫";
    case "MAX30100":
      return v.BPM && v.SpO2 ? `${v.BPM} BPM / ${v.SpO2} %SpO₂` : "--";
    case "Quantum Key":
      return v.toString().slice(-32);
    default: return v;
  }
}

function formatTime(ts) {
  if (!ts) return "--";
  return new Date(ts).toLocaleString();
}

function updateUI(data, timestamp) {
  document.getElementById("field1").textContent = formatValue("Quantum Key", data["Quantum Key"]);
  document.getElementById("field2").textContent = formatValue("Temperature", data["Temperature"]);
  document.getElementById("field3").textContent = formatValue("Humidity", data["Humidity"]);
  document.getElementById("field4").textContent = formatValue("IR Sensor", data["IR Sensor"]);
  document.getElementById("field5").textContent = formatValue("MAX30100", data["MAX30100"]);
  document.getElementById("timestamp").textContent = "Last updated: " + formatTime(timestamp);

  // update charts
  const now = new Date().toLocaleTimeString();
  labels.push(now);
  tempData.push(data["Temperature"] || null);
  humidityData.push(data["Humidity"] || null);
  bpmData.push(data["MAX30100"] ? data["MAX30100"].BPM : null);
  spo2Data.push(data["MAX30100"] ? data["MAX30100"].SpO2 : null);

  if (labels.length > 20) {
    labels.shift();
    tempData.shift();
    humidityData.shift();
    bpmData.shift();
    spo2Data.shift();
  }

  if (tempChart) tempChart.update();
  if (humidityChart) humidityChart.update();
  if (maxChart) maxChart.update();

  const statusEl = document.getElementById("status");
  statusEl.textContent = "Connected ✔";
  statusEl.style.color = "limegreen";
}

function showError(errMsg) {
  const statusEl = document.getElementById("status");
  statusEl.textContent = "Error ❌ " + (errMsg || "");
  statusEl.style.color = "red";
}

async function fetchData() {
  try {
    const resp = await fetch(API_URL);
    if (!resp.ok) throw new Error("Network error: " + resp.status);
    const data = await resp.json();
    if (!data.ok) throw new Error("Backend error");
    updateUI(data.decrypted, data.timestamp);
  } catch (err) {
    console.error(err);
    showError(err.message);
  }
}

function initCharts() {
  const ctxTemp = document.getElementById("tempChart").getContext("2d");
  tempChart = new Chart(ctxTemp, {
    type: "line",
    data: { labels, datasets: [{ label: "Temperature (°C)", data: tempData, borderColor: "#ff5733", backgroundColor: "#ffcccb55", tension: 0.4 }] },
    options: { responsive:true, plugins:{legend:{display:true}} }
  });

  const ctxHumidity = document.getElementById("humidityChart").getContext("2d");
  humidityChart = new Chart(ctxHumidity, {
    type: "line",
    data: { labels, datasets: [{ label: "Humidity (%)", data: humidityData, borderColor: "#33c1ff", backgroundColor: "#33ccff33", tension:0.4 }] },
    options: { responsive:true, plugins:{legend:{display:true}} }
  });

  const ctxMax = document.getElementById("maxChart").getContext("2d");
  maxChart = new Chart(ctxMax, {
    type: "line",
    data: {
      labels,
      datasets: [
        { label: "BPM", data: bpmData, borderColor: "#33ff57", backgroundColor: "#33ff5733", tension:0.4 },
        { label: "SpO2", data: spo2Data, borderColor: "#ff33a6", backgroundColor: "#ff33a633", tension:0.4 }
      ]
    },
    options: { responsive:true, plugins:{legend:{display:true}} }
  });
}

// initial load
initCharts();
fetchData();
setInterval(fetchData, 20000); // every 20 seconds
