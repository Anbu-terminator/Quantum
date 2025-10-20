const AUTH_TOKEN = "YOUR_ESP_AUTH_TOKEN"; // same as server.py

const fieldElements = {
  field1: document.getElementById("field1"),
  field2: document.getElementById("field2"),
  field3: document.getElementById("field3"),
  field4: document.getElementById("field4"),
  field5: document.getElementById("field5"),
};

const irIndicator = document.getElementById("field4");
const timestampEl = document.getElementById("timestamp");

let tempChart, humChart, bpmChart;
let tempData = [], humData = [], bpmData = [], spo2Data = [], labels = [];

function initCharts() {
  const ctxTemp = document.getElementById("tempChart").getContext("2d");
  tempChart = new Chart(ctxTemp, {
    type: "line",
    data: { labels, datasets: [{ label: "Temperature (°C)", data: tempData, borderColor: "#FF5722", backgroundColor: "rgba(255,87,34,0.2)" }] },
    options: { responsive: true, animation: { duration: 800 } },
  });

  const ctxHum = document.getElementById("humChart").getContext("2d");
  humChart = new Chart(ctxHum, {
    type: "line",
    data: { labels, datasets: [{ label: "Humidity (%)", data: humData, borderColor: "#03A9F4", backgroundColor: "rgba(3,169,244,0.2)" }] },
    options: { responsive: true, animation: { duration: 800 } },
  });

  const ctxBPM = document.getElementById("bpmChart").getContext("2d");
  bpmChart = new Chart(ctxBPM, {
    type: "line",
    data: {
      labels,
      datasets: [
        { label: "BPM", data: bpmData, borderColor: "#4CAF50", backgroundColor: "rgba(76,175,80,0.2)" },
        { label: "SpO2", data: spo2Data, borderColor: "#FF9800", backgroundColor: "rgba(255,152,0,0.2)" }
      ]
    },
    options: { responsive: true, animation: { duration: 800 } },
  });
}

async function fetchData() {
  try {
    const res = await fetch(`/api/latest?auth=${AUTH_TOKEN}`);
    const data = await res.json();
    if (!data.ok) throw new Error("Fetch failed");

    const sensors = data.decrypted;
    timestampEl.textContent = `Last update: ${new Date(data.timestamp).toLocaleString()}`;

    fieldElements.field1.textContent = sensors["Quantum Key"];
    fieldElements.field2.textContent = sensors["Temperature"];
    fieldElements.field3.textContent = sensors["Humidity"];
    fieldElements.field5.textContent = typeof sensors["MAX30100"] === "object" ? `BPM: ${sensors["MAX30100"].BPM}, SpO2: ${sensors["MAX30100"].SpO2}` : sensors["MAX30100"];

    // IR indicator
    if (sensors["IR Sensor"] === 1) {
      irIndicator.style.backgroundColor = "#4CAF50";
    } else if (sensors["IR Sensor"] === 0) {
      irIndicator.style.backgroundColor = "#F44336";
    } else {
      irIndicator.style.backgroundColor = "gray";
    }

    // Update charts
    const label = new Date(data.timestamp).toLocaleTimeString();
    labels.push(label);
    tempData.push(Number(sensors["Temperature"]) || 0);
    humData.push(Number(sensors["Humidity"]) || 0);
    bpmData.push(sensors["MAX30100"]?.BPM || 0);
    spo2Data.push(sensors["MAX30100"]?.SpO2 || 0);

    if (labels.length > 20) { labels.shift(); tempData.shift(); humData.shift(); bpmData.shift(); spo2Data.shift(); }

    tempChart.update();
    humChart.update();
    bpmChart.update();

  } catch (err) {
    console.error(err);
    document.getElementById("status").textContent = "Error connecting to backend";
  }
}

initCharts();
fetchData();
setInterval(fetchData, 5000);
