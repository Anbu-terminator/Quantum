// script.js
const AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00";
const API_URL = "/api/latest?auth=" + AUTH_TOKEN;

async function fetchData() {
  try {
    const resp = await fetch(API_URL);
    if (!resp.ok) throw new Error("Network error");

    const data = await resp.json();
    if (!data.ok) throw new Error("Backend error");

    const d = data.decrypted || {};

    document.getElementById("field1").textContent = d["Quantum Key"] || "--";
    document.getElementById("field2").textContent = d["Temperature"] || "--";
    document.getElementById("field3").textContent = d["Humidity"] || "--";
    document.getElementById("field4").textContent = d["IR Sensor"] || "--";
    document.getElementById("field5").textContent = d["MAX30100"] || "--";
    document.getElementById("timestamp").textContent =
      "Last updated: " + (data.timestamp || "--");
    document.getElementById("status").textContent = "Connected ✔";
  } catch (err) {
    console.error(err);
    document.getElementById("status").textContent =
      "Error connecting to backend ❌";
  }
}

// initial fetch + auto refresh
fetchData();
setInterval(fetchData, 20000);
