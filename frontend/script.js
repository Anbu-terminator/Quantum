const API_URL = "/api/latest?auth=ESP8266_AUTH";
const dataDiv = document.getElementById("data");
const btn = document.getElementById("refreshBtn");

async function fetchData() {
  dataDiv.innerHTML = "Loading...";
  try {
    const res = await fetch(API_URL);
    const json = await res.json();
    const data = json.decrypted;
    dataDiv.innerHTML = "";
    Object.entries(data).forEach(([key, val]) => {
      const c = document.createElement("div");
      c.className = "card";
      c.innerHTML = `
        <h3>${key}</h3>
        <p><strong>Value:</strong> ${val.value}</p>
        <p><strong>Challenge ID:</strong> ${val.challenge_id || "N/A"}</p>
        <p><strong>Token:</strong> ${val.challenge_token || "N/A"}</p>
      `;
      dataDiv.appendChild(c);
    });
  } catch (err) {
    dataDiv.innerHTML = "Error fetching data.";
  }
}

btn.addEventListener("click", fetchData);
window.onload = fetchData;
