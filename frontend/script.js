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
      c.className = "card " + (val.hmac_valid ? "valid" : "invalid");
      c.innerHTML = `
        <h3>${key}</h3>
        <p><strong>Value:</strong> ${val.value}</p>
        <p><strong>HMAC:</strong> ${val.hmac_valid ? "✅ Valid" : "❌ Invalid"}</p>
      `;
      dataDiv.appendChild(c);
    });
  } catch (err) {
    dataDiv.innerHTML = "Error fetching data.";
  }
}

btn.addEventListener("click", fetchData);
window.onload = fetchData;
