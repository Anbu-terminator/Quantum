// Use your actual ESP auth token 
const ESP_AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00";
const API_BASE = "/api/latest";

const dataDiv = document.getElementById("data");
const btn = document.getElementById("refreshBtn");

async function fetchData() {
  dataDiv.innerHTML = "Loading...";
  try {
    // Add a timestamp to prevent caching
    const url = `${API_BASE}?auth=${ESP_AUTH_TOKEN}&t=${Date.now()}`;
    const res = await fetch(url, { cache: "no-store" });

    if (res.status === 401) {
      dataDiv.innerHTML = "Unauthorized! Check ESP_AUTH_TOKEN.";
      return;
    }

    const json = await res.json();
    const data = json.decrypted;
    dataDiv.innerHTML = "";

    Object.entries(data).forEach(([key, val]) => {
      const c = document.createElement("div");
      c.className = "card";

      // Decrypted value may still contain ::challenge info
      let valueParts = (val.value || "").split("::");
      let value = valueParts[0];
      let challenge_id = val.challenge_id || valueParts[1] || "N/A";
      let challenge_token = val.challenge_token || valueParts[2] || "N/A";

      c.innerHTML = `
        <h3>${key}</h3>
        <p><strong>Value:</strong> ${value}</p>
        <p><strong>Challenge ID:</strong> ${challenge_id}</p>
        <p><strong>Token:</strong> ${challenge_token}</p>
      `;
      dataDiv.appendChild(c);
    });
  } catch (err) {
    dataDiv.innerHTML = "Error fetching data: " + err;
  }
}

// Refresh button
btn.addEventListener("click", fetchData);

// Fetch latest on page load
window.onload = fetchData;
