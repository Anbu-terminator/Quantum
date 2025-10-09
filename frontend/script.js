// Use your actual ESP auth token
const API_URL = "/api/latest?auth=6772698c38270a210fabf1133fc6ad00";

const dataDiv = document.getElementById("data");
const btn = document.getElementById("refreshBtn");

async function fetchData() {
  dataDiv.innerHTML = "Loading...";
  try {
    const res = await fetch(API_URL);
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

      let value = val.value || "N/A";
      let challenge_id = val.challenge_id || "N/A";
      let challenge_token = val.challenge_token || "N/A";

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

// Fetch automatically on page load
window.onload = fetchData;
