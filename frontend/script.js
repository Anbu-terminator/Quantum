const API = "/latest"; // If serving frontend from same server, proxied; otherwise use full URL like http://server:5000/latest

async function fetchLatest() {
  try {
    const res = await fetch(API);
    if (!res.ok) throw new Error('Fetch failed: ' + res.status);
    const json = await res.json();
    render(json);
  } catch (err) {
    document.getElementById('cards').innerHTML = `<div class="card"><h2>Error</h2><p>${err.message}</p></div>`;
  }
}

function render(data) {
  const cards = document.getElementById('cards');
  cards.innerHTML = "";

  const feeds = (data.feeds_decrypted || []);
  if (feeds.length === 0) {
    cards.innerHTML = `<div class="card"><h2>No data</h2><p>--</p></div>`;
    return;
  }

  // show the latest feed (first in list)
  const latest = feeds[0];
  document.getElementById('last-updated').textContent = `Latest: ${latest.created_at || 'unknown'}`;

  // Temperature
  const tempCard = document.createElement('div'); tempCard.className = 'card';
  tempCard.innerHTML = `<h2>Temperature</h2><p>${latest.temperature ?? '—'}</p>`;
  cards.appendChild(tempCard);

  // Humidity
  const humCard = document.createElement('div'); humCard.className = 'card';
  humCard.innerHTML = `<h2>Humidity</h2><p>${latest.humidity ?? '—'}</p>`;
  cards.appendChild(humCard);

  // IR
  const irCard = document.createElement('div'); irCard.className = 'card';
  irCard.innerHTML = `<h2>IR Sensor</h2><p>${latest.ir ?? '—'}</p>`;
  cards.appendChild(irCard);

  // Raw JSON
  document.getElementById('raw').textContent = JSON.stringify(latest, null, 2);
}

// simple polling every 15s
fetchLatest();
setInterval(fetchLatest, 15000);
