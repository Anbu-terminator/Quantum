// script.js

// Fetch latest ThingSpeak feed and display decrypted values
async function fetchLatestFeed() {
    try {
        const res = await fetch('/feeds/latest?auth=6772698c38270a210fabf1133fc6ad00');
        const data = await res.json();
        const feedList = document.getElementById('feed-list');
        feedList.innerHTML = '';

        if (!data.decrypted) {
            feedList.innerHTML = '<li>No decrypted data available</li>';
            return;
        }

        for (const key in data.decrypted) {
            const val = data.decrypted[key];
            const li = document.createElement('li');
            li.textContent = `${key}: ${val.value ?? 'N/A'} (HMAC valid: ${val.hmac_valid})`;
            feedList.appendChild(li);
        }
    } catch (err) {
        console.error('Error fetching feed:', err);
    }
}

// Get new quantum challenge
async function getQuantumChallenge() {
    try {
        const res = await fetch('/quantum/challenge');
        const data = await res.json();
        const challengeInfo = document.getElementById('challenge-info');
        if (data.ok) {
            challengeInfo.textContent = JSON.stringify(data, null, 2);
        } else {
            challengeInfo.textContent = `Error: ${data.error}`;
        }
    } catch (err) {
        console.error('Error fetching quantum challenge:', err);
    }
}

// Event listener for button
document.getElementById('new-challenge').addEventListener('click', getQuantumChallenge);

// Auto-fetch latest feed every 10 seconds
fetchLatestFeed();
setInterval(fetchLatestFeed, 10000);
