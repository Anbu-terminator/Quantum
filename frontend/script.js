async function fetchData() {
  const out = document.getElementById('readings');
  out.innerText = 'Fetching...';
  try {
    const res = await fetch('/decrypt_latest');
    if (!res.ok) {
      out.innerText = 'Server error: ' + res.status;
      return;
    }
    const j = await res.json();
    if (j.error) {
      out.innerText = 'Error: ' + JSON.stringify(j);
      return;
    }
    const data = j.data;
    out.innerHTML = '';
    for (let i = 1; i <= 5; i++) {
      const k = 'field' + i;
      const d = data[k];
      const div = document.createElement('div');
      div.className = 'reading';
      div.innerHTML = `<strong>${k}</strong>: ${d === null ? '<em>empty</em>' : (typeof d === 'object' ? JSON.stringify(d) : d)}`;
      out.appendChild(div);
    }
    const ts = document.createElement('div'); ts.style.marginTop='8px'; ts.style.fontSize='0.9em';
    ts.innerText = 'Created at: ' + (j.created_at || '-');
    out.appendChild(ts);
  } catch (e) {
    out.innerText = 'Fetch failed: ' + e.toString();
  }
}
document.getElementById('refresh').addEventListener('click', fetchData);
fetchData();
