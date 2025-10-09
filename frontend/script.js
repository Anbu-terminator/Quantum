const API = '/feeds/latest';

async function fetchLatest() {
  document.getElementById('status').textContent = "Fetching …";
  try {
    const res = await fetch(API);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const d = data.decrypted || {};

    setField('temp', d.Temperature?.value);
    setQ('qtemp', d.Temperature?.hmac_valid);

    setField('hum', d.Humidity?.value);
    setQ('qhum', d.Humidity?.hmac_valid);

    setField('ir', d.IR?.value);
    setQ('qir', d.IR?.hmac_valid);

    setField('l1', d.Label1?.value);
    setQ('ql1', d.Label1?.hmac_valid);

    setField('l2', d.Label2?.value);
    setQ('ql2', d.Label2?.hmac_valid);

    document.getElementById('status').textContent = "Updated";

    // show any attached challenge info for the first non-empty field
    let any = d.Temperature || d.Humidity || d.IR || d.Label1 || d.Label2;
    if (any && any.challenge) {
      document.getElementById('qproof').textContent = JSON.stringify(any.challenge, null, 2);
    } else {
      document.getElementById('qproof').textContent = "No challenge info available";
    }

  } catch (err) {
    document.getElementById('status').textContent = "Error fetching";
    console.error(err);
  }
}

function setField(id, v) {
  document.getElementById(id).textContent = v != null ? v : '—';
}
function setQ(id, ok) {
  document.getElementById(id).textContent = ok === null || ok === undefined ? '' : (ok ? '✓' : '✗');
}

fetchLatest();
setInterval(fetchLatest, 30000);
