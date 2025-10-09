const AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00"; // must match config. Optional.

async function fetchLatest() {
  document.getElementById('status').textContent = "Fetching latest...";
  try {
    const res = await fetch(`/feeds/latest?auth=${AUTH_TOKEN}`);
    if (!res.ok) {
      const t = await res.text();
      document.getElementById('status').textContent = `Error ${res.status}`;
      document.getElementById('raw').textContent = t;
      return;
    }
    const obj = await res.json();
    const dec = obj.decrypted || {};
    // fields
    setField('Label1', dec.Label1);
    setField('Temperature', dec.Temperature);
    setField('Humidity', dec.Humidity);
    setField('IR', dec.IR);
    setField('Label2', dec.Label2);

    // meta (hmac status)
    setMeta('Label1', dec.Label1?.hmac_ok, dec.Label1?.challenge_id);
    setMeta('Temperature', dec.Temperature?.hmac_ok, dec.Temperature?.challenge_id);
    setMeta('Humidity', dec.Humidity?.hmac_ok, dec.Humidity?.challenge_id);
    setMeta('IR', dec.IR?.hmac_ok, dec.IR?.challenge_id);
    setMeta('Label2', dec.Label2?.hmac_ok, dec.Label2?.challenge_id);

    document.getElementById('raw').textContent = JSON.stringify(obj._raw_feed || obj, null, 2);
    document.getElementById('status').textContent = "Updated";
  } catch (err) {
    console.error(err);
    document.getElementById('status').textContent = "Fetch error";
    document.getElementById('raw').textContent = String(err);
  }
}

function setField(id, obj) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = obj?.value ?? obj ?? '—';
}

function setMeta(id, hmac_ok, challenge_id) {
  const el = document.getElementById('m' + id);
  if (!el) return;
  if (hmac_ok === true) el.textContent = `hmac ✓   (challenge ${challenge_id || '—'})`;
  else if (hmac_ok === false) el.textContent = `hmac ✗   (challenge ${challenge_id || '—'})`;
  else el.textContent = '';
}

fetchLatest();
setInterval(fetchLatest, 15000);
