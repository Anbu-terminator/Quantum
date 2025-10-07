async function loadLatest(){
  try{
    const r = await fetch('/api/latest');
    const j = await r.json();
    const rows = document.getElementById('rows');
    rows.innerHTML = '';
    document.getElementById('meta').innerText = `Entry: ${j.entry_id || '-'}  |  Time: ${j.created_at || '-'}`;
    if(!j.ok){ rows.innerHTML = `<tr><td colspan="3">Error: ${j.error}</td></tr>`; return; }
    const dec = j.decoded || {};
    for(let i=1;i<=5;i++){
      const key = 'field'+i;
      const cell = dec[key];
      let status = 'unknown';
      let val = '';
      if(!cell) { status='missing'; }
      else if(cell.ok){
        status = 'ok';
        val = cell.value;
      } else {
        status = cell.error;
      }
      rows.innerHTML += `<tr><td>${key}</td><td>${val}</td><td class="${status==='ok' ? 'ok' : 'err'}">${status}</td></tr>`;
    }
  }catch(e){
    document.getElementById('rows').innerHTML = `<tr><td colspan="3">Fetch error: ${e.toString()}</td></tr>`;
  }
}

loadLatest();
setInterval(loadLatest, 15_000); // refresh every 15s
