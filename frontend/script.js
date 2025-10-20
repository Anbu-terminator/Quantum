const AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00"; // Must match server.py

const fields = {
  field1: document.getElementById("field1"),
  field2: document.getElementById("field2"),
  field3: document.getElementById("field3"),
  field4: document.getElementById("field4"),
  field5: document.getElementById("field5"),
};

const irIndicator = document.getElementById("field4");
const timestampEl = document.getElementById("timestamp");

let tempData=[], humData=[], bpmData=[], spo2Data=[], labels=[];
let tempChart, humChart, bpmChart;

function initCharts(){
  tempChart = new Chart(document.getElementById("tempChart").getContext("2d"), {
    type:"line",
    data:{labels, datasets:[{label:"Temperature (°C)", data: tempData, borderColor:"#FF5722", backgroundColor:"rgba(255,87,34,0.2)"}]},
    options:{responsive:true, animation:{duration:800}}
  });

  humChart = new Chart(document.getElementById("humChart").getContext("2d"), {
    type:"line",
    data:{labels, datasets:[{label:"Humidity (%)", data: humData, borderColor:"#03A9F4", backgroundColor:"rgba(3,169,244,0.2)"}]},
    options:{responsive:true, animation:{duration:800}}
  });

  bpmChart = new Chart(document.getElementById("bpmChart").getContext("2d"), {
    type:"line",
    data:{labels, datasets:[
      {label:"BPM", data:bpmData, borderColor:"#4CAF50", backgroundColor:"rgba(76,175,80,0.2)"},
      {label:"SpO2", data:spo2Data, borderColor:"#FF9800", backgroundColor:"rgba(255,152,0,0.2)"}
    ]},
    options:{responsive:true, animation:{duration:800}}
  });
}

async function fetchData(){
  try{
    const res = await fetch(`/api/latest?auth=${AUTH_TOKEN}`);
    const data = await res.json();
    if(!data.ok) throw new Error("Fetch failed");

    const s = data.decrypted;
    timestampEl.textContent = `Last update: ${new Date(data.timestamp).toLocaleString()}`;

    fields.field1.textContent = s["Quantum Key"];
    fields.field2.textContent = s["Temperature"];
    fields.field3.textContent = s["Humidity"];
    fields.field5.textContent = typeof s["MAX30100"]==="object"? `BPM:${s["MAX30100"].BPM}, SpO2:${s["MAX30100"].SpO2}`: s["MAX30100"];

    if(s["IR Sensor"]===1) irIndicator.style.backgroundColor="#4CAF50";
    else if(s["IR Sensor"]===0) irIndicator.style.backgroundColor="#F44336";
    else irIndicator.style.backgroundColor="gray";

    const label = new Date(data.timestamp).toLocaleTimeString();
    labels.push(label);
    tempData.push(Number(s["Temperature"])||0);
    humData.push(Number(s["Humidity"])||0);
    bpmData.push(s["MAX30100"]?.BPM||0);
    spo2Data.push(s["MAX30100"]?.SpO2||0);

    if(labels.length>20){ labels.shift(); tempData.shift(); humData.shift(); bpmData.shift(); spo2Data.shift(); }

    tempChart.update(); humChart.update(); bpmChart.update();

  } catch(err){
    console.error(err);
    document.getElementById("status").textContent="Error connecting to backend";
  }
}

initCharts();
fetchData();
setInterval(fetchData, 5000);
