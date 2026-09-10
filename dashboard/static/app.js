async function u(){
var s=await fetch('/api/stats');
var d=await s.json();
document.getElementById('T').textContent=d.total;
document.getElementById('O').textContent=d.allowed;
document.getElementById('K').textContent=d.killed;
document.getElementById('Q').textContent=d.quarantined;
document.getElementById('P').textContent=d.processEvents;
document.getElementById('N').textContent=d.networkEvents;
var e=await fetch('/api/events');
var ev=await e.json();
var tb=document.getElementById('tb');
tb.innerHTML='';
for(var i=ev.length-1;i>=0&&i>=ev.length-50;i--){
var r=ev[i];
var tr=document.createElement('tr');
tr.innerHTML='<td>'+new Date(r.timestamp).toLocaleTimeString()+'</td>'+'<td>'+r.type+'</td>'+'<td>'+r.pid+'</td>'+'<td>'+r.exe+'</td>'+'<td>'+r.reason+'</td>'+'<td>'+r.action+'</td>';
tb.appendChild(tr);
}
}
u();
setInterval(u,3000);