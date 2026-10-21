const $=id=>document.getElementById(id);let current=null,connected=false,eventKey='';
async function api(path,method='GET',data){const r=await fetch('/api/'+path,{method,headers:{'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data),credentials:'same-origin'});const value=await r.json();if(!r.ok)throw new Error(value.error||'Request failed');return value;}
function error(e){$('error').textContent=e.message;$('error').hidden=false;}
function render(v){current=v;connected=true;$('error').hidden=true;const state=v.status;
 $('status').textContent=({pairing:'Awaiting terminal',connected:'Paired',planned:'Plan ready',approval:'Awaiting approval',running:'Simulation running',complete:'Preview complete',ended:'Disconnected'})[state]||state;
 $('pair-panel').hidden=true;$('waiting-panel').hidden=state!=='pairing';$('plan-panel').hidden=!['connected','planned','complete'].includes(state);$('progress-panel').hidden=!['approval','running','complete'].includes(state);$('disconnect').hidden=state==='ended';
 $('plan').hidden=state!=='planned';if(state==='planned'){$('plan-title').textContent=v.hostname;$('steps').replaceChildren(...(v.steps||[]).map(text=>{const li=document.createElement('li');li.textContent=text;return li;}));}
 $('progress-title').textContent=state==='complete'?'Preview complete':state==='running'?'Following the setup':'Waiting for local approval';$('progress-copy').textContent=state==='complete'?'No deployment resources were changed. You can prepare another plan or disconnect.':state==='running'?'The terminal is running the built-in simulation.':'Return to the terminal and type the requested hostname to approve this simulation.';
 const key=JSON.stringify(v.events);if(key!==eventKey){eventKey=key;$('events').replaceChildren(...(v.events||[]).map(text=>{const li=document.createElement('li');li.textContent=text;return li;}));}
 ['pair','plan','run'].forEach(x=>$('nav-'+x).classList.toggle('current',x===(state==='pairing'?'pair':['connected','planned'].includes(state)?'plan':'run')));
}
async function action(button,fn){button.disabled=true;try{await fn();}catch(e){error(e);}finally{button.disabled=false;}}
$('pair-form').addEventListener('submit',e=>{e.preventDefault();action(e.submitter,async()=>{const code=$('code').value;$('code').value='';render(await api('pair','POST',{code}));});});
$('plan-form').addEventListener('submit',e=>{e.preventDefault();action(e.submitter,async()=>render(await api('plan','POST',{hostname:$('hostname').value})));});
$('run').addEventListener('click',e=>action(e.currentTarget,async()=>render(await api('run','POST',{digest:current.digest}))));
$('disconnect').addEventListener('click',e=>action(e.currentTarget,async()=>{await api('session','DELETE');connected=false;current=null;$('pair-panel').hidden=false;['waiting-panel','plan-panel','progress-panel','disconnect'].forEach(x=>$(x).hidden=true);$('status').textContent='Disconnected';}));
setInterval(async()=>{if(!connected)return;try{render(await api('session'));}catch(e){connected=false;error(e);$('status').textContent='Connection lost';$('run').disabled=true;}},1000);
api('session').then(render).catch(()=>{});
