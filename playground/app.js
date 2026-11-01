import {relationships} from './topology.js';
const $ = selector => document.querySelector(selector);
const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const clone = value => structuredClone(value);
const state = {routers:[],policy:{},findings:[],baseline:null,originals:new Map(),selected:null,tab:'objects',modified:new Set(),engineReady:false,policyModified:false,busy:0,revision:0,exportResult:null};
let worker, requestId=0;
const pending = new Map();
function notify(message,error=false) { const box=$('#notice');box.textContent=message;box.classList.toggle('error',error);box.hidden=!message; }
function engineStatus(text) { $('#engine-status').textContent=text; }
function startEngine() {
  worker = new Worker('./engine-worker.js',{type:'module'});
  worker.onmessage = ({data}) => {
    if(data.type==='ready') { state.engineReady=true;engineStatus('Python engine ready');renderInspector();runChecks(false);return; }
    if(data.id && pending.has(data.id)) { const {resolve,reject}=pending.get(data.id);pending.delete(data.id);data.ok?resolve(data):reject(new Error(data.error)); }
    else if(data.type==='error') { state.engineReady=false;engineStatus('Engine unavailable · refresh to retry');notify('The Python engine could not start. The snapshot is still viewable. '+data.error,true);renderInspector(); }
  };
  worker.onerror = event => {state.engineReady=false;engineStatus('Engine unavailable · refresh to retry');notify('Unable to start the browser Python engine. '+event.message,true);for(const {reject} of pending.values())reject(new Error('Python worker failed'));pending.clear();renderInspector();};
  worker.postMessage({action:'boot'});
}
function callEngine(action,extra={}) {
  if(!state.engineReady) return Promise.reject(new Error('The Python engine is still loading. Please wait.'));
  const id=++requestId;
  return new Promise((resolve,reject)=>{pending.set(id,{resolve,reject});worker.postMessage({id,action,routers:state.routers,policy:state.policy,selected:state.selected,...extra});});
}
function current() {return state.routers.find(r=>r.name===state.selected);}
function countFor(name,severity='P1') {return state.findings.filter(f=>f.device===name&&f.severity===severity).length;}
function select(name) {state.selected=name;state.exportResult=null;render();}
function render() {renderSidebar();renderMetrics();renderMap();renderInspector();renderFindings();}
function renderSidebar() {
  $('#device-count').textContent=state.routers.length+' nodes';
  const query=$('#search').value.toLowerCase();
  let last='';
  $('#device-list').innerHTML=state.routers.filter(r=>r.name.toLowerCase().includes(query)).map(r=>{
    const label=({edge:'EDGE & CORE',core:'EDGE & CORE',border:'BORDERS',bng:'SUBSCRIBER GATEWAYS',switch:'DISTRIBUTION',sw:'DISTRIBUTION'})[r.role]||'OTHER NODES';
    const heading=label===last?'':`<div class="group-label">${esc(label)}</div>`;last=label;
    const count=countFor(r.name);
    return heading+`<button class="device-row ${r.name===state.selected?'selected':''}" data-device="${esc(r.name)}" aria-pressed="${r.name===state.selected}"><span class="device-symbol">${r.role==='switch'?'▤':'◇'}</span>${esc(r.name)}${state.modified.has(r.name)?'<span class="device-modified">·</span>':''}${count?`<span class="device-count">${count}</span>`:''}</button>`;
  }).join('');
  $('#device-list').querySelectorAll('[data-device]').forEach(button=>button.onclick=()=>select(button.dataset.device));
}
function renderMetrics() {
  $('#metric-routers').textContent=state.routers.length;
  $('#metric-peers').textContent=state.routers.reduce((n,r)=>n+r.bgp.peers.length,0)+' configured BGP sessions';
  for(const [id,severity] of [['p1','P1'],['p2','P2'],['unknown','UNKNOWN']]) $('#metric-'+id).textContent=state.findings.filter(f=>f.severity===severity).length;
}
function renderMap() {
  const positions=new Map();
  const groups=[state.routers.filter(r=>!['border','bng','switch','sw'].includes(r.role)),state.routers.filter(r=>r.role==='border'),state.routers.filter(r=>r.role==='bng'),state.routers.filter(r=>['switch','sw'].includes(r.role))];
  const ys=[14,37,62,87];
  groups.forEach((routers,row)=>routers.forEach((r,i)=>positions.set(r.name,{x:(i+1)*100/(routers.length+1),y:ys[row]})));
  const edges=relationships(state.routers);
  const lines=edges.map(edge=>{
    const a=positions.get(edge.a),b=positions.get(edge.b);if(!a||!b)return '';
    const good=edge.status==='reciprocal',warning=edge.status==='one-sided';
    const color=good?'#4d9a84':warning?'#ca925a':'#536c78';
    const dash=edge.inferred||edge.status==='inactive'?' stroke-dasharray="1.1 1.1"':'';
    return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${color}" stroke-width=".35"${dash}/>`;
  }).join('');
  $('#network-map').innerHTML=`<svg viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">${lines}</svg>`+state.routers.map(r=>{
    const p=positions.get(r.name);return `<button class="map-node ${r.name===state.selected?'selected':''}" data-node="${esc(r.name)}" style="left:${p.x}%;top:${p.y}%" aria-label="Inspect ${esc(r.name)}" aria-pressed="${r.name===state.selected}"><strong><i class="node-dot ${countFor(r.name)?'has-issues':''}"></i>${esc(r.name)}</strong><small>${esc(r.role.toUpperCase())}</small></button>`;
  }).join('');
  $('#network-map').querySelectorAll('[data-node]').forEach(button=>button.onclick=()=>select(button.dataset.node));
}
function card(title,count,body,open=false) {return `<details class="object-card" ${open?'open':''}><summary>${title}<span>${count}</span></summary><div class="object-content">${body||'<span class="muted">No explicit configuration</span>'}</div></details>`;}
function kv(key,value) {return `<div class="kv"><span>${esc(key)}</span><code>${esc(value??'unknown')}</code></div>`;}
function renderObjects(r) {
  const fw=r.firewall_v4;
  const rules=fw.rules.map((f,i)=>`<div class="rule ${f.enabled?'':'disabled'}"><span class="muted">${i+1}</span><span class="tag ${['drop','reject'].includes(f.action)?'drop':''}">${esc(f.action)}</span><code>${esc([f.chain,f.protocol,f.source_network||f.source_group,f.destination_ports?'→ '+f.destination_ports:'',f.ingress?'on '+f.ingress:'',!f.enabled?'(disabled)':'',Object.keys(f.extra).length?'[opaque predicates]':''].filter(Boolean).join(' · '))}</code></div>`).join('');
  const peers=r.bgp.peers.map(p=>`<div class="rule ${p.enabled?'':'disabled'}"><span class="tag">${esc(p.role||'BGP')}</span><code><b>${esc(p.name)}</b> → ${esc(p.remote_address||'unknown')}<br>Redistribute: ${esc(p.redistribute.join(', ')||'none explicit')}<br>IN ${esc(p.import_policy||'—')} / OUT ${esc(p.export_policy||'—')}</code></div>`).join('');
  return card('FirewallV4',fw.rules.length+' rules',kv('Connection tracking',fw.connection_tracking===null?'unknown':fw.connection_tracking?'enabled':'disabled')+rules,true)+
    card('BGP',r.bgp.peers.length+' peers',peers)+
    card('Addresses',r.addresses.length,r.addresses.map(a=>kv(a.interface,a.address+(a.enabled?'':' · disabled'))).join(''))+
    card('Interfaces',r.interfaces.length,r.interfaces.map(i=>kv(i.name,[i.kind,i.mode,!i.enabled?'disabled':''].filter(Boolean).join(' · '))).join(''))+
    card('PPP & RADIUS',r.ppp_servers.length+' / '+r.radius.length,r.ppp_servers.map(s=>kv(s.interface,'MTU '+(s.mtu??'unknown'))).join('')+r.radius.map(s=>kv(s.address,(s.timeout_ms??'?')+'ms · '+(s.source_address??'unknown'))).join(''))+
    card('SNMP & DNS','Services',kv('SNMP',r.snmp_enabled===null?'unknown':r.snmp_enabled?'enabled':'disabled')+kv('Location',r.snmp_location||'not set')+kv('DNS',r.dns.join(', ')||'not set'))+
    card('Import coverage',r.unexported.length+' uncovered',`<p class="helper">${r.unexported.length} source commands are outside full export coverage. The model is an inspection subset, not a complete vendor configuration.</p>`+r.diagnostics.map(d=>`<div class="rule"><code>${esc(d.code)}<br>${esc(d.message)}</code></div>`).join(''));
}
function renderExperiment(r) {
  const disabled=state.engineReady?'':'disabled';
  return `<p class="helper">Change the semantic model, then re-run the heuristics. Your device configuration is never changed.</p>
  <div class="experiment-block"><h3>Quick experiments</h3><div class="inline-actions"><button class="button small" data-quick="final-drop" ${disabled}>Enable final input drop</button>${r.role==='bng'?`<button class="button small" data-quick="radius" ${disabled}>Use 500ms / 2000ms</button>`:''}<button class="button small" data-quick="reset" ${disabled}>Reset this router</button></div></div>
  ${r.role==='bng'?`<div class="experiment-block"><h3>Subscriber settings</h3><label class="field">Connection tracking<select id="conntrack" ${disabled}><option value="null" ${r.firewall_v4.connection_tracking===null?'selected':''}>Unknown</option><option value="false" ${r.firewall_v4.connection_tracking===false?'selected':''}>Disabled</option><option value="true" ${r.firewall_v4.connection_tracking===true?'selected':''}>Enabled</option></select></label>${r.ppp_servers.map((s,i)=>`<label class="field">PPPoE MTU · ${esc(s.interface)}<input type="number" min="576" max="9216" value="${s.mtu??''}" data-mtu="${i}" ${disabled}></label>`).join('')}</div>`:''}
  <div class="experiment-block"><h3>BGP sessions</h3>${r.bgp.peers.length?r.bgp.peers.map((p,i)=>`<label class="toggle-row"><span>${esc(p.name)} <span class="muted">${esc(p.remote_address||'')}</span></span><input type="checkbox" data-peer="${i}" ${p.enabled?'checked':''} ${disabled}></label>`).join(''):'<p class="muted">No BGP sessions in this model.</p>'}</div>
  <div class="experiment-block"><h3>Input firewall rules</h3>${r.firewall_v4.rules.map((f,i)=>f.chain==='input'?`<label class="toggle-row"><code>${i+1}. ${esc([f.action,f.protocol,f.source_group||f.source_network,f.destination_ports,f.ingress].filter(Boolean).join(' · '))}</code><input type="checkbox" data-rule="${i}" ${f.enabled?'checked':''} ${disabled}></label>`:'').join('')||'<p class="muted">No input rules.</p>'}</div>
  <div class="experiment-block"><h3>Test a packet</h3><p class="helper">Evaluate the ordered IPv4 input rules for a source and protocol. Unknown predicates remain unknown.</p><form id="packet-form"><label class="field">Source address<input id="probe-source" value="${esc(state.policy.snmp_pollers?.[0]||'198.51.100.9')}" required></label><div class="field-row"><label class="field">Protocol<select id="probe-protocol"><option>udp</option><option>tcp</option><option>icmp</option><option>ospf</option></select></label><label class="field">Destination port<input id="probe-port" type="number" min="0" max="65535" value="161" required></label></div><button class="button small" ${disabled}>Evaluate packet</button></form><div id="packet-result" role="status"></div></div>
  <div><h3>Test a route</h3><form id="route-form"><label class="field">Applied filter chain<select id="probe-chain">${[...new Set(r.bgp.policies.map(p=>p.chain))].map(c=>`<option>${esc(c)}</option>`).join('')||'<option value="">No policies</option>'}</select></label><label class="field">Route prefix<input id="probe-prefix" value="195.10.222.1/32" required></label><button class="button small" ${disabled}>Evaluate route</button></form><div id="route-result" role="status"></div></div>`;
}
function renderExport() {
  return `<p class="helper">Render a supported configuration fragment from the current semantic model. Missing feature mappings remain explicit. No output is applied to a device.</p><form id="export-form"><div class="field-row"><label class="field">Target platform<select id="export-vendor"><option value="routeros">RouterOS</option><option value="cisco-ios">Cisco IOS · ACL</option></select></label><label class="field">Target version<input id="export-version" value="7.19.3" required></label></div><label class="toggle-row"><span>Allow a clearly labelled partial fragment</span><input id="export-partial" type="checkbox" checked></label><button class="button primary small" ${state.engineReady?'':'disabled'}>Preview conversion</button></form><div id="export-result" role="status"></div><p class="model-note">RouterOS export targets 7.1–7.19 syntax. IOS export produces an unattached named ACL. Interfaces, PPP, RADIUS, SNMP and other inspection-only features block full export.</p>`;
}
function renderInspector() {
  const r=current();if(!r)return;
  $('#selected-role').textContent=r.role.toUpperCase()+' / SEMANTIC ROUTER';$('#selected-name').textContent=r.name;
  $('#selected-platform').textContent=(r.platform.hardware||'Hardware unknown')+' · RouterOS '+(r.platform.version||((r.platform.family||'?')+'.x inferred · exact version unknown'));
  $('#edited-badge').hidden=!state.modified.has(r.name);
  document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b.dataset.tab===state.tab));
  const content=$('#inspector-content');
  if(state.tab==='objects')content.innerHTML=renderObjects(r);
  if(state.tab==='experiment'){content.innerHTML=renderExperiment(r);bindExperiments(r);}
  if(state.tab==='export'){content.innerHTML=renderExport();bindExport();}
  if(state.tab==='json'){
    content.innerHTML=`<p class="helper">Edit the common model directly. Apply validates its structure and reruns the same Python checks across the workspace.</p><form id="model-form"><label class="field">Common model JSON<textarea id="model-json" class="json-editor" spellcheck="false"></textarea></label><div class="inline-actions"><button class="button primary small" ${state.engineReady?'':'disabled'}>Apply & run checks</button><button type="button" class="button small" id="download-model">↓ Model</button></div></form><div id="model-error" class="error-text" role="status"></div>`;
    $('#model-json').value=JSON.stringify(r,null,2);
    $('#model-form').onsubmit=async event=>{event.preventDefault();try{const value=JSON.parse($('#model-json').value);if(value.name!==r.name)throw new Error('Keep the model name unchanged; use import to add a new router.');const routers=state.routers.map(item=>item.name===r.name?value:item);const result=await callEngine('audit',{routers});state.routers=routers;state.findings=result.findings;state.modified.add(r.name);state.revision++;render();notify('Model applied. Policy checks re-evaluated in Python.');}catch(error){$('#model-error').textContent=error.message;}};
    $('#download-model').onclick=()=>download(r.name+'.json',r);
  }
}
async function mutate(edit,message) {
  edit(current());state.modified.add(state.selected);state.revision++;render();await runChecks(false);notify(message||'Model updated. Policy checks re-evaluated.');
}
function bindExperiments(r) {
  document.querySelectorAll('[data-quick]').forEach(b=>b.onclick=async()=>{
    if(b.dataset.quick==='reset'){const original=state.originals.get(r.name);if(original){state.routers=state.routers.map(item=>item.name===r.name?clone(original):item);state.modified.delete(r.name);state.revision++;render();await runChecks(false);notify('Router restored to its original snapshot.');}return;}
    if(b.dataset.quick==='radius')await mutate(router=>router.radius.filter(s=>s.enabled).forEach((s,i)=>s.timeout_ms=i===0?500:2000),'RADIUS timeouts updated in this model.');
    if(b.dataset.quick==='final-drop')await mutate(router=>{const rules=router.firewall_v4.rules;const candidate=[...rules].reverse().find(f=>f.chain==='input'&&['drop','reject'].includes(f.action)&&!f.protocol&&!f.source_network&&!f.source_group&&!f.destination_network&&!f.destination_group&&!f.destination_ports&&!f.source_ports&&!f.ingress&&!f.egress&&!Object.keys(f.extra).length);if(candidate){candidate.enabled=true;rules.splice(rules.indexOf(candidate),1);rules.push(candidate);}else rules.push({chain:'input',action:'drop',protocol:null,source_network:null,source_group:null,destination_network:null,destination_group:null,destination_ports:null,source_ports:null,ingress:null,egress:null,enabled:true,extra:{},source:null});},'Final input drop enabled in this model.');
  });
  const track=$('#conntrack');if(track)track.onchange=()=>mutate(router=>router.firewall_v4.connection_tracking=JSON.parse(track.value));
  document.querySelectorAll('[data-mtu]').forEach(input=>input.onchange=()=>{if(!input.reportValidity())return;mutate(router=>router.ppp_servers[Number(input.dataset.mtu)].mtu=Number(input.value));});
  document.querySelectorAll('[data-peer]').forEach(input=>input.onchange=()=>mutate(router=>router.bgp.peers[Number(input.dataset.peer)].enabled=input.checked));
  document.querySelectorAll('[data-rule]').forEach(input=>input.onchange=()=>mutate(router=>router.firewall_v4.rules[Number(input.dataset.rule)].enabled=input.checked));
  $('#packet-form').onsubmit=async event=>{event.preventDefault();await probe('packet-result',{kind:'firewall',source:$('#probe-source').value.trim(),protocol:$('#probe-protocol').value,port:$('#probe-port').value});};
  $('#route-form').onsubmit=async event=>{event.preventDefault();await probe('route-result',{kind:'route',chain:$('#probe-chain').value,prefix:$('#probe-prefix').value.trim()});};
}
async function probe(target,values) {
  const box=$('#'+target);
  try{const result=await callEngine('probe',values);box.innerHTML=`<div class="result-box">Verdict: <span class="verdict ${esc(result.verdict)}">${esc(result.verdict.toUpperCase())}</span>\nConfiguration evaluation only.</div>`;}catch(error){box.textContent=error.message;box.className='error-text';}
}
function bindExport() {
  $('#export-vendor').onchange=()=>$('#export-version').value=$('#export-vendor').value==='routeros'?'7.19.3':'15.2';
  $('#export-form').onsubmit=async event=>{event.preventDefault();const box=$('#export-result');box.textContent='Rendering with Python…';try{const result=await callEngine('export',{vendor:$('#export-vendor').value,version:$('#export-version').value.trim(),partial:$('#export-partial').checked});state.exportResult=result;box.innerHTML=`<div class="model-note">${result.complete?'All represented features covered. Review target defaults and attachment before deployment.':'PARTIAL FRAGMENT · This is not a replacement device configuration.'}</div><pre class="result-box">${esc(result.text)}</pre>${result.diagnostics.length?`<div class="error-text">${result.diagnostics.map(esc).join('\n')}</div>`:''}<button id="download-export" class="button small">↓ Download fragment</button>`;$('#download-export').onclick=()=>download(current().name+($('#export-vendor').value==='routeros'?'.rsc':'.ios'),result.text);}catch(error){box.innerHTML=`<div class="error-text">Export blocked:\n${esc(error.message)}</div>`;}};
}
function renderFindings() {
  const scope=$('#scope-filter').value,severity=$('#severity-filter').value;
  const items=state.findings.filter(f=>(scope!=='selected'||f.device===state.selected)&&(severity==='all'||f.severity===severity));
  const order={P1:0,P2:1,UNKNOWN:2};items.sort((a,b)=>order[a.severity]-order[b.severity]);
  $('#findings-count').textContent=items.length;
  $('#findings-body').innerHTML=items.map(f=>`<tr><td><span class="severity ${esc(f.severity)}">${esc(f.severity)}</span></td><td><button class="table-device" data-finding-device="${esc(f.device)}">${esc(f.device)}</button></td><td>${esc(f.check)}</td><td>${esc(f.message)}</td><td>${f.source?esc(f.source.path.split('/').pop()+':'+f.source.line):'model'}</td></tr>`).join('')||'<tr><td colspan="5"><div class="empty-state">No findings match this view. Unknowns remain separate from passes.</div></td></tr>';
  $('#findings-body').querySelectorAll('[data-finding-device]').forEach(b=>b.onclick=()=>select(b.dataset.findingDevice));
  $('#check-summary').textContent=(state.engineReady?'Same Python policy engine as the CLI':'Baseline snapshot · Python engine is loading')+' · '+state.routers.length+' models · '+state.modified.size+' modified'+(state.policyModified?' · policy edited':'')+' · no connectivity probes';
}
async function runChecks(showNotice=true) {
  if(!state.engineReady){if(showNotice)notify('The Python engine is loading. Try again in a moment.');return;}
  const revision=state.revision;state.busy++;$('#run-checks').disabled=true;$('#run-checks').textContent='Running checks…';
  try{const result=await callEngine('audit');if(revision===state.revision){state.findings=result.findings;renderSidebar();renderMetrics();renderMap();renderFindings();if(showNotice)notify('Checks completed with the deterministic Python engine. No config was sent for ML processing.');}}
  catch(error){notify('Checks could not complete: '+error.message,true);}
  finally{state.busy--;if(!state.busy){$('#run-checks').disabled=false;$('#run-checks').textContent='▶ Run all checks';}}
}
function download(name,value) {const blob=new Blob([typeof value==='string'?value:JSON.stringify(value,null,2)],{type:typeof value==='string'?'text/plain':'application/json'});const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
async function importConfig(name,text,version='') {
  if(text.length>5*1024*1024)throw new Error('Please load a config smaller than 5 MB.');
  if(!/^[a-zA-Z0-9_.-]+$/.test(name))throw new Error('Use letters, digits, dots, underscores or hyphens in the router name.');
  const result=await callEngine('import',{name,text,version});
  const index=state.routers.findIndex(r=>r.name===name);
  if(index===-1)state.routers.push(result.router);else state.routers[index]=result.router;
  if(!state.originals.has(name))state.originals.set(name,clone(result.router));
  state.modified.add(name);state.selected=name;state.revision++;
}
$('#edit-policy').onclick=()=>{$('#policy-json').value=JSON.stringify(state.policy,null,2);$('#policy-error').textContent='';$('#apply-policy').disabled=!state.engineReady;$('#policy-dialog').showModal();};
$('#close-policy').onclick=()=>$('#policy-dialog').close();
$('#policy-form').onsubmit=async event=>{event.preventDefault();$('#apply-policy').disabled=true;try{const policy=JSON.parse($('#policy-json').value);const result=await callEngine('audit',{policy});state.policy=policy;state.policyModified=true;state.findings=result.findings;state.revision++;$('#policy-dialog').close();render();notify('Network policy updated. Deterministic checks re-evaluated.');}catch(error){$('#policy-error').textContent=error.message;}finally{$('#apply-policy').disabled=false;}};
$('#search').oninput=renderSidebar;
$('#run-checks').onclick=()=>runChecks();
$('#scope-filter').onchange=renderFindings;$('#severity-filter').onchange=renderFindings;
document.querySelectorAll('[data-tab]').forEach(button=>button.onclick=()=>{state.tab=button.dataset.tab;renderInspector();});
$('#reset-all').onclick=async()=>{state.routers=clone(state.baseline.routers);state.policy=clone(state.baseline.policy);state.findings=clone(state.baseline.findings);state.originals=new Map(state.routers.map(r=>[r.name,clone(r)]));state.modified.clear();state.policyModified=false;state.revision++;if(!current())state.selected=state.routers[0].name;render();if(state.engineReady)await runChecks(false);notify('Workspace restored to the bundled snapshot.');};
$('#download-workspace').onclick=()=>download('semanticrouter-workspace.json',{routers:state.routers,policy:state.policy});
$('#download-report').onclick=()=>download('semanticrouter-report.json',{kind:'configuration-only',findings:state.findings,modified:[...state.modified]});
$('#upload-button').onclick=()=>$('#import-dialog').showModal();$('#close-import').onclick=()=>$('#import-dialog').close();$('#choose-files').onclick=()=>$('#file-input').click();
$('#file-input').onchange=async event=>{
  const files=[...event.target.files];if(!files.length)return;
  if(files.some(file=>file.size>5*1024*1024)){notify('Please choose config files smaller than 5 MB.',true);return;}
  if(files.length===1){$('#import-name').value=files[0].name.replace(/\.[^.]+$/,'');$('#import-text').value=await files[0].text();}
  else{try{for(const file of files)await importConfig(file.name.replace(/\.[^.]+$/,''),await file.text());$('#import-dialog').close();render();await runChecks(false);notify('Loaded '+files.length+' exports locally in your browser.');}catch(error){notify(error.message,true);}}
  event.target.value='';
};
$('#import-form').onsubmit=async event=>{event.preventDefault();$('#import-submit').disabled=true;try{await importConfig($('#import-name').value.trim(),$('#import-text').value,$('#import-version').value.trim());$('#import-dialog').close();render();await runChecks(false);notify('Export parsed into semantic objects locally. Policy checks updated.');}catch(error){notify(error.message,true);}finally{$('#import-submit').disabled=false;}};
async function main() {
  try{
    const response=await fetch('./data.json');if(!response.ok)throw new Error('Snapshot could not be loaded.');
    const data=await response.json();state.baseline=clone(data);state.routers=clone(data.routers);state.policy=clone(data.policy);state.findings=clone(data.findings);state.originals=new Map(state.routers.map(r=>[r.name,clone(r)]));state.selected=state.routers.find(r=>r.name==='bng-X1')?.name||state.routers[0].name;$('#snapshot-mode').textContent=data.mode;render();startEngine();
  }catch(error){notify('Unable to load the playground: '+error.message,true);engineStatus('Snapshot unavailable');}
}
main();
