import { loadSnapshot } from './data.js';

const $ = id => document.getElementById(id);
const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const number = value => value == null ? 'Unavailable' : new Intl.NumberFormat('en-CA', {maximumFractionDigits: 2}).format(value);
const time = value => new Intl.DateTimeFormat('en-CA', {timeZone:'America/Toronto', month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',timeZoneName:'short'}).format(new Date(value));
const label = value => String(value).replaceAll('_', ' ');
const empty = text => `<div class="empty">${escape(text)}</div>`;
const table = (headers, rows) => `<table><thead><tr>${headers.map(h=>`<th scope="col">${h}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>`;
let snapshot = null;

function chart(points, field, title, unit, color) {
  if (!points.length) return `<div class="chart"><h3>${title}</h3>${empty('No measurements in this snapshot')}</div>`;
  const values = points.map(p => p[field]);
  const maximum = Math.max(1, ...values.filter(v => v != null));
  const times = points.map(p => Date.parse(p.window_start));
  const duration = Math.max(1, times.at(-1) - times[0]);
  const coordinates = values.map((v,i) => v == null ? null : [20 + (times[i]-times[0])/duration*460, 130 - v/maximum*100]);
  let segments = [], current = [];
  for (const point of coordinates) { if (point) current.push(point.join(',')); else { if(current.length) segments.push(current); current=[]; } }
  if(current.length) segments.push(current);
  const plot = segments.map(s=>`<polyline points="${s.join(' ')}" fill="none" stroke="${color}" stroke-width="3"/>`).join('') + coordinates.filter(Boolean).map(([x,y])=>`<circle cx="${x}" cy="${y}" r="4" fill="${color}"/>`).join('');
  const rows = points.map(p=>`<tr><td>${escape(time(p.window_start))}</td><td>${number(p[field])}</td></tr>`);
  return `<div class="chart"><div class="chart-title"><div><h3>${title}</h3><span>${unit} · latest window</span></div><strong>${number(values.at(-1))}</strong></div>${values.every(v=>v==null) ? empty('Measurements unavailable — capture failed') : `<svg viewBox="0 0 500 155" role="img" aria-label="${title}; vertical scale zero to ${maximum} ${unit}. Exact values in table below."><path d="M20 30H480 M20 80H480 M20 130H480" stroke="#e4ecef" fill="none"/><text x="20" y="19" font-size="10" fill="#617582">${number(maximum)} ${unit}</text><text x="20" y="148" font-size="10" fill="#617582">0</text>${plot}</svg><div class="axis"><span>${escape(time(points[0].window_start))}</span><span>${escape(time(points.at(-1).window_start))}</span></div>`}<details class="measurement-table"><summary>View exact measurements</summary>${table(['Window start (Toronto)',unit],rows)}</details></div>`;
}

function render(data) {
  $('updated').textContent = `Snapshot: ${time(data.health.updated_at)}`;
  $('health').innerHTML = [['Capture',data.health.capture_status],['Model',data.health.model_status],['Firewall',data.health.firewall_status],['Mitigation mode',data.health.mitigation_mode]].map(([name,value])=>`<div class="health-card"><small>${name}</small><strong class="${['running','loaded','available'].includes(value)?'good':'warn'}">${escape(label(value))}</strong></div>`).join('');
  const points = [...data.metrics.points].sort((a,b)=>Date.parse(a.window_start)-Date.parse(b.window_start));
  $('charts').innerHTML = chart(points,'packets_per_second','Packet rate','packets/s','#087f83') + chart(points,'bytes_per_second','Byte rate','bytes/s','#516cb0');
  if ($('overview-charts')) $('overview-charts').innerHTML = $('charts').innerHTML.replaceAll('Exact values in table below.', 'Exact values available on the Traffic page.');
  const detections = [...data.detections.detections].sort((a,b)=>Date.parse(b.detected_at)-Date.parse(a.detected_at)||a.id.localeCompare(b.id));
  $('detection-count').textContent = `${detections.length} records`;
  $('detections').innerHTML = detections.length ? table(['Time / event','Scope / source','Aggregate model score','Source-rule evidence','Decision'],detections.map(d=>{
    const a=d.attribution;
    const evidence=a ? `${escape(a.protocol.toUpperCase())} · ${number(a.packets_per_second)} packets/s<small>SYN: ${a.syn_per_second==null?'Not applicable':number(a.syn_per_second)+' /s'}<br>${number(a.packet_share*100)}% of ${escape(label(a.share_basis))}<br>${number(a.consecutive_windows)} consecutive qualifying windows<br>Aggregate event: ${escape(d.aggregate_detection_id)}</small>` : 'Not applicable';
    return `<tr><td>${escape(time(d.detected_at))}<small>${escape(d.id)}</small></td><td><span class="pill">${escape(d.scope)}</span><small>${escape(d.source_ip??'Unknown source')}</small></td><td><strong>${number(d.attack_score*100)}%</strong><small>${escape(d.model_version)}${d.scope==='source'?'<br>Copied from aggregate event':''}</small></td><td>${evidence}</td><td><span class="pill ${d.decision==='block_requested'?'request':''}">${escape(label(d.decision))}</span></td></tr>`;
  })) : empty('No detection records in this snapshot');
  const blocks=[...data.blocks.blocks].sort((a,b)=>Date.parse(b.blocked_at)-Date.parse(a.blocked_at)||a.id.localeCompare(b.id));
  $('block-count').textContent=`${blocks.length} confirmed ${blocks.length === 1 ? 'record' : 'records'}`;
  $('blocks').innerHTML=blocks.length?table(['Source / record','Reason','Confirmed at (Toronto)','Planned expiry (Toronto)'],blocks.map(b=>`<tr><td><strong>${escape(b.source_ip)}</strong><small>${escape(b.id)}</small></td><td>${escape(b.reason)}</td><td>${escape(time(b.blocked_at))}</td><td>${escape(time(b.expires_at))}</td></tr>`)):empty('No confirmed blocks in this snapshot');
}

async function refresh() {
  const scenario=$('scenario').value;
  $('reload').disabled=true; $('scenario').disabled=true;
  $('notice').className=''; $('notice').textContent='Loading sample data…';
  try {
    const nextSnapshot=await loadSnapshot(scenario);
    render(nextSnapshot);
    snapshot=nextSnapshot;
    $('notice').className=['stale','unavailable'].includes(scenario)?'warning':'';
    $('notice').textContent=scenario==='stale'?'STALE SNAPSHOT DEMO — showing an older example. Status and records may no longer reflect system state.':scenario==='unavailable'?'CAPTURE UNAVAILABLE DEMO — rates are unavailable, not zero. Previous example events remain visible.':'MOCK MODE — fixed October 22 example data. No live capture, model inference, or firewall connection.';
  } catch(error) {
    $('notice').className='error';
    $('notice').textContent=`${error.message}. ${snapshot?'Retaining the last successful snapshot; all displayed data is stale.':'No data loaded. System state is unknown.'}`;
    if(!snapshot) for(const id of ['health','charts','overview-charts','detections','blocks'].filter(id => $(id))) $(id).innerHTML=empty('Data unavailable');
  } finally { $('reload').disabled=false; $('scenario').disabled=false; }
}
$('reload').addEventListener('click',refresh);
$('scenario').addEventListener('change',refresh);
refresh();
