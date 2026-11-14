import { loadSnapshot } from './data.js';
import { loadApiSnapshot, describeApi } from './api-client.js';
import { updateStatusIndicators } from './status.js';
import { mountCharts, captureChartState } from './graphs.js';

const $ = id => document.getElementById(id);
const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const number = value => value == null ? 'Unavailable' : new Intl.NumberFormat('en-CA', {maximumFractionDigits: 2}).format(value);
const time = value => new Intl.DateTimeFormat('en-CA', {timeZone:'America/Toronto', month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',timeZoneName:'short'}).format(new Date(value));
const label = value => String(value).replaceAll('_', ' ');
const empty = text => `<div class="empty">${escape(text)}</div>`;
const table = (headers, rows) => `<table><thead><tr>${headers.map(h=>`<th scope="col">${h}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>`;
let snapshot = null;
let pollTimer;
let busy = false;
const apiMode = () => $('source').value === 'api';

function chart(points, field, title, unit, unavailable = 'Measurements unavailable — capture failed') {
  if (!points.length) return `<div class="chart"><h3>${title}</h3>${empty('No measurements in this snapshot')}</div>`;
  const values = points.map(p => p[field]);
  const maximum = Math.max(1, ...values.filter(v => v != null));
  const rows = points.map(p=>`<tr><td>${escape(time(p.window_start))}</td><td>${number(p[field])}</td></tr>`);
  return `<div class="chart"><div class="chart-title"><div><h3>${title}</h3><span>${unit} · latest window</span></div><strong><span class="sr-only">${number(values.at(-1))}</span><span aria-hidden="true" ${values.at(-1) == null ? '' : `data-rate="${field}" data-value="${values.at(-1)}"`}>${number(values.at(-1))}</span></strong></div>${values.every(v=>v==null) ? empty(unavailable) : `<svg data-series="${escape(JSON.stringify(points.map(p=>({time:Date.parse(p.window_start),seconds:p.window_seconds,value:p[field]}))))}" data-unit="${unit}" viewBox="0 0 500 155" role="img" aria-label="${title}; vertical scale zero to ${maximum} ${unit}. Exact values in table below."><path d="M20 30H480 M20 80H480 M20 130H480" stroke="#e4ecef" fill="none"/><text x="20" y="19" font-size="10" fill="#617582">${number(maximum)} ${unit}</text><text x="20" y="148" font-size="10" fill="#617582">0</text></svg><div class="axis"><span>${escape(time(points[0].window_start))}</span><span>${escape(time(points.at(-1).window_start))}</span></div>`}<details class="measurement-table"><summary>View exact measurements</summary>${table(['Window start (Toronto)',unit],rows)}</details></div>`;
}

function render(data, recorded = false) {
  $('updated').textContent = `${apiMode() ? 'API response' : 'Snapshot'}: ${time(data.health.updated_at)}`;
  $('health').innerHTML = [['Capture',data.health.capture_status],['Model',data.health.model_status],['Firewall',data.health.firewall_status],['Mitigation mode',data.health.mitigation_mode]].map(([name,value])=>`<div class="health-card"><small>${name}</small><strong class="${['running','loaded','available'].includes(value)?'good':'warn'}">${escape(label(value))}</strong></div>`).join('');
  if (JSON.stringify(data.metrics.points) !== JSON.stringify(snapshot?.metrics.points)) {
    const chartState=captureChartState();
    const points = [...data.metrics.points].sort((a,b)=>Date.parse(a.window_start)-Date.parse(b.window_start));
    $('charts').innerHTML = chart(points,'packets_per_second','Packet rate','packets/s') + chart(points,'bytes_per_second','Byte rate','bytes/s',recorded ? 'Byte rates were not recorded in this audit log' : undefined);
    if ($('overview-charts')) $('overview-charts').innerHTML = $('charts').innerHTML.replaceAll('Exact values in table below.', 'Exact values available on the Traffic page.');
    mountCharts(chartState);
  }
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

function setNotice(text, tone = '') {
  const notice = $('notice');
  notice.className = tone;
  if (notice.textContent !== text) notice.textContent = text;
}

function setApiStatuses(data, summary) {
  const statuses = {
    detection: data ? `${data.detections.detections.length} API records · ${summary.current ? 'current input' : 'see freshness warning'}` : summary.text,
    mitigation: data ? `${data.health.mitigation_mode.replaceAll('_', ' ')} · ${data.blocks.blocks.length} confirmed records` : summary.text
  };
  for (const [name, text] of Object.entries(statuses)) {
    const item = $(`${name}-status`);
    item.dataset.tone = 'unknown';
    $(`${name}-summary`).textContent = text;
    item.setAttribute('aria-label', `${name === 'detection' ? 'Detection' : 'Mitigation'} API: ${text}`);
    $(`${name}-tip`).textContent = summary.text;
  }
}

async function refresh() {
  if (busy) return;
  busy = true;
  clearTimeout(pollTimer);
  const scenario=$('scenario').value;
  $('reload').disabled=true; $('scenario').disabled=true; $('source').disabled=true;
  if (!apiMode() || !snapshot && $('notice').className !== 'error') setNotice(apiMode() ? 'Loading API data…' : 'Loading sample data…');
  try {
    const apiResult=apiMode() ? await loadApiSnapshot() : null;
    const nextSnapshot=apiResult ? apiResult.snapshot : await loadSnapshot(scenario);
    const recorded = apiResult?.observations[0].source.startsWith('recorded_');
    render(nextSnapshot, recorded);
    snapshot=nextSnapshot;
    if (apiResult) {
      const summary=describeApi(apiResult.observations);
      setNotice(summary.text, summary.current ? '' : 'warning');
      setApiStatuses(snapshot, summary);
      return;
    }
    updateStatusIndicators(snapshot, scenario);
    $('notice').className=['stale','unavailable'].includes(scenario)?'warning':'';
    $('notice').textContent=scenario==='stale'?'STALE SNAPSHOT DEMO — showing an older example. Status and records may no longer reflect system state.':scenario==='unavailable'?'CAPTURE UNAVAILABLE DEMO — rates are unavailable, not zero. Previous example events remain visible.':'MOCK MODE — fixed October 22 example data. No live capture, model inference, or firewall connection.';
  } catch(error) {
    if (apiMode()) setApiStatuses(null, {text: snapshot ? 'Stale API snapshot' : 'API data unavailable'});
    else updateStatusIndicators(snapshot, 'error');
    setNotice(`${error.name === 'AbortError' ? 'API request timed out' : error instanceof TypeError ? 'Cannot reach the selected data server' : error.message}. ${snapshot?'Retaining the last successful snapshot; all displayed data is stale.':'No data loaded. System state is unknown.'}`, 'error');
    if(!snapshot) for(const id of ['health','charts','overview-charts','detections','blocks'].filter(id => $(id))) $(id).innerHTML=empty('Data unavailable');
  } finally {
    busy=false;
    $('reload').disabled=false; $('scenario').disabled=apiMode(); $('source').disabled=false;
    if(apiMode()) pollTimer=setTimeout(refresh,1000);
  }
}
function changeSource() {
  snapshot=null;
  if (apiMode()) setApiStatuses(null, {text: 'Awaiting API data'});
  else updateStatusIndicators(null);
  setNotice(apiMode() ? 'Loading API data…' : 'Loading sample data…');
  for(const id of ['health','charts','overview-charts','detections','blocks'].filter(id=>$(id))) $(id).innerHTML=empty('Awaiting selected data source');
  $('updated').textContent='Awaiting snapshot';
  $('detection-count').textContent=''; $('block-count').textContent='';
  document.querySelector('.sample').textContent=apiMode()?'● API DATA':'● SAMPLE DATA';
  $('reload').textContent=apiMode()?'Refresh now':'Reload sample';
  document.querySelector('footer span').textContent=apiMode()?'API schema v1 · Refresh after each completed request':'API schema v1 · Fixed example snapshot';
  for(const name of ['detection','mitigation']) document.querySelector(`#${name}-status small`).textContent=`${name==='detection'?'Detection':'Mitigation'} · ${apiMode()?'API':'demo'}`;
  refresh();
}
$('source').addEventListener('change',changeSource);
$('source').value=new URLSearchParams(location.search).get('source')==='api'?'api':'mock';
$('reload').addEventListener('click',refresh);
$('scenario').addEventListener('change',refresh);
changeSource();
