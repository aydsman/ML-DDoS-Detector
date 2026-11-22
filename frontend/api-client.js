import { validateSnapshot } from './validation.js';

export async function loadApiSnapshot(request = fetch) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 4000);
  try {
    const sections = ['health', 'metrics', 'detections', 'blocks'];
    const results = await Promise.all(sections.map(async section => {
      const response = await request(`/api/${section}`, {cache:'no-store', signal:controller.signal});
      if (!response.ok) throw new Error(`${section} request failed (${response.status})`);
      const freshness = response.headers.get('X-Dashboard-Freshness');
      const source = response.headers.get('X-Dashboard-Source');
      const kind = response.headers.get('X-Dashboard-Data-Kind');
      if (!['empty','current','stale','unavailable','stopped','historical'].includes(freshness) || !['none','live','replay','recorded_live','recorded_replay'].includes(source) || !['none','synthetic','reviewed_packet_windows'].includes(kind)) throw new Error(`${section} freshness/provenance headers missing or invalid`);
      return {section, data:await response.json(), freshness, source, kind};
    }));
    const {source, kind} = results[0];
    if (results.some(result => result.source !== source || result.kind !== kind)) {
      throw new Error('API provenance changed during refresh');
    }
    const snapshot = validateSnapshot(Object.fromEntries(results.map(r=>[r.section,r.data])));
    return {snapshot, observations:results.map(({section,freshness,source,kind})=>({section,freshness,source,kind}))};
  } finally {clearTimeout(timeout);controller.abort();}
}

export function describeApi(observations) {
  const details = observations.map(r=>`${r.section}: ${r.freshness}, ${r.source}, ${r.kind}`).join(' · ');
  const current = observations.every(r=>r.freshness==='current' && r.source==='live');
  const synthetic = observations.some(r=>r.kind==='synthetic');
  const recorded = observations.some(r=>r.source.startsWith('recorded_'));
  const replay = observations.some(r=>r.source==='replay');
  const states = [...new Set(observations.map(r=>r.freshness))];
  let text;
  if (recorded) text = `Recorded monitor run — saved ${synthetic ? 'synthetic test data' : 'packet measurements'}; not live monitoring.`;
  else if (replay) text = `Replay data — ${synthetic ? 'synthetic test measurements' : 'recorded packet measurements'}; not live capture.`;
  else if (synthetic) text = 'Synthetic test data — does not describe real network traffic.';
  else text = current ? 'Live API measurements.' : 'API measurements are not current.';
  const warnings = states.filter(s=>s!=='current' && !(s==='historical' && (recorded || replay)));
  if (warnings.length) text += ` Measurement status: ${warnings.join(', ')}.`;
  return {current, text, details:`${details}. Freshness describes measurement status; API response time is not capture time.`};
}
