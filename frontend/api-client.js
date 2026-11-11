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
  const details=observations.map(r=>`${r.section}: ${r.freshness}, ${r.source}, ${r.kind}`).join(' · ');
  const current=observations.every(r=>r.freshness==='current' && r.source==='live');
  const title=observations.some(r=>r.source.startsWith('recorded_')) ? 'RECORDED MONITOR RUN' : 'API DATA';
  return {current, text:`${title} — ${details}. Freshness is measurement status; response time is not capture time.`};
}
