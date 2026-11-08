// These summaries describe fixed demonstration snapshots, never live safety.
export function summarizeSnapshot(data, state = 'sample') {
  if (!data) return { detection: [state === 'error' ? 'Data unavailable' : 'Awaiting data', 'unknown'], mitigation: [state === 'error' ? 'Data unavailable' : 'Awaiting data', 'unknown'] };
  if (state === 'error' || state === 'stale') return { detection: ['Stale snapshot', 'unknown'], mitigation: ['Stale snapshot', 'unknown'] };
  if (state === 'unavailable' || data.health.capture_status !== 'running' || data.health.model_status !== 'loaded') {
    return { detection: ['Detection unavailable', 'unknown'], mitigation: mitigationSummary(data) };
  }
  return {
    detection: [data.detections.detections.length ? 'Detection records in snapshot' : 'No detection records', data.detections.detections.length ? 'attention' : 'neutral'],
    mitigation: mitigationSummary(data)
  };
}
function mitigationSummary(data) {
  if (data.health.firewall_status !== 'available') return ['Firewall unavailable', 'unknown'];
  const count = data.blocks.blocks.length;
  const mode = data.health.mitigation_mode === 'monitor_only' ? 'Monitor only' : 'Automatic mode';
  return [`${mode} · ${count} confirmed ${count === 1 ? 'block' : 'blocks'} in snapshot`, count ? 'attention' : 'neutral'];
}
export function updateStatusIndicators(data, state) {
  const result = summarizeSnapshot(data, state);
  for (const name of ['detection', 'mitigation']) {
    const [text, tone] = result[name];
    const item = document.getElementById(`${name}-status`);
    item.dataset.tone = tone;
    document.getElementById(`${name}-summary`).textContent = text;
    item.setAttribute('aria-label', `${name === 'detection' ? 'Detection' : 'Mitigation'} demo: ${text}`);
    document.getElementById(`${name}-tip`).textContent = `Demo: ${text}. ${name === 'detection' ? 'An empty history does not prove there is no attack.' : 'Mode is separate from confirmed blocks; these historical examples do not confirm current protection.'} Live state is unknown.${state === 'error' || state === 'stale' ? ' Retained data may no longer reflect system state.' : ''}`;
  }
}
