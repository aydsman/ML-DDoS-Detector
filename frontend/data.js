// Replace this loader with the four API calls when the backend contract is reviewed.
export async function loadSnapshot(scenario = 'sample') {
  if (scenario === 'error') throw new Error('Simulated connection failure');
  const response = await fetch('../docs/api-examples.json', { cache: 'no-store' });
  if (!response.ok) throw new Error(`Sample request failed (${response.status})`);
  const data = await response.json();
  for (const key of ['health', 'metrics', 'detections', 'blocks']) {
    if (data[key]?.schema_version !== '1') throw new Error(`Unsupported ${key} schema`);
  }
  if (scenario === 'empty' || scenario === 'zero') {
    if (scenario === 'empty') data.metrics.points = [];
    else data.metrics.points.forEach(p => { p.packets_per_second = 0; p.bytes_per_second = 0; });
    data.detections.detections = [];
    data.blocks.blocks = [];
    data.health.mitigation_mode = 'monitor_only';
  }
  if (scenario === 'unavailable') {
    data.health.capture_status = 'error';
    data.health.mitigation_mode = 'monitor_only';
    data.metrics.points.forEach(p => { p.packets_per_second = null; p.bytes_per_second = null; });
  }
  return data;
}
