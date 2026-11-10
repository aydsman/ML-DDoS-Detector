// Validate the display contract before replacing a previously usable snapshot.
export function validateSnapshot(data) {
  const fail = message => { throw new Error(`Invalid sample data: ${message}`); };
  const date = value => typeof value === 'string' && Number.isFinite(Date.parse(value));
  const id = value => typeof value === 'string' && value.trim().length > 0;
  const ipv4 = value => {
    if (typeof value !== 'string') return false;
    const octets = value.split('.');
    return octets.length === 4 && octets.every(octet => /^(0|[1-9][0-9]{0,2})$/.test(octet) && Number(octet) <= 255);
  };
  const numeric = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
  for (const key of ['health', 'metrics', 'detections', 'blocks']) {
    if (data?.[key]?.schema_version !== '1') fail(`${key} schema version`);
    if (!date(data[key].updated_at)) fail(`${key} update time`);
  }
  const h = data.health;
  for (const [key, allowed] of Object.entries({capture_status:['running','stopped','error'],model_status:['loading','loaded','error'],firewall_status:['available','unavailable','error'],mitigation_mode:['monitor_only','automatic']})) {
    if (!allowed.includes(h[key])) fail(`health.${key}`);
  }
  for (const [key, field] of [['metrics','points'],['detections','detections'],['blocks','blocks']]) {
    if (!Array.isArray(data[key][field])) fail(`${key}.${field} must be an array`);
  }
  for (const p of data.metrics.points) {
    if (!date(p?.window_start) || !numeric(p.window_seconds) || p.window_seconds === 0) fail('measurement window');
    for (const key of ['packets_per_second','bytes_per_second']) if (p[key] !== null && !numeric(p[key])) fail(key);
  }
  for (const d of data.detections.detections) {
    if (!id(d?.id) || !date(d.detected_at) || !numeric(d.attack_score) || d.attack_score > 1 || typeof d.model_version !== 'string') fail('detection fields');
    if (!['aggregate','source'].includes(d.scope) || !['no_action','alert','block_requested'].includes(d.decision)) fail('detection scope or decision');
    if (d.scope === 'aggregate' && (d.source_ip !== null || d.attribution !== null || d.aggregate_detection_id !== null || d.decision === 'block_requested')) fail('aggregate attribution');
    if (d.scope === 'source') {
      const a = d.attribution;
      if (!ipv4(d.source_ip) || !id(d.aggregate_detection_id) || !a || !['tcp','udp','icmp'].includes(a.protocol)) fail('source attribution');
      if (!numeric(a.packets_per_second) || !numeric(a.packet_share) || a.packet_share > 1 || !Number.isInteger(a.consecutive_windows) || a.consecutive_windows < 1) fail('source evidence');
      if (a.share_basis !== 'all_selected_packets' || (a.syn_per_second !== null && !numeric(a.syn_per_second))) fail('source evidence units');
    }
  }
  for (const b of data.blocks.blocks) {
    if (!id(b?.id) || !ipv4(b.source_ip) || typeof b.reason !== 'string' || !date(b.blocked_at) || !date(b.expires_at) || Date.parse(b.expires_at) <= Date.parse(b.blocked_at)) fail('confirmed block fields');
  }
  return data;
}
