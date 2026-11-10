import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../frontend/validation.js',import.meta.url),'utf8');
const {validateSnapshot}=await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const fixture=JSON.parse(readFileSync(new URL('../docs/api-examples.json',import.meta.url),'utf8'));
test('shared API fixture is accepted',()=>assert.equal(validateSnapshot(fixture),fixture));
test('zero and null remain valid distinct measurements',()=>{const d=structuredClone(fixture);d.metrics.points[0].packets_per_second=0;d.metrics.points[0].bytes_per_second=null;validateSnapshot(d);assert.equal(d.metrics.points[0].packets_per_second,0);assert.equal(d.metrics.points[0].bytes_per_second,null)});
for(const [name,change] of [
  ['missing history',d=>delete d.metrics.points],
  ['missing rate',d=>delete d.metrics.points[0].packets_per_second],
  ['invalid timestamp',d=>d.health.updated_at='bad'],
  ['negative rate',d=>d.metrics.points[0].bytes_per_second=-1],
  ['numeric detection ID',d=>d.detections.detections[0].id=42],
  ['numeric block ID',d=>d.blocks.blocks[0].id=42],
  ['invalid block IPv4',d=>d.blocks.blocks[0].source_ip='192.0.2.256'],
  ['invalid attribution IPv4',d=>d.detections.detections.find(x=>x.scope==='source').source_ip='not-an-address'],
  ['numeric aggregate reference',d=>d.detections.detections.find(x=>x.scope==='source').aggregate_detection_id=42],
  ['unsupported share basis',d=>d.detections.detections.find(x=>x.scope==='source').attribution.share_basis='matching_protocol_packets'],
  ['invalid score',d=>d.detections.detections[0].attack_score=2],
  ['aggregate claiming source',d=>d.detections.detections.find(x=>x.scope==='aggregate').source_ip='10.0.0.1'],
  ['source missing evidence',d=>d.detections.detections.find(x=>x.scope==='source').attribution=null],
  ['backwards expiry',d=>d.blocks.blocks[0].expires_at=d.blocks.blocks[0].blocked_at]
]) test(`rejects ${name}`,()=>{const d=structuredClone(fixture);change(d);assert.throws(()=>validateSnapshot(d),/Invalid sample data/)});
