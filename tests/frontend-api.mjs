import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const moduleUrl=s=>'data:text/javascript;base64,'+Buffer.from(s).toString('base64');
const validation=moduleUrl(readFileSync(new URL('../frontend/validation.js',import.meta.url),'utf8'));
const {loadApiSnapshot,describeApi}=await import(moduleUrl(readFileSync(new URL('../frontend/api-client.js',import.meta.url),'utf8').replace('./validation.js',validation)));
const fixture=JSON.parse(readFileSync(new URL('../docs/api-examples.json',import.meta.url),'utf8'));
const request=(options={})=>async url=>{const section=url.split('/').at(-1);return {ok:section!==options.fail,status:503,headers:new Headers(options.missing?{}:{'X-Dashboard-Freshness':options.freshness??'historical','X-Dashboard-Source':section===options.changedSource?'live':(options.source??'replay'),'X-Dashboard-Data-Kind':'synthetic'}),json:async()=>structuredClone(fixture[section])}};
test('loads four endpoints and preserves replay provenance',async()=>{const r=await loadApiSnapshot(request());assert.deepEqual(r.snapshot,fixture);assert.equal(describeApi(r.observations).current,false);assert.match(describeApi(r.observations).details,/historical, replay, synthetic/)});
test('partial endpoint failure rejects entire candidate snapshot',async()=>{await assert.rejects(loadApiSnapshot(request({fail:'metrics'})),/metrics request failed/)});
test('missing provenance never becomes current',async()=>{await assert.rejects(loadApiSnapshot(request({missing:true})),/headers missing/)});
test('only uniformly current live observations are current',()=>{const rows=['health','metrics','detections','blocks'].map(section=>({section,freshness:'current',source:'live',kind:'synthetic'}));assert.equal(describeApi(rows).current,true);rows[2].freshness='stale';assert.equal(describeApi(rows).current,false)});
test('mixed source provenance rejects the entire candidate snapshot',async()=>{await assert.rejects(loadApiSnapshot(request({changedSource:'metrics'})),/provenance changed/)});

test('labels an archived live run as recorded and historical', async () => {
  const result = await loadApiSnapshot(request({source:'recorded_live'}));
  const description = describeApi(result.observations);
  assert.equal(description.current, false);
  assert.match(description.text, /^Recorded monitor run.*synthetic test data.*not live monitoring/);
  assert.match(description.details, /historical, recorded_live, synthetic/);
});

test('recorded packet run has concise warning and full provenance details',()=>{
  const observations=['health','metrics','detections','blocks'].map(section=>({section,freshness:'historical',source:'recorded_replay',kind:'reviewed_packet_windows'}));
  const summary=describeApi(observations);
  assert.equal(summary.current,false);
  assert.equal(summary.text,'Recorded monitor run — saved packet measurements; not live monitoring.');
  for(const row of observations) assert.ok(summary.details.includes(`${row.section}: historical, recorded_replay, reviewed_packet_windows`));
  assert.match(summary.details,/API response time is not capture time/);
  observations[2].freshness='unavailable';
  assert.match(describeApi(observations).text,/unavailable/);
});
