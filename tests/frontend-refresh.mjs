import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const fixture=JSON.parse(readFileSync(new URL('../docs/api-examples.json',import.meta.url),'utf8'));
const app=readFileSync(new URL('../frontend/app.js',import.meta.url),'utf8').replace(/^import .*;$/gm,'');
const html=readFileSync(new URL('../frontend/index.html',import.meta.url),'utf8');
const settle=()=>new Promise(resolve=>setImmediate(resolve));
function setup() {
  const elements=new Map();
  class Element {
    constructor(){this.textContent='';this.className='';this.dataset={};this.attributes={};this.listeners={};this.disabled=false;this.writes=0;}
    set innerHTML(value){this.html=value;this.writes++;for(const match of value.matchAll(/id="([^"]+)"/g)) elements.set(match[1],new Element());}
    get innerHTML(){return this.html??'';}
    setAttribute(name,value){this.attributes[name]=value;}
    addEventListener(name,callback){this.listeners[name]=callback;}
  }
  for(const match of html.matchAll(/id="([^"]+)"/g)) elements.set(match[1],new Element());
  const get=id=>elements.get(id);
  get('scenario').value='sample';
  const selectors=new Map();
  const pending=[];
  const timers=new Map();let timerId=0;
  const context={
    document:{getElementById:get,querySelector:selector=>{if(!selectors.has(selector))selectors.set(selector,new Element());return selectors.get(selector);}},
    location:{search:'?source=api'}, URLSearchParams,Intl,Date,JSON,TypeError,
    loadApiSnapshot:()=>new Promise((resolve,reject)=>pending.push({resolve,reject,source:'api'})),
    loadSnapshot:()=>new Promise((resolve,reject)=>pending.push({resolve,reject,source:'mock'})),
    describeApi:()=>({current:false,text:'Recorded measurements; not live.',details:'Full recorded provenance.'}),
    updateStatusIndicators:()=>{},captureChartState:()=>({}),mountCharts:()=>{},
    setTimeout:callback=>{timers.set(++timerId,callback);return timerId;},clearTimeout:id=>timers.delete(id)
  };
  vm.runInNewContext(app,context);
  return {get,pending,timers,respond:async(data=fixture)=>{const candidate=pending.shift();candidate.resolve(candidate.source==='api'?{snapshot:structuredClone(data),observations:[{source:'recorded_replay',kind:'reviewed_packet_windows'}]}:structuredClone(data));await settle();},poll:()=>{const [id,callback]=timers.entries().next().value;timers.delete(id);callback();}};
}

test('polls preserve health cards, unchanged charts and tables, while showing refresh state',async()=>{
  const h=setup();
  assert.equal(h.get('refresh-state').textContent,'Refreshing…');
  await h.respond();
  const health=h.get('health');const writes=health.writes;
  const capture=h.get('health-capture_status');
  const detectionWrites=h.get('detections').writes;
  const chartWrites=h.get('charts').writes;
  h.poll();
  assert.equal(h.get('reload').disabled,false);
  assert.equal(h.get('source').disabled,false);
  assert.equal(h.get('refresh-state').dataset.busy,'true');
  const changed=structuredClone(fixture);changed.health.updated_at='2026-11-18T19:00:00Z';
  await h.respond(changed);
  assert.equal(health.writes,writes);
  assert.equal(h.get('health-capture_status'),capture);
  assert.equal(h.get('detections').writes,detectionWrites);
  assert.equal(h.get('charts').writes,chartWrites);
  assert.equal(h.get('refresh-state').textContent,'Auto-refresh · 1s');
  assert.match(h.get('updated').textContent,/Nov 18/);
  changed.health.capture_status='stopped';
  h.poll();await h.respond(changed);
  assert.equal(health.writes,writes);
  assert.equal(capture.textContent,'stopped');
  assert.equal(capture.className,'warn');
});

test('source change supersedes a pending poll; its late response cannot overwrite sample data',async()=>{
  const h=setup();await h.respond();h.poll();
  h.get('source').value='mock';h.get('source').listeners.change();
  const sample=structuredClone(fixture);sample.health.model_status='unavailable';
  const old=h.pending.shift();
  await h.respond(sample);
  old.resolve({snapshot:fixture,observations:[{source:'recorded_replay',kind:'reviewed_packet_windows'}]});
  await settle();
  assert.equal(h.get('health-model_status').textContent,'unavailable');
  assert.equal(h.get('provenance').hidden,true);
  assert.equal(h.timers.size,0);
  assert.equal(h.get('refresh-state').textContent,'Sample loaded');
});

test('poll failure retains displayed cards and marks the snapshot stale; retry recovers',async()=>{
  const h=setup();await h.respond();const writes=h.get('health').writes;
  h.poll();h.pending.shift().reject(new TypeError('network'));await settle();
  assert.equal(h.get('health').writes,writes);
  assert.equal(h.get('notice').className,'error');
  assert.match(h.get('notice').textContent,/stale/);
  assert.equal(h.get('refresh-state').textContent,'Update failed');
  h.poll();await h.respond();
  assert.equal(h.get('health').writes,writes);
  assert.equal(h.get('notice').className,'warning');
  assert.equal(h.get('refresh-state').dataset.busy,'false');
});
