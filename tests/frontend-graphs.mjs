import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../frontend/graph-model.js',import.meta.url),'utf8');
const {segments,nearest}=await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const point=(time,value,seconds=1)=>({time,value,seconds});
test('nulls and absent one-second windows split recorded history',()=>{
 const data=[point(0,1),point(1000,null),point(2000,2),point(5000,3),point(6000,0)];
 assert.deepEqual(segments(data),[[0],[2],[3,4]]);
 assert.equal(nearest(data,3500),-1);
 assert.equal(nearest(data,1000),1);
});
test('zero, single-point and all-unavailable histories retain their meaning',()=>{
 assert.deepEqual(segments([point(0,0)]),[[0]]);
 assert.deepEqual(segments([point(0,null)]),[]);
 assert.equal(nearest([],10),-1);
 assert.equal(nearest([point(0,9)],300),0);
});
test('inspection snaps to actual records and respects variable window durations',()=>{
 const data=[point(0,8,2),point(2000,12,2),point(4000,null,2)];
 assert.deepEqual(segments(data),[[0,1]]);
 assert.equal(nearest(data,1600),1);
 assert.equal(nearest(data,3900),2);
});
test('the 30 fabricated windows retain original final measurements',()=>{
 const data=JSON.parse(readFileSync(new URL('../docs/api-examples.json',import.meta.url),'utf8')).metrics.points;
 assert.equal(data.length,30);
 for(const p of data.slice(-2)){assert.equal(p.packets_per_second,4212);assert.equal(p.bytes_per_second,252720);}
 assert.deepEqual(segments(data.map(p=>point(Date.parse(p.window_start),p.packets_per_second,p.window_seconds))),[Array.from({length:30},(_,i)=>i)]);
});
const validationSource=readFileSync(new URL('../frontend/validation.js',import.meta.url),'utf8');
const validationUrl='data:text/javascript;base64,'+Buffer.from(validationSource).toString('base64');
const loaderSource=readFileSync(new URL('../frontend/data.js',import.meta.url),'utf8').replace('./validation.js',validationUrl);
const {loadSnapshot}=await import(`data:text/javascript;base64,${Buffer.from(loaderSource).toString('base64')}`);
const fixture=readFileSync(new URL('../docs/api-examples.json',import.meta.url),'utf8');
globalThis.fetch=async()=>({ok:true,json:async()=>JSON.parse(fixture)});
test('all six demo scenarios retain data-state semantics',async()=>{
 assert.equal((await loadSnapshot('sample')).metrics.points.length,30);
 assert.equal((await loadSnapshot('empty')).metrics.points.length,0);
 assert.ok((await loadSnapshot('zero')).metrics.points.every(p=>p.packets_per_second===0));
 const unavailable=await loadSnapshot('unavailable');assert.ok(unavailable.metrics.points.every(p=>p.packets_per_second===null));assert.ok(unavailable.blocks.blocks.length);
 assert.deepEqual(await loadSnapshot('stale'),await loadSnapshot('sample'));
 await assert.rejects(loadSnapshot('error'),/Simulated connection failure/);
});
