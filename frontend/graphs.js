import { segments, nearest } from './graph-model.js';
const NS='http://www.w3.org/2000/svg';
const motion=matchMedia('(prefers-reduced-motion: reduce)');
const exact=n=>new Intl.NumberFormat('en-CA',{maximumFractionDigits:20}).format(n);
const stamp=t=>new Intl.DateTimeFormat('en-CA',{timeZone:'America/Toronto',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',timeZoneName:'short'}).format(t);
let controllers=[]; let firstMount=true;
function element(name,attrs,parent) {const node=document.createElementNS(NS,name);for(const [key,value] of Object.entries(attrs)) node.setAttribute(key,value);parent.append(node);return node;}
class Graph {
  constructor(svg) {
    this.svg=svg; this.points=JSON.parse(svg.dataset.series); this.unit=svg.dataset.unit;
    this.maximum=Math.max(1,...this.points.map(p=>p.value??0)); this.progress=1; this.index=-1;
    this.latest=this.points.findLastIndex(p=>p.value!=null);
    this.lines=segments(this.points).map(indices=>({indices,node:element('polyline',{fill:'none',stroke:'currentColor','stroke-width':3},svg)}));
    // Isolated measurements remain visible without manufacturing a connecting line.
    this.isolated=this.lines.filter(s=>s.indices.length===1 && s.indices[0]!==this.latest).map(s=>({index:s.indices[0],node:element('path',{class:'recorded-point',stroke:'currentColor','stroke-width':3},svg)}));
    this.marker=element('circle',{r:4,fill:'currentColor'},svg);
    this.hover=element('circle',{r:5,fill:'currentColor',stroke:'#fff','stroke-width':2,visibility:'hidden'},svg);
    this.tip=document.createElement('div');this.tip.className='graph-tooltip';this.tip.hidden=true;this.tip.id=`graph-tip-${svg.closest('.view').id}-${this.unit==='packets/s'?'packets':'bytes'}`;document.body.append(this.tip);
    this.live=document.createElement('span');this.live.className='sr-only';this.live.setAttribute('aria-live','polite');svg.after(this.live);
    svg.setAttribute('tabindex','0');svg.setAttribute('role','group');svg.setAttribute('aria-label',svg.getAttribute('aria-label')+' Presentation entrance only; not a recorded rise from zero. Use Left and Right arrows, Home or End to inspect; Escape dismisses.');
    this.events=new AbortController(); const options={signal:this.events.signal};
    svg.addEventListener('pointermove',e=>{if(e.pointerType==='mouse')this.pointer(e);},options);
    svg.addEventListener('pointerleave',()=>{if(!this.pinned)this.dismissTimer=setTimeout(()=>this.dismiss(),120);},options);
    svg.addEventListener('pointerenter',()=>clearTimeout(this.dismissTimer),options);
    this.tip.addEventListener('pointerenter',()=>clearTimeout(this.dismissTimer),options);
    this.tip.addEventListener('pointerleave',()=>{if(!this.pinned)this.dismiss();},options);
    svg.addEventListener('pointerup',e=>{if(e.pointerType!=='mouse'){this.pinned=true;this.pointer(e);}},options);
    svg.addEventListener('keydown',e=>{
      if(e.key==='Escape'){this.dismiss();return;}
      if(!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;
      e.preventDefault();if(this.progress<1)return;
      let i=this.index<0?this.latest:this.index;
      if(e.key==='Home')i=0;else if(e.key==='End')i=this.points.length-1;else i=Math.max(0,Math.min(this.points.length-1,i+(e.key==='ArrowLeft'?-1:1)));
      this.inspect(i,true);
    },options);
    svg.addEventListener('blur',()=>this.dismiss(),options);
    this.observer=new ResizeObserver(()=>this.layout());this.observer.observe(svg);
    this.layout();
  }
  coords(i) {const p=this.points[i];const duration=Math.max(1,this.points.at(-1).time-this.points[0].time);return [20+(p.time-this.points[0].time)/duration*Math.max(1,this.width-40),this.height-25-(p.value??0)/this.maximum*Math.max(1,this.height-55)*this.progress];}
  layout() {
    const width=this.svg.clientWidth,height=this.svg.clientHeight;if(!width||!height)return;
    if(this.width && (width!==this.width||height!==this.height))this.finish();
    this.width=width;this.height=height;this.svg.setAttribute('viewBox',`0 0 ${width} ${height}`);
    this.svg.querySelector('path').setAttribute('d',`M20 30H${width-20} M20 ${(height+5)/2}H${width-20} M20 ${height-25}H${width-20}`);
    this.svg.querySelectorAll('text')[1].setAttribute('y',height-5);this.draw();this.dismiss();
  }
  draw() {
    if(!this.width)return;
    for(const s of this.lines)s.node.setAttribute('points',s.indices.map(i=>this.coords(i).join(',')).join(' '));
    for(const s of this.isolated){const [x,y]=this.coords(s.index);s.node.setAttribute('d',`M${x-2} ${y}h4`);}
    const [x,y]=this.coords(this.latest);this.marker.setAttribute('cx',x);this.marker.setAttribute('cy',y);
    this.marker.setAttribute('aria-label',`${this.latest===this.points.length-1?'Latest':'Last available'} reading: ${exact(this.points[this.latest].value)} ${this.unit}, ${stamp(this.points[this.latest].time)}`);
  }
  enter() {
    this.finish();if(motion.matches||document.hidden||!this.svg.clientWidth)return;
    this.progress=0;this.svg.dataset.animating='true';this.draw();const start=performance.now();
    const tick=now=>{this.progress=1-Math.pow(1-Math.min(1,(now-start)/500),3);this.draw();if(this.progress<1)this.frame=requestAnimationFrame(tick);else this.finish();};
    this.frame=requestAnimationFrame(tick);
  }
  finish(){cancelAnimationFrame(this.frame);this.progress=1;delete this.svg.dataset.animating;this.draw();this.dismiss();}
  pointer(e){if(this.progress<1)return;const rect=this.svg.getBoundingClientRect();const fraction=Math.max(0,Math.min(1,(e.clientX-rect.left-20)/Math.max(1,rect.width-40)));this.inspect(nearest(this.points,this.points[0].time+fraction*(this.points.at(-1).time-this.points[0].time)));}
  inspect(i,keyboard=false) {
    if(i<0){this.dismiss();return;}this.index=i;const p=this.points[i];const [x,y]=this.coords(i);
    this.hover.setAttribute('visibility',p.value==null||i===this.latest?'hidden':'visible');this.hover.setAttribute('cx',x);this.hover.setAttribute('cy',y);
    const prefix=i===this.latest&&i!==this.points.length-1?'Last available reading · ':'';
    this.tip.textContent=`${prefix}${stamp(p.time)} · ${p.value==null?'Unavailable':exact(p.value)+' '+this.unit}`;this.tip.hidden=false;
    this.svg.setAttribute('aria-describedby',this.tip.id);if(keyboard)this.live.textContent=this.tip.textContent;
    const rect=this.svg.getBoundingClientRect(),box=this.tip.getBoundingClientRect();
    this.tip.style.left=`${Math.max(8,Math.min(innerWidth-box.width-8,rect.left+x-box.width/2))}px`;
    const above=rect.top+y-box.height-14;this.tip.style.top=`${Math.max(8,Math.min(innerHeight-box.height-8,above<8?rect.top+y+14:above))}px`;
  }
  dismiss(){clearTimeout(this.dismissTimer);this.index=-1;this.pinned=false;this.tip.hidden=true;this.hover.setAttribute('visibility','hidden');this.svg.removeAttribute('aria-describedby');this.live.textContent='';}
  destroy(){this.finish();this.events.abort();this.observer.disconnect();this.tip.remove();this.live.remove();}
}
export function captureChartState(){
  const focused=controllers.find(c=>document.activeElement===c.svg);
  return {restore:focused?{view:focused.svg.closest('.view').id,unit:focused.unit}:null,
    opened:[...document.querySelectorAll('.measurement-table[open]')].map(d=>[d.closest('.view').id,d.closest('.chart').querySelector('h3').textContent])};
}
export function mountCharts({restore=null,opened=[]}={}){
  controllers.forEach(c=>c.destroy());controllers=[...document.querySelectorAll('svg[data-series]')].map(svg=>new Graph(svg));
  // Rendering replaces chart nodes; restore useful disclosure/focus state.
  for(const d of document.querySelectorAll('.measurement-table'))if(opened.some(([v,t])=>v===d.closest('.view').id&&t===d.closest('.chart').querySelector('h3').textContent))d.open=true;
  if(restore)controllers.find(c=>c.unit===restore.unit&&c.svg.closest('.view').id===restore.view)?.svg.focus({preventScroll:true});
  if(firstMount){firstMount=false;controllers.filter(c=>!c.svg.closest('[hidden]')).forEach(c=>c.enter());}
}
window.addEventListener('dashboard-view-leave',()=>controllers.forEach(c=>c.finish()));
window.addEventListener('dashboard-view-change',()=>controllers.forEach(c=>{if(!c.svg.closest('[hidden]')){c.layout();c.enter();}}));
window.addEventListener('sidebar-resize-start',()=>controllers.forEach(c=>c.finish()));
motion.addEventListener('change',()=>controllers.forEach(c=>c.finish()));
document.addEventListener('visibilitychange',()=>controllers.forEach(c=>c.finish()));
document.addEventListener('pointerdown',e=>controllers.forEach(c=>{if(!c.svg.contains(e.target))c.dismiss();}));
document.addEventListener('keydown',e=>{if(e.key==='Escape')controllers.forEach(c=>c.dismiss());});
window.addEventListener('scroll',()=>controllers.forEach(c=>c.dismiss()),true);
