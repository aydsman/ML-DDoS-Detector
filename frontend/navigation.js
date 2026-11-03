const names = {overview:'Overview',traffic:'Traffic',detections:'Detections',blocks:'Blocks'};
const views = [...document.querySelectorAll('.view')];
const nav = document.querySelector('.glass-nav');
let active = null;
let pending;
function showPage(initial = false) {
  const page = location.hash.slice(1) || 'overview';
  if (page === 'page-title') { document.getElementById('page-title').focus(); return; }
  if (!names[page]) { location.replace('#overview'); return; }
  clearTimeout(pending);
  if (page === active) { views.forEach(view => view.classList.remove("leaving")); return; }
  window.dispatchEvent(new Event('dashboard-view-leave'));
  const previous = document.querySelector('.view:not([hidden])');
  const change = () => {
    views.forEach(view => { view.hidden = view.id !== `view-${page}`; view.classList.remove('entering','leaving'); });
    const next = document.getElementById(`view-${page}`);
    next.classList.add('entering');
    document.getElementById('page-title').textContent = names[page];
    document.title = `ML-DDoS-Detector · ${names[page]}`;
    document.querySelectorAll('.glass-nav nav a').forEach(link => {
      const selected = link.hash === `#${page}`;
      link.classList.toggle('selected',selected);
      if(selected) link.setAttribute('aria-current','page'); else link.removeAttribute('aria-current');
    });
    active = page;
    window.dispatchEvent(new Event('dashboard-view-change'));
    if(!initial) document.getElementById('page-title').focus({preventScroll:true});
  };
  if(initial || matchMedia('(prefers-reduced-motion: reduce)').matches) change();
  else { previous?.classList.add('leaving'); pending = setTimeout(change,100); }
}
nav.addEventListener('keydown',event => {
  if(event.key === 'Escape') nav.classList.add('labels-dismissed');
});
nav.addEventListener('focusin',() => nav.classList.remove('labels-dismissed'));
nav.addEventListener('pointerover',() => nav.classList.remove('labels-dismissed'));
window.addEventListener('hashchange',() => showPage());
const toggle = document.getElementById('sidebar-toggle');
toggle.addEventListener('click', () => {
  window.dispatchEvent(new Event('sidebar-resize-start'));
  hideTip();
  const expanded = toggle.getAttribute('aria-expanded') !== 'true';
  toggle.setAttribute('aria-expanded', String(expanded));
  toggle.setAttribute('aria-label', expanded ? 'Collapse sidebar' : 'Expand sidebar');
  document.body.classList.toggle('sidebar-expanded', expanded);
});
// Escape dismisses descriptions without changing the selected page.
nav.addEventListener('pointerdown', () => nav.classList.remove('labels-dismissed'));
document.querySelector('.workspace').classList.add('initial');
setTimeout(() => document.querySelector('.workspace').classList.remove('initial'),500);
showPage(true);

// A single moving hover surface stays separate from the selected-page surface.
const links=[...nav.querySelectorAll('nav a')];
const navigation=nav.querySelector('nav');
const selection=document.createElement('span');selection.className='nav-selection';selection.setAttribute('aria-hidden','true');navigation.prepend(selection);
function moveSelection(){
  const link=links.find(link=>link.classList.contains('selected'));if(!link)return;
  selection.style.width=`${link.offsetWidth}px`;selection.style.height=`${link.offsetHeight}px`;selection.style.transform=`translate(${link.offsetLeft}px,${link.offsetTop}px)`;
}
window.addEventListener('dashboard-view-change',moveSelection);
new ResizeObserver(moveSelection).observe(navigation);
moveSelection();
const highlight=document.createElement('span');highlight.className='nav-hover';highlight.setAttribute('aria-hidden','true');navigation.prepend(highlight);
let hovered=null;
function moveHighlight(link){
  hovered=link;if(!link){highlight.style.opacity='0';return;}
  highlight.style.width=`${link.offsetWidth}px`;highlight.style.height=`${link.offsetHeight}px`;
  highlight.style.transform=`translate(${link.offsetLeft}px,${link.offsetTop}px)`;highlight.style.opacity='1';
}
links.forEach(link=>{
  link.addEventListener('pointerenter',()=>moveHighlight(link));link.addEventListener('focus',()=>moveHighlight(link));
});
navigation.addEventListener('pointerleave',()=>moveHighlight(links.includes(document.activeElement)?document.activeElement:null));
navigation.addEventListener('focusout',()=>requestAnimationFrame(()=>moveHighlight(links.includes(document.activeElement)?document.activeElement:null)));
new ResizeObserver(()=>moveHighlight(hovered)).observe(navigation);
// Render flyouts outside the rail so its short-window scrolling cannot clip them.
const flyout=document.createElement('div');flyout.className='sidebar-flyout';flyout.hidden=true;document.body.append(flyout);
let tipTimer,tipTarget,tipDismissTimer;
function hideTip(){clearTimeout(tipDismissTimer);clearTimeout(tipTimer);tipTarget=null;flyout.hidden=true;}
function showTip(target){
  hideTip();const label=target.querySelector('.status-tooltip,.nav-label');
  if(!label || (target.matches('a') && document.body.classList.contains('sidebar-expanded')))return;
  tipTarget=target;tipTimer=setTimeout(()=>{
    if(tipTarget!==target)return;
    flyout.textContent=label.textContent;flyout.hidden=false;
    const rect=target.getBoundingClientRect(),box=flyout.getBoundingClientRect();
    flyout.style.left=`${Math.max(8,Math.min(innerWidth-box.width-8,rect.right+14))}px`;
    flyout.style.top=`${Math.max(8,Math.min(innerHeight-box.height-8,rect.top+(rect.height-box.height)/2))}px`;
  },matchMedia('(prefers-reduced-motion: reduce)').matches?0:150);
}
[...links,...nav.querySelectorAll('.status-item')].forEach(target=>{
  target.addEventListener('pointerenter',()=>showTip(target));target.addEventListener('pointerleave',()=>{tipDismissTimer=setTimeout(hideTip,120);});
  target.addEventListener('focus',()=>showTip(target));target.addEventListener('blur',hideTip);
  target.addEventListener('click',()=>{if(target.matches('.status-item'))showTip(target);else hideTip();});
});
document.addEventListener('keydown',e=>{if(e.key==='Escape'){hideTip();moveHighlight(null);}});
document.addEventListener('pointerdown',e=>{if(!nav.contains(e.target))hideTip();});
window.addEventListener('resize',hideTip);window.addEventListener('scroll',hideTip,true);
window.addEventListener('hashchange',hideTip);

flyout.addEventListener('pointerenter',()=>clearTimeout(tipDismissTimer));
flyout.addEventListener('pointerleave',hideTip);
