const names = {overview:'Overview',traffic:'Traffic',detections:'Detections',blocks:'Blocks'};
const views = [...document.querySelectorAll('.view')];
const pin = document.querySelector('.nav-pin');
const nav = document.querySelector('.glass-nav');
let active = null;
let pending;
function showPage(initial = false) {
  const page = location.hash.slice(1) || 'overview';
  if (page === 'page-title') { document.getElementById('page-title').focus(); return; }
  if (!names[page]) { location.replace('#overview'); return; }
  clearTimeout(pending);
  if (page === active) { views.forEach(view => view.classList.remove("leaving")); return; }
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
    if(!initial) document.getElementById('page-title').focus({preventScroll:true});
  };
  if(initial || matchMedia('(prefers-reduced-motion: reduce)').matches) change();
  else { previous?.classList.add('leaving'); pending = setTimeout(change,100); }
}
pin.addEventListener('click',() => {
  const open = nav.classList.toggle('pinned');
  document.body.classList.toggle('nav-pinned',open);
  pin.setAttribute('aria-expanded',String(open));
  pin.setAttribute('aria-label',open?'Unpin sidebar':'Pin sidebar open');
});
nav.addEventListener('keydown',event => {
  if(event.key === 'Escape' && nav.classList.contains('pinned')) pin.click();
});
window.addEventListener('hashchange',() => showPage());
document.querySelector('.workspace').classList.add('initial');
setTimeout(() => document.querySelector('.workspace').classList.remove('initial'),500);
showPage(true);
