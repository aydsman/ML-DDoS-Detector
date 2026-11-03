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
