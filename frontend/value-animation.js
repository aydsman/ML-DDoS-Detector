// Only visual rate values tween. Accessible values and exact tables stay final.
let frame = 0;
const motion = matchMedia('(prefers-reduced-motion: reduce)');
const format = value => new Intl.NumberFormat('en-CA', {maximumFractionDigits: 2}).format(value);
export function animateRates(previous, next) {
  cancelAnimationFrame(frame);
  const nodes = [...document.querySelectorAll('[data-rate]')];
  const finish = () => nodes.forEach(node => { node.textContent = format(Number(node.dataset.value)); });
  finish();
  if (!previous || motion.matches || document.hidden) return;
  const pairs = nodes.filter(node => node.getClientRects().length).map(node => {
    const key = node.dataset.rate;
    return {node, from: previous[key], to: next[key]};
  }).filter(p => Number.isFinite(p.from) && Number.isFinite(p.to) && p.from !== p.to);
  if (!pairs.length) return;
  const start = performance.now();
  const step = now => {
    if (motion.matches || document.hidden) { finish(); return; }
    const progress = Math.min(1, (now - start) / 400);
    const eased = 1 - (1 - progress) ** 3;
    pairs.forEach(({node, from, to}) => { node.textContent = format(from + (to - from) * eased); });
    if (progress < 1) frame = requestAnimationFrame(step); else finish();
  };
  frame = requestAnimationFrame(step);
}
