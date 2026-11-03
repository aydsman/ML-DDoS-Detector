// Keep recorded windows separate from presentation coordinates.
export function segments(points) {
  const result = []; let current = [];
  points.forEach((p,i) => {
    const previous = points[i-1];
    if (previous && p.time > previous.time + previous.seconds*1000) {
      if (current.length) result.push(current); current = [];
    }
    if (p.value == null) { if(current.length) result.push(current); current=[]; }
    else current.push(i);
  });
  if(current.length) result.push(current);
  return result;
}
export function nearest(points, time) {
  if (!points.length) return -1;
  let index = 0;
  for(let i=1;i<points.length;i++) if(Math.abs(points[i].time-time)<Math.abs(points[index].time-time)) index=i;
  // Do not snap across an unrecorded interval between windows.
  for(let i=1;i<points.length;i++) if(time>points[i-1].time+points[i-1].seconds*1000 && time<points[i].time) return -1;
  return index;
}
