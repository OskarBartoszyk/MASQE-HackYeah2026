import React from 'react';

// An original folded-mask monogram. Kept as geometry, crisp at every size.
export function Mark() { return <svg className="masqe-mark" viewBox="0 0 48 48" fill="none" aria-label="MASQE"><path d="M5 8h12l7 10 7-10h12v24L24 43 5 32V8Z" fill="currentColor"/><path d="m12 18 12 8 12-8v10l-12 7-12-7V18Z" fill="#171D20"/><path d="m12 10 12 16L36 10" stroke="#171D20" strokeWidth="3"/></svg>; }
const paths = {
  activity: <><rect x="2" y="8" width="5" height="7" rx="1"/><rect x="17" y="2" width="5" height="6" rx="1"/><rect x="17" y="16" width="5" height="6" rx="1"/><path d="M7 11.5h5V5h5M12 11.5V19h5"/></>,
  overview: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
  ghost: <><path d="m5 7 5 5-5 5M13 17h6"/><rect x="2" y="3" width="20" height="18" rx="3"/></>,
  incidents: <><path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5m0 3v1"/></>,
  audit: <><path d="M8 3h11v18H5V6m3-3v5H3M9 12h6m-6 4h6"/></>,
  policy: <><path d="m12 2 8 4v6c0 5-8 10-8 10S4 17 4 12V6l8-4Z"/><path d="m8 12 3 3 5-6"/></>,
  test: <><path d="m9 3 0 6-6 10c-1 2 1 2 2 2h14c1 0 3 0 2-2L15 9V3M7 3h10M7 15h10"/></>,
  agents: <><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.8-3.6 3.4-5.5 6.5-5.5s5.7 1.9 6.5 5.5"/><path d="M16 5.5a3 3 0 0 1 0 5.6M18.5 14.8c1.6.8 2.6 2.5 3 5.2"/></>,
  bell: <><path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15L6 16Z"/><path d="M10 20a2 2 0 0 0 4 0"/></>,
  search: <><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4.5 4.5"/></>,
};
paths.operations = paths.overview; paths.events = paths.audit; paths.playground = paths.test;
export function Icon({ name }) { return <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>; }
