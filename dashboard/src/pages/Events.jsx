import React, { useMemo } from 'react';
import { Panel, Empty, EventRow } from '../ui';
import { ACTION, CONTROL, controlLabel } from '../lib';

// Audit explorer: global time range + filters, every row opens the drawer.
export function Events({ events, filters, setFilters, openEvent, canExport, exportFile, scope }) {
  const set = (k, v) => setFilters(prev => ({ ...prev, [k]: v }));
  const controls = useMemo(() => [...new Set(events.flatMap(e => e.controls || []))].sort(), [events]);
  const actions = useMemo(() => [...new Set(events.map(e => e.action))].sort(), [events]);
  const q = (filters.q || '').toLowerCase().trim();
  const rows = events.filter(e => {
    if (filters.decision === 'RESTRICTED' ? !['REDACT', 'GHOST', 'REQUIRE_APPROVAL'].includes(e.decision) : filters.decision === 'BLOCK' ? !['BLOCK', 'THROTTLE'].includes(e.decision) : filters.decision && e.decision !== filters.decision) return false;
    if (filters.control && !(e.controls || []).includes(filters.control)) return false;
    if (filters.action && e.action !== filters.action) return false;
    if (filters.session && e.session_id !== filters.session) return false;
    if (q && ![e.id, e.user, e.agent, e.action, e.resource, e.session_id, ...(e.reasons || [])].join(' ').toLowerCase().includes(q)) return false;
    return true;
  });
  const active = Object.values(filters).some(Boolean);
  return <div className="page">
    <Panel eyebrow={scope === 'all' ? 'WSZYSCY UŻYTKOWNICY' : 'TWOJE ZDARZENIA'} title={`Dziennik zdarzeń (${rows.length})`} action={canExport ? <div className="row-gap"><button className="secondary small" onClick={() => exportFile('csv')}>Eksport CSV</button><button className="secondary small" onClick={() => exportFile('json')}>Eksport JSON</button></div> : <small className="muted">Eksport: rola bezpieczeństwa</small>}>
      <div className="filters">
        <input placeholder="Szukaj: ID, użytkownik, zasób, sesja, powód…" value={filters.q || ''} onChange={e => set('q', e.target.value)} aria-label="Szukaj w zdarzeniach" />
        <select value={filters.decision || ''} onChange={e => set('decision', e.target.value)} aria-label="Decyzja"><option value="">Każda decyzja</option><option value="ALLOW">Dozwolone</option><option value="RESTRICTED">Ograniczone</option><option value="REDACT">Zredagowane</option><option value="GHOST">Izolowane</option><option value="REQUIRE_APPROVAL">Wymaga zgody</option><option value="BLOCK">Zablokowane</option></select>
        <select value={filters.control || ''} onChange={e => set('control', e.target.value)} aria-label="Kontrola"><option value="">Każda kontrola</option>{[...new Set([...controls, ...Object.keys(CONTROL)])].map(c => <option key={c} value={c}>{controlLabel(c)}</option>)}</select>
        <select value={filters.action || ''} onChange={e => set('action', e.target.value)} aria-label="Działanie"><option value="">Każde działanie</option>{actions.map(a => <option key={a} value={a}>{ACTION[a] || a}</option>)}</select>
        {active && <button className="link" onClick={() => setFilters({})}>Wyczyść filtry</button>}
      </div>
      {filters.session && <p className="muted small">Sesja: <code>{filters.session}</code></p>}
      <div className="event-head"><span>Czas</span><span>Kto</span><span>Działanie</span><span>Kontrole</span><span>Decyzja</span><span>Narzut</span></div>
      <div className="event-list tall">{rows.length ? rows.slice(0, 400).map(e => <EventRow key={e.id} e={e} onOpen={openEvent} />) : <Empty>Brak zdarzeń dla tych filtrów w wybranym okresie.</Empty>}</div>
      <p className="fineprint">Dziennik nie przechowuje treści promptów ani wykrytych danych; dane osobowe w nazwach zasobów są maskowane.</p>
    </Panel>
  </div>;
}
