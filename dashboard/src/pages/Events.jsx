import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Panel, Empty, EventRow } from '../ui';
import { ACTION, CONTROL, controlLabel, api, number, clock } from '../lib';

// Tamper-evident audit: the gateway recomputes the HMAC chain over every
// audit and incident record and reports anything changed outside it.
function AuditIntegrity({ apiKey, openEvent }) {
  const [state, setState] = useState(null), [busy, setBusy] = useState(false), [error, setError] = useState('');
  const check = useCallback(async () => {
    setBusy(true);
    try { setState(await api('/v1/audit/verify', apiKey)); setError(''); } catch (e) { setError(e.message); } finally { setBusy(false); }
  }, [apiKey]);
  useEffect(() => { check(); const timer = setInterval(check, 30000); return () => clearInterval(timer); }, [check]);
  if (error) return <div className="integrity broken" role="alert">The audit chain could not be verified: {error}</div>;
  if (!state) return null;
  const ok = state.status === 'intact';
  return <div className={`integrity ${ok ? '' : 'broken'}`} role={ok ? 'status' : 'alert'}>
    <div>
      <strong><span className="mark" aria-hidden="true">{ok ? '✓' : '!'}</span>{ok ? 'Audit log verified: nothing changed, deleted or inserted outside the gateway' : `Audit log integrity violated: ${number(state.problem_count)} problem${state.problem_count === 1 ? '' : 's'}`}</strong>
      <p>HMAC-SHA256 chain · {number(state.entries)} entries · {number(state.events)} events · {number(state.incidents)} incident updates · head #{state.head_seq} <code title={state.head_hash}>{(state.head_hash || '').slice(0, 12)}</code> · checked {clock(state.verified_at)}{state.baseline_sealed > 0 ? ` · ${number(state.baseline_sealed)} older records sealed when the chain was enabled` : ''}{state.key_source === 'ephemeral' ? ' · temporary key' : ''}</p>
      {!ok && <ul>{state.problems.slice(0, 6).map((p, i) => { const id = p.record.startsWith('event:') && p.kind !== 'record_deleted' ? p.record.slice(6) : ''; return <li key={i}>{id ? <button className="link" onClick={() => openEvent(id)}>{p.record}</button> : <code>{p.record}</code>} · {p.detail}{p.seq ? ` (entry ${p.seq})` : ''}</li>; })}</ul>}
    </div>
    <button className="secondary small" disabled={busy} onClick={check}>{busy ? 'Verifying…' : 'Verify now'}</button>
  </div>;
}

// Audit explorer: global time range + filters, every row opens the drawer.
export function Events({ events, filters, setFilters, openEvent, canExport, exportFile, scope, apiKey, canVerify }) {
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
    {canVerify && <AuditIntegrity apiKey={apiKey} openEvent={openEvent} />}
    <Panel eyebrow={scope === 'all' ? 'ALL USERS' : 'YOUR EVENTS'} title={`Event log (${rows.length})`} action={canExport ? <div className="row-gap"><button className="secondary small" onClick={() => exportFile('csv')}>Export CSV</button><button className="secondary small" onClick={() => exportFile('json')}>Export JSON</button></div> : <small className="muted">Export: security role</small>}>
      <div className="filters">
        <input placeholder="Search: ID, user, resource, session, reason…" value={filters.q || ''} onChange={e => set('q', e.target.value)} aria-label="Search events" />
        <select value={filters.decision || ''} onChange={e => set('decision', e.target.value)} aria-label="Decision"><option value="">Any decision</option><option value="ALLOW">Allowed</option><option value="RESTRICTED">Restricted</option><option value="REDACT">Redacted</option><option value="GHOST">Isolated</option><option value="REQUIRE_APPROVAL">Needs approval</option><option value="BLOCK">Blocked</option></select>
        <select value={filters.control || ''} onChange={e => set('control', e.target.value)} aria-label="Control"><option value="">Any control</option>{[...new Set([...controls, ...Object.keys(CONTROL)])].map(c => <option key={c} value={c}>{controlLabel(c)}</option>)}</select>
        <select value={filters.action || ''} onChange={e => set('action', e.target.value)} aria-label="Action"><option value="">Any action</option>{actions.map(a => <option key={a} value={a}>{ACTION[a] || a}</option>)}</select>
        {active && <button className="link" onClick={() => setFilters({})}>Clear filters</button>}
      </div>
      {filters.session && <p className="muted small">Session: <code>{filters.session}</code></p>}
      <div className="event-head"><span>Time</span><span>Who</span><span>Action</span><span>Controls</span><span>Decision</span><span>Overhead</span></div>
      <div className="event-list tall">{rows.length ? rows.slice(0, 400).map(e => <EventRow key={e.id} e={e} onOpen={openEvent} />) : <Empty>No events match these filters in the selected period.</Empty>}</div>
      <p className="fineprint">The log never stores prompt content or detected values; personal data in resource names is masked. Every record is sealed in a hash chain, and exports carry the chain head.</p>
    </Panel>
  </div>;
}
