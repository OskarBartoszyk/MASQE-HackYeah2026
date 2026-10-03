import React, { useEffect, useState } from 'react';
import { Panel, Severity, Empty, Pill, Trace } from '../ui';
import { api, INCIDENT, STATUS, ACTION, dateTime, ago, incidentSummary } from '../lib';

const SOURCE = { ghost_shell: 'Ghost Shell', gateway: 'Gateway' };

// Unified incident queue: gateway detections and Ghost Shell evidence.
export function Incidents({ apiKey, incidents, selectedId, select, canTriage, reload, openGhost, openEvent }) {
  const [tab, setTab] = useState('active'), [note, setNote] = useState(''), [event, setEvent] = useState(null), [error, setError] = useState('');
  const shown = incidents.filter(i => tab === 'all' || (tab === 'active' ? i.status !== 'resolved' : i.status === tab));
  const current = incidents.find(i => i.id === selectedId) || shown[0];
  useEffect(() => {
    setEvent(null); setError(''); setNote(current?.note || '');
    if (current?.source === 'gateway') api(`/v1/events/${encodeURIComponent(current.ref)}`, apiKey).then(setEvent).catch(e => setError(e.message));
  }, [current?.id, apiKey]);
  async function setStatus(status) {
    try { await api(`/v1/incidents/${encodeURIComponent(current.id)}/status`, apiKey, { method: 'POST', body: JSON.stringify({ status, note }) }); await reload(); }
    catch (e) { setError(e.message); }
  }
  const count = s => incidents.filter(i => s === 'active' ? i.status !== 'resolved' : s === 'all' || i.status === s).length;
  return <div className="page">
    <div className="split">
      <Panel className="list-panel" eyebrow="QUEUE" title="Incidents" action={<div className="segmented small">{[['active', 'Active'], ['acknowledged', 'In progress'], ['resolved', 'Resolved'], ['all', 'All']].map(([id, t]) => <button key={id} className={tab === id ? 'on' : ''} onClick={() => setTab(id)}>{t} <small>{count(id)}</small></button>)}</div>}>
        {shown.length ? <ul className="incident-list">{shown.map(i => <li key={i.id}><button className={current?.id === i.id ? 'on' : ''} onClick={() => select(i.id)}>
          <span className="top"><Severity value={i.severity} /><span className={`status ${i.status}`}>{STATUS[i.status]}</span><small>{ago(i.opened_at)}</small></span>
          <strong>{INCIDENT[i.type] || i.type}</strong>
          <small>{SOURCE[i.source]} · {i.user} · {i.agent}</small>
        </button></li>)}</ul> : <Empty>No incidents in this category.</Empty>}
      </Panel>
      <Panel className="detail-panel" eyebrow={current ? `${SOURCE[current.source]} · ${current.id}` : 'INCIDENT'} title={current ? (INCIDENT[current.type] || current.type) : 'Select an incident'}>
        {!current ? <Empty>New incidents appear here automatically.</Empty> : <>
          <div className="incident-meta"><Severity value={current.severity} /><span className={`status ${current.status}`}>{STATUS[current.status]}</span><span className="muted small">opened {dateTime(current.opened_at)}{current.updated_by && ` · updated by ${current.updated_by}`}</span></div>
          <p className="lead">{incidentSummary(current)}</p>
          <dl className="facts-grid"><div><dt>User</dt><dd>{current.user}</dd></div><div><dt>Agent</dt><dd>{current.agent}</dd></div><div className="wide"><dt>Reference</dt><dd><code>{current.ref}</code></dd></div></dl>
          {canTriage ? <div className="triage">
            <textarea rows="2" placeholder="Analyst note (optional)" value={note} onChange={e => setNote(e.target.value)} aria-label="Note" />
            <div className="row-gap">
              {current.status !== 'acknowledged' && current.status !== 'resolved' && <button className="secondary" onClick={() => setStatus('acknowledged')}>Take ownership</button>}
              {current.status !== 'resolved' && <button className="primary" onClick={() => setStatus('resolved')}>Resolve</button>}
              {current.status === 'resolved' && <button className="secondary" onClick={() => setStatus('open')}>Reopen</button>}
            </div>
          </div> : <p className="muted small">Changing status requires the security role.</p>}
          {current.note && !canTriage && <p className="muted small">Note: {current.note}</p>}
          {error && <div className="alert">{error}</div>}
          {current.source === 'ghost_shell' && <button className="secondary full" onClick={() => openGhost(current.ref)}>Open the session recording in Ghost Shell →</button>}
          {event && <div className="incident-event">
            <div className="row-gap"><Pill value={event.decision} /><strong>{ACTION[event.action] || event.action}</strong><button className="link" onClick={() => openEvent(event.id)}>Full event →</button></div>
            <h3 className="drawer-sub">Decision trace</h3><Trace steps={event.trace} />
          </div>}
        </>}
      </Panel>
    </div>
  </div>;
}
