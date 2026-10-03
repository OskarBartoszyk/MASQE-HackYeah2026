import React, { useEffect } from 'react';
import { DECISION, SEVERITY, ACTION, CHECK, EXECUTION, controlLabel, clock, dateTime, msf, number, percent, usd } from './lib';

export function Pill({ value }) {
  const [label, tone] = DECISION[value] || [value || '—', 'neutral'];
  return <span className={`pill ${tone}`}><i />{label}</span>;
}

export function Severity({ value }) {
  const [label, tone] = SEVERITY[value] || [value || '—', 'neutral'];
  return <span className={`sev ${tone}`}>{label}</span>;
}

export function Panel({ title, eyebrow, action, children, className = '' }) {
  return <section className={`panel ${className}`}>
    {(title || action) && <header className="panel-head"><div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h2>{title}</h2></div>{action}</header>}
    {children}
  </section>;
}

export function Kpi({ label, value, sub, tone = '', onClick }) {
  const Tag = onClick ? 'button' : 'div';
  return <Tag className={`kpi ${tone} ${onClick ? 'clickable' : ''}`} onClick={onClick}>
    <span className="kpi-label">{label}</span><strong>{value}</strong><small>{sub}</small>
  </Tag>;
}

export function Segmented({ value, options, onChange, label }) {
  return <div className="segmented" role="group" aria-label={label}>
    {options.map(([id, text]) => <button key={id} className={value === id ? 'on' : ''} aria-pressed={value === id} onClick={() => onChange(id)}>{text}</button>)}
  </div>;
}

export function Empty({ children }) { return <div className="empty-state">{children}</div>; }

const MARK = { pass: '✓', flag: '!', fail: '✕', skip: '–' };

export function Trace({ steps }) {
  if (!steps?.length) return <p className="muted small">Brak śladu decyzji dla tego zdarzenia.</p>;
  return <ol className="trace">{steps.map((st, i) => <li key={i} className={st.result}>
    <span className="trace-mark" aria-label={st.result}>{MARK[st.result] || '·'}</span>
    <div className="trace-body">
      <div className="trace-line"><strong>{CHECK[st.check] || st.check}</strong><span>{st.check === 'decision' ? (DECISION[st.detail]?.[0] || st.detail) : st.detail}</span></div>
      {st.score != null && <div className="trace-score" title={st.threshold != null ? `wynik ${st.score} · próg ${st.threshold}` : `wynik ${st.score}`}>
        <span className="track"><i style={{ width: `${Math.min(100, st.score * 100)}%` }} />{st.threshold != null && <b style={{ left: `${st.threshold * 100}%` }} />}</span>
        <code>{st.score.toFixed(2)}{st.threshold != null && ` / próg ${st.threshold.toFixed(2)}`}</code>
      </div>}
    </div>
  </li>)}</ol>;
}

export function Explanation({ evaluation }) {
  const x = evaluation.explanation || {};
  if (x.status === 'not_required') return null;
  if (x.status === 'pending') return <div className="xai pending"><span className="eyebrow">WYJAŚNIENIE AI</span><p>Lokalny model przygotowuje opis w tle. Decyzja została już wyegzekwowana.</p></div>;
  if (x.status !== 'generated') return <div className="xai muted-box"><span className="eyebrow">WYJAŚNIENIE AI</span><p>Model wyjaśniający nie odpowiedział. Rozstrzygają powody techniczne powyżej.</p></div>;
  return <div className="xai"><span className="eyebrow">WYJAŚNIENIE AI · {x.model}</span><h3>{x.title}</h3><p>{x.summary}</p>
    {x.factors?.length > 0 && <ul>{x.factors.map((f, i) => <li key={i}>{f}</li>)}</ul>}
    {x.next_step && <p className="next"><strong>Co dalej: </strong>{x.next_step}</p>}
    <p className="fineprint">Tekst wygenerowany przez model może zawierać błędy; rozstrzygają powody techniczne.</p></div>;
}

export function EventDrawer({ event, onClose, onSession, onGhost }) {
  useEffect(() => {
    const key = e => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', key);
    return () => window.removeEventListener('keydown', key);
  }, [onClose]);
  if (!event) return null;
  const e = event;
  return <div className="drawer-wrap" onClick={onClose}>
    <aside className="drawer" role="dialog" aria-label="Szczegóły zdarzenia" onClick={ev => ev.stopPropagation()}>
      <header className="drawer-head">
        <div><Pill value={e.decision} /><h2>{ACTION[e.action] || e.action}</h2><span className="muted small">{dateTime(e.timestamp)} · <code>{e.id}</code></span></div>
        <button className="icon-btn" onClick={onClose} aria-label="Zamknij">×</button>
      </header>
      <dl className="facts-grid">
        <div><dt>Użytkownik</dt><dd>{e.user} <small>{e.role}</small></dd></div>
        <div><dt>Agent / model</dt><dd>{e.agent} <small>{e.model || '—'}</small></dd></div>
        <div className="wide"><dt>Zasób</dt><dd><code>{e.resource || '—'}</code></dd></div>
        <div><dt>Wykonanie</dt><dd>{EXECUTION[e.execution_status] || e.execution_status}{e.approved_by && <small> · zatwierdził {e.approved_by}</small>}</dd></div>
        <div><dt>Czas decyzji</dt><dd>{msf(e.gateway_ms)} <small>{e.semantic_escalated ? `+ AI ${msf(e.semantic_ms)}` : 'bez AI'}</small></dd></div>
        <div><dt>Tokeny / koszt</dt><dd>{number(e.tokens)} <small>{usd(e.cost_usd)}</small></dd></div>
        {!e.details_hidden && <div><dt>Ryzyko</dt><dd>{percent(e.risk)}</dd></div>}
        <div className="wide"><dt>Sesja</dt><dd><button className="link" onClick={() => onSession(e.session_id)}>{e.session_id}</button></dd></div>
        <div className="wide"><dt>Polityka</dt><dd><code>{e.policy_version}</code></dd></div>
      </dl>
      {(e.controls || []).length > 0 && <div className="chips">{e.controls.map(c => <span key={c} className="chip">{controlLabel(c)}</span>)}</div>}
      <h3 className="drawer-sub">Ślad decyzji</h3>
      <Trace steps={e.trace} />
      <h3 className="drawer-sub">Powody</h3>
      <ul className="reasons">{(e.reasons || []).map((r, i) => <li key={i}>{r}</li>)}</ul>
      {e.details_hidden && <p className="muted small">Wyniki detektorów, progi i identyfikatory sygnatur widzi tylko zespół bezpieczeństwa.</p>}
      {e.decision !== 'ALLOW' && <Explanation evaluation={e} />}
      {(e.controls || []).includes('ghost_shell') && <button className="secondary full" onClick={() => onGhost(e.session_id)}>Otwórz nagranie w Ghost Shell →</button>}
    </aside>
  </div>;
}

export function EventRow({ e, onOpen, fresh }) {
  return <button className={`event-row ${fresh ? 'fresh' : ''}`} onClick={() => onOpen(e.id)}>
    <span className="t">{clock(e.timestamp)}</span>
    <span className="who"><strong>{e.user}</strong><small>{e.agent}</small></span>
    <span className="what"><strong>{ACTION[e.action] || e.action}</strong><small>{e.resource}</small></span>
    <span className="ctl">{(e.controls || []).slice(0, 2).map(c => <span key={c} className="chip">{controlLabel(c)}</span>)}</span>
    {e.execution_status === 'EXECUTED_OUTPUT_BLOCKED' ? <span className="pill block"><i />Wynik wstrzymany</span> : <Pill value={e.decision} />}
    <span className="lat">{msf(e.gateway_ms)}</span>
  </button>;
}
