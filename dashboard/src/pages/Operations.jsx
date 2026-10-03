import React, { useState } from 'react';
import { Panel, Kpi, Pill, Severity, Empty, EventRow } from '../ui';
import { number, percent, msf, usd, ago, controlLabel, INCIDENT, ACTION, RANGES } from '../lib';

const SERIES = [['allowed', 'Dozwolone', 'allow'], ['restricted', 'Ograniczone', 'redact'], ['blocked', 'Zablokowane', 'block']];

function bucketLabel(minute, range) {
  const d = new Date(minute + ':00Z');
  if (range === '7d') return d.toLocaleString('pl-PL', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
  return d.toLocaleTimeString('pl-PL', { hour: '2-digit', minute: '2-digit' });
}

export function Timeline({ points = [], range }) {
  const [hover, setHover] = useState(null);
  const max = Math.max(1, ...points.map(p => p.allowed + p.restricted + p.blocked));
  const totals = SERIES.map(([k]) => points.reduce((s, p) => s + p[k], 0));
  return <div className="timeline">
    <div className="legend-row">{SERIES.map(([k, label, tone], i) => <span key={k}><i className={`sw ${tone}`} />{label}<b>{number(totals[i])}</b></span>)}</div>
    <div className="plot" role="img" aria-label="Decyzje w wybranym okresie" onMouseLeave={() => setHover(null)}>
      {[.25, .5, .75].map(g => <span key={g} className="grid" style={{ bottom: `${g * 100}%` }} />)}
      {points.map((p, i) => { const total = p.allowed + p.restricted + p.blocked; return <div key={p.minute} className={`col ${hover === i ? 'hover' : ''}`} onMouseEnter={() => setHover(i)}>
        <div className="stack" style={{ height: `${total / max * 100}%` }}>{SERIES.map(([k, , tone]) => p[k] > 0 && <span key={k} className={tone} style={{ flexGrow: p[k] }} />)}</div>
      </div>; })}
      {hover !== null && points[hover] && <div className="tip" style={{ left: `${(hover + .5) / points.length * 100}%` }}><strong>{bucketLabel(points[hover].minute, range)}</strong>{SERIES.map(([k, label]) => <span key={k}>{label}: <b>{points[hover][k]}</b></span>)}</div>}
    </div>
    <div className="axis"><span>{points[0] ? bucketLabel(points[0].minute, range) : ''}</span><span>{max} / przedział</span><span>teraz</span></div>
    <details className="data-table"><summary>Tabela danych</summary><div className="table-scroll"><table><thead><tr><th>Przedział</th><th>Dozwolone</th><th>Ograniczone</th><th>Zablokowane</th></tr></thead>
      <tbody>{points.filter(p => p.allowed + p.restricted + p.blocked > 0).map(p => <tr key={p.minute}><td>{bucketLabel(p.minute, range)}</td><td>{p.allowed}</td><td>{p.restricted}</td><td>{p.blocked}</td></tr>)}</tbody></table></div></details>
  </div>;
}

function Bars({ data, label, onPick, empty }) {
  const rows = Object.entries(data || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  if (!rows.length) return <Empty>{empty}</Empty>;
  const max = Math.max(...rows.map(r => r[1]));
  return <div className="bars">{rows.map(([k, v]) => <button key={k} className="bar-row" onClick={() => onPick?.(k)}><span>{label(k)}</span><span className="track"><i style={{ width: `${v / max * 100}%` }} /></span><b>{v}</b></button>)}</div>;
}

export function Operations({ data, events, fresh, incidents, approvals, me, range, go, openEvent, approve, busy, paused, setPaused, buffered, flush, demo }) {
  const d = data.decisions || {};
  const blocked = (d.BLOCK || 0) + (d.THROTTLE || 0), restricted = (d.REDACT || 0) + (d.GHOST || 0) + (d.REQUIRE_APPROVAL || 0);
  const open = incidents.filter(i => i.status !== 'resolved');
  const critical = open.filter(i => i.severity === 'critical').length;
  const global = (data.budgets || []).find(b => b.scope === 'global');
  const [feed, setFeed] = useState('all');
  const visible = events.filter(e => feed === 'all' || (feed === 'blocked' ? ['BLOCK', 'THROTTLE'].includes(e.decision) : !['ALLOW', 'BLOCK', 'THROTTLE'].includes(e.decision))).slice(0, 60);
  const rangeLabel = RANGES.find(r => r[0] === range)?.[1];
  return <div className="page">
    <div className="kpis">
      <Kpi label={`Żądania · ${rangeLabel}`} value={number(data.requests)} sub={`${(data.requests_per_second_1m || 0).toFixed(2)} / s teraz`} onClick={() => go('events', {})} />
      <Kpi label="Zablokowane" value={number(blocked)} sub={`${percent(data.requests ? blocked / data.requests : 0)} ruchu`} tone="bad" onClick={() => go('events', { decision: 'BLOCK' })} />
      <Kpi label="Ograniczone" value={number(restricted)} sub={`${number(d.REDACT)} redakcji · ${number(d.GHOST)} w izolacji`} tone="warn" onClick={() => go('events', { decision: 'RESTRICTED' })} />
      <Kpi label="Otwarte incydenty" value={number(open.length)} sub={critical ? `${critical} krytycznych` : 'brak krytycznych'} tone={critical ? 'bad' : ''} onClick={() => go('incidents', {})} />
      <Kpi label="Narzut bramy p95" value={msf(data.gateway_overhead_ms?.p95)} sub={`${percent(data.deterministic_resolution_rate)} bez AI`} onClick={() => go('agents', {})} />
      <Kpi label="Koszt dziś" value={usd(data.daily_cost_usd)} sub={global ? `${percent(global.used_ratio)} budżetu tokenów` : '—'} onClick={() => go('agents', {})} />
    </div>
    <div className="ops-grid">
      <Panel className="feed" eyebrow="NA ŻYWO" title="Strumień decyzji" action={<div className="feed-actions">
        <div className="segmented small">{[['all', 'Wszystkie'], ['blocked', 'Blokady'], ['restricted', 'Ograniczone']].map(([id, t]) => <button key={id} className={feed === id ? 'on' : ''} onClick={() => setFeed(id)}>{t}</button>)}</div>
        <button className="secondary small" onClick={() => setPaused(!paused)}>{paused ? '▶ Wznów' : '❚❚ Wstrzymaj'}</button>
      </div>}>
        {paused && buffered > 0 && <button className="buffer-note" onClick={flush}>{buffered} nowych zdarzeń · pokaż</button>}
        <div className="event-head"><span>Czas</span><span>Kto</span><span>Działanie</span><span>Kontrole</span><span>Decyzja</span><span>Narzut</span></div>
        <div className="event-list">{visible.length ? visible.map(e => <EventRow key={e.id} e={e} fresh={fresh.has(e.id)} onOpen={openEvent} />) : <Empty>{demo ? 'Brak ruchu. Włącz generator ruchu w trybie demo albo uruchom scenariusz.' : 'Brak zdarzeń w tym okresie.'}</Empty>}</div>
      </Panel>
      <div className="side-col">
        <Panel eyebrow="KOLEJKA" title="Incydenty" action={<button className="link" onClick={() => go('incidents', {})}>Wszystkie →</button>}>
          {open.length ? <ul className="incident-mini">{open.slice(0, 5).map(i => <li key={i.id}><button onClick={() => go('incidents', { id: i.id })}>
            <Severity value={i.severity} /><span><strong>{INCIDENT[i.type] || i.type}</strong><small>{i.user} · {ago(i.opened_at)}</small></span></button></li>)}</ul> : <Empty>Brak otwartych incydentów.</Empty>}
        </Panel>
        {me?.can_approve && <Panel eyebrow="ZGODA CZŁOWIEKA" title={`Do zatwierdzenia (${approvals.length})`}>
          {approvals.length ? approvals.map(a => <div className="approval-item" key={a.id}><div><strong>{ACTION[a.action] || a.action}</strong><small>{a.requester} · {a.resource}</small></div>
            <button className="primary small" disabled={busy || a.requester === me.user_id} title={a.requester === me.user_id ? 'Nie możesz zatwierdzić własnej akcji' : ''} onClick={() => approve(a.id)}>Zatwierdź</button></div>) : <Empty>Nic nie czeka na decyzję.</Empty>}
        </Panel>}
        <Panel eyebrow="POSTAWA" title="Bezpieczeństwo systemu">
          <div className="posture-mini"><strong className={data.security_posture < 80 ? 'bad' : ''}>{data.security_posture ?? '—'}</strong><span>/ 100</span></div>
          <ul className="posture-list">{(data.posture_components || []).map(c => <li key={c.name} title={c.detail} className={c.points < c.max ? 'lost' : ''}><span>{c.name}</span><b>{c.points}/{c.max}</b></li>)}</ul>
        </Panel>
      </div>
    </div>
    <Panel eyebrow={`DECYZJE · ${rangeLabel}`} title="Przebieg w czasie"><Timeline points={data.timeline} range={range} /></Panel>
    <div className="two">
      <Panel eyebrow={`KONTROLE · ${rangeLabel}`} title="Co zatrzymało lub ograniczyło ruch">
        <Bars data={data.controls_triggered} label={controlLabel} onPick={k => go('events', { control: k })} empty="Żadna kontrola nie zadziałała w tym okresie." />
        <h3 className="sub">Sygnatury ataków</h3>
        <Bars data={data.threat_signatures} label={k => k} onPick={k => go('events', { control: 'threat:' + k })} empty="Brak dopasowań z threat feed." />
      </Panel>
      <Panel eyebrow="ZASOBY" title="Budżety dzisiaj" action={<button className="link" onClick={() => go('agents', {})}>Szczegóły →</button>}>
        <div className="budget-list">{(data.budgets || []).slice(0, 6).map(b => <div className="budget" key={b.scope}>
          <div><strong>{b.scope}</strong><small>{number(b.tokens)} / {b.token_limit ? number(b.token_limit) : '∞'} tok.{b.cost_limit_usd ? ` · ${usd(b.cost_usd)} / ${usd(b.cost_limit_usd)}` : ''}</small></div>
          <span className="meter"><i className={b.status.toLowerCase()} style={{ width: `${Math.min(100, b.used_ratio * 100)}%` }} /></span>
          <span className={`status-tag ${b.status.toLowerCase()}`}>{{ OK: 'OK', WARN: 'Ostrzeżenie', THROTTLE: 'Spowolnione', EXCEEDED: 'Przekroczony' }[b.status]} · {percent(b.used_ratio)}</span>
        </div>)}</div>
        <div className="perf-row"><div><span>p50 / p95 / p99</span><strong>{msf(data.latency_ms?.p50)} · {msf(data.latency_ms?.p95)} · {msf(data.latency_ms?.p99)}</strong></div><div><span>Analiza AI (śr.)</span><strong>{msf(data.average_semantic_ms)}</strong></div><div><span>Tokeny dziś</span><strong>{number(data.daily_tokens)}</strong></div></div>
      </Panel>
    </div>
  </div>;
}
