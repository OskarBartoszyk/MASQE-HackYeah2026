import React from 'react';
import { Panel, Empty } from '../ui';
import { ACTION, number, percent, usd, msf } from '../lib';

const STATUS_LABEL = { OK: 'OK', WARN: 'Ostrzeżenie', THROTTLE: 'Spowolnione', EXCEEDED: 'Przekroczony' };

// Identities, effective authority and resource consumption.
export function Agents({ data, policy }) {
  const p = policy?.policy;
  const roles = Object.entries(p?.roles || {});
  const agents = Object.entries(p?.agents || {});
  const actions = Object.keys(p?.actions || {}).sort();
  return <div className="page">
    <Panel eyebrow="ZASOBY · DZIŚ" title="Budżety i koszty">
      {(data.budgets || []).length ? <div className="table-scroll"><table className="data">
        <thead><tr><th>Zakres</th><th>Tokeny</th><th>Limit</th><th>Koszt</th><th>Limit kosztu</th><th>Wykorzystanie</th><th>Status</th></tr></thead>
        <tbody>{data.budgets.map(b => <tr key={b.scope}><td><code>{b.scope}</code></td><td>{number(b.tokens)}</td><td>{b.token_limit ? number(b.token_limit) : '∞'}</td><td>{usd(b.cost_usd)}</td><td>{b.cost_limit_usd ? usd(b.cost_limit_usd) : '—'}</td>
          <td><span className="meter inline"><i className={b.status.toLowerCase()} style={{ width: `${Math.min(100, b.used_ratio * 100)}%` }} /></span> {percent(b.used_ratio)}</td>
          <td><span className={`status-tag ${b.status.toLowerCase()}`}>{STATUS_LABEL[b.status]}</span></td></tr>)}</tbody>
      </table></div> : <Empty>Brak zużycia dzisiaj.</Empty>}
      <p className="fineprint">Progi: ostrzeżenie od {percent(p?.budget_alerts?.warn_at)}, spowolnienie od {percent(p?.budget_alerts?.throttle_at)}, blokada od 100%. Zużycie jest mierzone przez bramę i uzgadniane z faktycznym zużyciem modelu.</p>
    </Panel>
    <Panel eyebrow="WYDAJNOŚĆ" title="Telemetria bramy">
      <div className="perf-grid">
        <div><span>Narzut bramy p50</span><strong>{msf(data.gateway_overhead_ms?.p50)}</strong></div>
        <div><span>Narzut bramy p95</span><strong>{msf(data.gateway_overhead_ms?.p95)}</strong></div>
        <div><span>Całkowity czas p99</span><strong>{msf(data.latency_ms?.p99)}</strong></div>
        <div><span>Kontrole deterministyczne (śr.)</span><strong>{msf(data.average_deterministic_ms)}</strong></div>
        <div><span>Analiza AI (śr., gdy użyta)</span><strong>{msf(data.average_semantic_ms)}</strong></div>
        <div><span>Rozstrzygnięte bez AI</span><strong>{percent(data.deterministic_resolution_rate)}</strong></div>
      </div>
      <p className="fineprint">Czas decyzji nie obejmuje generowania wyjaśnień AI, które działa w tle.</p>
    </Panel>
    <Panel eyebrow="TOŻSAMOŚCI" title="Uprawnienia efektywne: rola ∩ agent">
      {roles.length ? <div className="table-scroll"><table className="matrix">
        <thead><tr><th>Działanie</th>{roles.map(([r]) => <th key={r}>{r}</th>)}{agents.map(([a]) => <th key={a} className="agent-col">agent: {a}</th>)}</tr></thead>
        <tbody>{actions.map(a => { const perm = p.actions[a].permission; return <tr key={a}><td>{ACTION[a] || a}<small>{p.actions[a].require_approval ? ' · zgoda' : ''}</small></td>
          {roles.map(([r, role]) => { const ok = (role.permissions || []).includes(perm); return <td key={r} className={ok ? 'yes' : 'no'} aria-label={ok ? 'tak' : 'nie'}>{ok ? '●' : '·'}</td>; })}
          {agents.map(([n, ag]) => { const ok = (ag.permissions || []).includes(perm); return <td key={n} className={`agent-col ${ok ? 'yes' : 'no'}`}>{ok ? '●' : '·'}</td>; })}
        </tr>; })}</tbody>
      </table></div> : <Empty>Polityka niedostępna dla tej roli.</Empty>}
      <p className="fineprint">Agent wykona działanie tylko wtedy, gdy ma je zarówno rola użytkownika, jak i sam agent, a pozwala na nie polityka zasobu. Agent nigdy nie ma więcej uprawnień niż osoba, która go uruchomiła.</p>
    </Panel>
  </div>;
}
