import React from 'react';
import { Panel, Empty } from '../ui';
import { ACTION, number, percent, usd, msf } from '../lib';

const STATUS_LABEL = { OK: 'OK', WARN: 'Warning', THROTTLE: 'Throttled', EXCEEDED: 'Exceeded' };

// Identities, effective authority and resource consumption.
export function Agents({ data, policy }) {
  const p = policy?.policy;
  const roles = Object.entries(p?.roles || {});
  const agents = Object.entries(p?.agents || {});
  const actions = Object.keys(p?.actions || {}).sort();
  return <div className="page">
    <Panel eyebrow="RESOURCES · TODAY" title="Budgets and costs">
      {(data.budgets || []).length ? <div className="table-scroll"><table className="data">
        <thead><tr><th>Scope</th><th>Tokens</th><th>Limit</th><th>Cost</th><th>Cost limit</th><th>Usage</th><th>Status</th></tr></thead>
        <tbody>{data.budgets.map(b => <tr key={b.scope}><td><code>{b.scope}</code></td><td>{number(b.tokens)}</td><td>{b.token_limit ? number(b.token_limit) : '∞'}</td><td>{usd(b.cost_usd)}</td><td>{b.cost_limit_usd ? usd(b.cost_limit_usd) : '—'}</td>
          <td><span className="meter inline"><i className={b.status.toLowerCase()} style={{ width: `${Math.min(100, b.used_ratio * 100)}%` }} /></span> {percent(b.used_ratio)}</td>
          <td><span className={`status-tag ${b.status.toLowerCase()}`}>{STATUS_LABEL[b.status]}</span></td></tr>)}</tbody>
      </table></div> : <Empty>No usage today.</Empty>}
      <p className="fineprint">Bands: warning from {percent(p?.budget_alerts?.warn_at)}, throttling from {percent(p?.budget_alerts?.throttle_at)}, block at 100%. Usage is measured by the gateway and reconciled with the model's actual consumption.</p>
    </Panel>
    <Panel eyebrow="PERFORMANCE" title="Gateway telemetry">
      <div className="perf-grid">
        <div><span>Gateway overhead p50</span><strong>{msf(data.gateway_overhead_ms?.p50)}</strong></div>
        <div><span>Gateway overhead p95</span><strong>{msf(data.gateway_overhead_ms?.p95)}</strong></div>
        <div><span>Total latency p99</span><strong>{msf(data.latency_ms?.p99)}</strong></div>
        <div><span>Deterministic checks (avg)</span><strong>{msf(data.average_deterministic_ms)}</strong></div>
        <div><span>AI analysis (avg, when used)</span><strong>{msf(data.average_semantic_ms)}</strong></div>
        <div><span>PII model (avg, uncached calls)</span><strong>{msf(data.average_pii_model_ms)}</strong></div>
        <div><span>Resolved without AI</span><strong>{percent(data.deterministic_resolution_rate)}</strong></div>
      </div>
      <p className="fineprint">Gateway overhead is the gateway's own work. The PII model and the semantic guard run in parallel and are reported separately; repeated texts reuse cached model results. AI explanations are generated in the background.</p>
    </Panel>
    <Panel eyebrow="IDENTITIES" title="Effective permissions: role ∩ agent">
      {roles.length ? <div className="table-scroll"><table className="matrix">
        <thead><tr><th>Action</th>{roles.map(([r]) => <th key={r}>{r}</th>)}{agents.map(([a]) => <th key={a} className="agent-col">agent: {a}</th>)}</tr></thead>
        <tbody>{actions.map(a => { const perm = p.actions[a].permission; return <tr key={a}><td>{ACTION[a] || a}<small>{p.actions[a].require_approval ? ' · approval' : ''}</small></td>
          {roles.map(([r, role]) => { const ok = (role.permissions || []).includes(perm); return <td key={r} className={ok ? 'yes' : 'no'} aria-label={ok ? 'yes' : 'no'}>{ok ? '●' : '·'}</td>; })}
          {agents.map(([n, ag]) => { const ok = (ag.permissions || []).includes(perm); return <td key={n} className={`agent-col ${ok ? 'yes' : 'no'}`}>{ok ? '●' : '·'}</td>; })}
        </tr>; })}</tbody>
      </table></div> : <Empty>Policy not available for this role.</Empty>}
      <p className="fineprint">An agent can act only when both the user's role and the agent hold the permission and the resource policy allows it. An agent never has more authority than the person who runs it.</p>
    </Panel>
  </div>;
}
