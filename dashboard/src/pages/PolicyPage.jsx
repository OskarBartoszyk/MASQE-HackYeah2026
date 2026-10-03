import React from 'react';
import { Panel, Empty } from '../ui';
import { GUARDS, DECISION, number, percent, dateTime } from '../lib';

const ACTION_LABEL = { block: 'block', redact: 'redact', require_approval: 'human approval', ghost: 'isolate', throttle: 'throttle', log: 'log only' };

export function PolicyPage({ policy, health }) {
  const p = policy?.policy;
  if (!p) return <div className="page"><Empty>The policy is not available for this role.</Empty></div>;
  const feed = policy.threat_feed?.signatures || [];
  return <div className="page">
    <div className="policy-bar">
      <div><span className="eyebrow">ACTIVE POLICY</span><h2>Mode {p.mode}</h2><p className="muted">Version {p.version} · hash <code>{policy.hash}</code> · loaded {dateTime(policy.reloaded_at)}</p></div>
      <p className="muted small">Edits to <code>policies/policy.yaml</code> or <code>threat-feed.yaml</code> apply from the next request. An invalid file is rejected and the last valid version keeps serving.</p>
    </div>
    {health?.config_error && <div className="alert">The last change was rejected: <code>{health.config_error}</code></div>}
    {!policy.full && <div className="notice">Thresholds and signature patterns are visible to the security team only, so nobody can tune an attack just below a threshold.</div>}
    <Panel eyebrow="CONTROLS" title="Guardrails">
      <div className="guards">{Object.entries(GUARDS).map(([id, [name, desc]]) => { const g = p.security?.[id] || {}; return <article key={id} className={`guard ${g.enabled ? '' : 'off'}`}>
        <span className={`status-tag ${g.enabled ? 'ok' : 'exceeded'}`}>{g.enabled ? 'Enabled' : 'Disabled'}</span><h3>{name}</h3><p>{desc}</p>
        <footer><span>Action: <b>{ACTION_LABEL[g.action] || g.action || '—'}</b></span>{g.threshold > 0 && <span>{id === 'intent_lock' ? 'Min. alignment' : 'Threshold'}: <b>{percent(g.threshold)}</b></span>}</footer>
      </article>; })}</div>
    </Panel>
    <div className="two">
      <Panel eyebrow="LIMITS" title="Budgets and limits"><dl className="kv">
        <div><dt>Daily tokens (org.)</dt><dd>{number(p.budgets?.daily_tokens)}</dd></div><div><dt>Daily cost (org.)</dt><dd>${Number(p.budgets?.daily_cost_usd || 0).toFixed(2)}</dd></div>
        <div><dt>Requests / min</dt><dd>{number(p.budgets?.requests_per_minute)}</dd></div><div><dt>Max steps / session</dt><dd>{number(p.budgets?.max_steps)}</dd></div>
        <div><dt>Default user limit</dt><dd>{number(p.user_default_budget?.daily_tokens)} tokens</dd></div><div><dt>New sessions / min</dt><dd>{number(p.sessions?.max_new_per_minute)}</dd></div>
        <div><dt>Allowed models</dt><dd>{(p.allowed_models || []).join(', ')}</dd></div>
      </dl></Panel>
      <Panel eyebrow="RESOURCES" title="Resource policy"><ul className="rules">{(p.resources || []).map(r => <li key={r.id || r.pattern}><code>{r.pattern}</code><span>{r.decision ? DECISION[r.decision.toUpperCase()]?.[0] || r.decision : ''}{r.permission ? ` · requires ${r.permission}` : ''}</span><small>{r.reason}</small></li>)}</ul></Panel>
    </div>
    <Panel eyebrow="THREAT FEED" title={`Known attack signatures (${feed.length})`}>
      <p className="muted small">{policy.remote_feed ? `Remote feed: ${policy.remote_feed}` : 'Local feed; a remote source can be enabled in threat_feed_remote.'}</p>
      <div className="table-scroll"><table className="data"><thead><tr><th>ID</th><th>Description</th><th>Severity</th><th>Action</th>{policy.full && <th>Pattern</th>}</tr></thead>
        <tbody>{feed.map(s => <tr key={s.id}><td><code>{s.id}</code></td><td>{s.description}{s.reference && <small> · {s.reference}</small>}</td><td>{s.severity || '—'}</td><td>{s.action}</td>{policy.full && <td><code className="pattern">{s.pattern}</code></td>}</tr>)}</tbody></table></div>
    </Panel>
  </div>;
}
