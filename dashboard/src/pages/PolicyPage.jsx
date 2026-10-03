import React from 'react';
import { Panel, Empty } from '../ui';
import { GUARDS, DECISION, number, percent, dateTime } from '../lib';

const ACTION_PL = { block: 'blokada', redact: 'redakcja', require_approval: 'zgoda człowieka', ghost: 'izolacja', throttle: 'spowolnienie', log: 'tylko zapis' };

export function PolicyPage({ policy, health }) {
  const p = policy?.policy;
  if (!p) return <div className="page"><Empty>Polityka jest niedostępna dla tej roli.</Empty></div>;
  const feed = policy.threat_feed?.signatures || [];
  return <div className="page">
    <div className="policy-bar">
      <div><span className="eyebrow">AKTYWNA POLITYKA</span><h2>Tryb {p.mode}</h2><p className="muted">Wersja {p.version} · hash <code>{policy.hash}</code> · wczytano {dateTime(policy.reloaded_at)}</p></div>
      <p className="muted small">Edycja <code>policies/policy.yaml</code> lub <code>threat-feed.yaml</code> działa od następnego żądania. Błędny plik jest odrzucany, a działa ostatnia poprawna wersja.</p>
    </div>
    {health?.config_error && <div className="alert">Ostatnia zmiana została odrzucona: <code>{health.config_error}</code></div>}
    {!policy.full && <div className="notice">Progi czułości i wzorce sygnatur widzi tylko zespół bezpieczeństwa, żeby nikt nie mógł dostroić ataku tuż pod próg.</div>}
    <Panel eyebrow="KONTROLE" title="Zabezpieczenia">
      <div className="guards">{Object.entries(GUARDS).map(([id, [name, desc]]) => { const g = p.security?.[id] || {}; return <article key={id} className={`guard ${g.enabled ? '' : 'off'}`}>
        <span className={`status-tag ${g.enabled ? 'ok' : 'exceeded'}`}>{g.enabled ? 'Włączona' : 'Wyłączona'}</span><h3>{name}</h3><p>{desc}</p>
        <footer><span>Reakcja: <b>{ACTION_PL[g.action] || g.action || '—'}</b></span>{g.threshold > 0 && <span>{id === 'intent_lock' ? 'Min. zgodność' : 'Próg'}: <b>{percent(g.threshold)}</b></span>}</footer>
      </article>; })}</div>
    </Panel>
    <div className="two">
      <Panel eyebrow="LIMITY" title="Budżety i limity"><dl className="kv">
        <div><dt>Tokeny dziennie (org.)</dt><dd>{number(p.budgets?.daily_tokens)}</dd></div><div><dt>Koszt dzienny (org.)</dt><dd>${Number(p.budgets?.daily_cost_usd || 0).toFixed(2)}</dd></div>
        <div><dt>Żądania / min</dt><dd>{number(p.budgets?.requests_per_minute)}</dd></div><div><dt>Maks. kroków / sesję</dt><dd>{number(p.budgets?.max_steps)}</dd></div>
        <div><dt>Domyślny limit użytkownika</dt><dd>{number(p.user_default_budget?.daily_tokens)} tok.</dd></div><div><dt>Nowe sesje / min</dt><dd>{number(p.sessions?.max_new_per_minute)}</dd></div>
        <div><dt>Dozwolone modele</dt><dd>{(p.allowed_models || []).join(', ')}</dd></div>
      </dl></Panel>
      <Panel eyebrow="ZASOBY" title="Polityka zasobów"><ul className="rules">{(p.resources || []).map(r => <li key={r.id || r.pattern}><code>{r.pattern}</code><span>{r.decision ? DECISION[r.decision.toUpperCase()]?.[0] || r.decision : ''}{r.permission ? ` · wymaga ${r.permission}` : ''}</span><small>{r.reason}</small></li>)}</ul></Panel>
    </div>
    <Panel eyebrow="THREAT FEED" title={`Sygnatury znanych ataków (${feed.length})`}>
      <p className="muted small">{policy.remote_feed ? `Feed zdalny: ${policy.remote_feed}` : 'Feed lokalny; zdalne źródło można włączyć w threat_feed_remote.'}</p>
      <div className="table-scroll"><table className="data"><thead><tr><th>ID</th><th>Opis</th><th>Waga</th><th>Reakcja</th>{policy.full && <th>Wzorzec</th>}</tr></thead>
        <tbody>{feed.map(s => <tr key={s.id}><td><code>{s.id}</code></td><td>{s.description}{s.reference && <small> · {s.reference}</small>}</td><td>{s.severity || '—'}</td><td>{s.action}</td>{policy.full && <td><code className="pattern">{s.pattern}</code></td>}</tr>)}</tbody></table></div>
    </Panel>
  </div>;
}
