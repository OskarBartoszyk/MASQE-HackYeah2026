import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import '../styles.css';
import '../console.css';
import '../app.css';
import { GhostShell } from './GhostShell';
import { Mark, Icon } from './Identity';
import { api, openStream, storage, RANGES, rangeMs, DEMO_IDENTITIES, number } from './lib';
import { Segmented, EventDrawer, Explanation } from './ui';
import { Operations } from './pages/Operations';
import { Events } from './pages/Events';
import { Incidents } from './pages/Incidents';
import { Agents } from './pages/Agents';
import { PolicyPage } from './pages/PolicyPage';
import { Playground } from './pages/Playground';
import { useTrafficGenerator, juryProgress, JuryPanel } from './demo';

const PAGES = {
  operations: ['Operations center', 'Live gateway decisions, incidents and resources.'],
  incidents: ['Incidents', 'Confirmed attacks and evidence for the security team to handle.'],
  events: ['Event log', 'Every decision with its full control trace.'],
  ghost: ['Ghost Shell', 'Isolated workspace for untrusted code, with honeytokens and a recorder.'],
  agents: ['Agents & resources', 'Effective permissions, budgets, costs and performance.'],
  policy: ['Policy', 'Active control configuration and threat feed.'],
  playground: ['Playground', 'Send any agent request and see the decision.'],
};
const NAV = [['operations', 'Operations'], ['incidents', 'Incidents'], ['events', 'Events'], ['ghost', 'Ghost Shell'], ['agents', 'Agents & resources'], ['policy', 'Policy']];

function initialPage() {
  const h = (window.location.hash || '').replace('#/', '').split('?')[0];
  return PAGES[h] ? h : 'operations';
}
const linkedEvent = new URLSearchParams((window.location.hash.split('?')[1]) || '').get('event');

function App() {
  const [demo, setDemo] = useState(() => storage.get('masqe-demo', true));
  const [key, setKey] = useState(() => storage.get('masqe-key', 'secops-demo-key'));
  const [page, setPage] = useState(initialPage);
  const [range, setRange] = useState(() => storage.get('masqe-range', '1h'));
  const [me, setMe] = useState(null), [data, setData] = useState({ decisions: {} }), [events, setEvents] = useState([]), [scope, setScope] = useState('own');
  const [incidents, setIncidents] = useState([]), [approvals, setApprovals] = useState([]), [policy, setPolicy] = useState(null), [health, setHealth] = useState(null);
  const [stream, setStream] = useState('connecting'), [offline, setOffline] = useState(''), [notice, setNotice] = useState('');
  const [paused, setPaused] = useState(false), [buffer, setBuffer] = useState([]), [fresh, setFresh] = useState(new Set());
  const [drawer, setDrawer] = useState(null), [drawerFallback, setDrawerFallback] = useState(null);
  const [filters, setFilters] = useState({}), [incidentId, setIncidentId] = useState(null), [ghostSession, setGhostSession] = useState(null);
  const [busy, setBusy] = useState(false), [generator, setGenerator] = useState(false), [jury, setJury] = useState(false), [exported, setExported] = useState(false);
  const [search, setSearch] = useState(''), [keyDraft, setKeyDraft] = useState('');
  const initialHash = useRef(null), pausedRef = useRef(paused), refreshTimer = useRef(null);
  pausedRef.current = paused;
  const can = p => (me?.console || []).includes(p);

  useEffect(() => { storage.set('masqe-demo', demo); storage.set('masqe-key', key); storage.set('masqe-range', range); }, [demo, key, range]);
  useEffect(() => { if (!window.location.hash.startsWith('#/' + page)) window.location.hash = '/' + page; }, [page]);
  useTrafficGenerator(demo && generator);

  const loadSummary = useCallback(async () => {
    try {
      const identity = await api('/v1/me', key);
      const has = p => (identity.console || []).includes(p);
      const [telemetry, inc, apr, status] = await Promise.all([
        has('telemetry.read') ? api(`/v1/telemetry?range=${range}`, key) : Promise.resolve({ decisions: {} }),
        has('audit.read_own') ? api('/v1/incidents', key) : Promise.resolve({ incidents: [] }),
        identity.can_approve ? api('/v1/approvals', key) : Promise.resolve({ approvals: [] }),
        fetch('/health').then(r => r.json()).catch(() => null),
      ]);
      setMe(identity); setData(telemetry); setIncidents(inc.incidents || []); setApprovals(apr.approvals || []); setHealth(status); setOffline('');
    } catch (e) { setOffline(e.message); }
  }, [key, range]);
  const loadPolicy = useCallback(async () => {
    try { const p = await api('/v1/policy', key); setPolicy(p); if (!initialHash.current) initialHash.current = p.hash; } catch { setPolicy(null); }
  }, [key]);
  const loadEvents = useCallback(async () => {
    try {
      const since = new Date(Date.now() - rangeMs[range]).toISOString();
      const out = await api(`/v1/audit?limit=1000&since=${encodeURIComponent(since)}`, key);
      setEvents(out.events || []); setScope(out.scope || 'own');
    } catch { setEvents([]); }
  }, [key, range]);

  useEffect(() => { loadSummary(); loadEvents(); loadPolicy(); }, [loadSummary, loadEvents, loadPolicy]);
  // Deep link: #/events?event=req_… opens the event drawer.
  useEffect(() => { if (linkedEvent) openEvent(linkedEvent); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { const t = setInterval(loadSummary, 10000), p = setInterval(loadPolicy, 15000); return () => { clearInterval(t); clearInterval(p); }; }, [loadSummary, loadPolicy]);

  // Live stream: upsert events, highlight new ones, refresh aggregates (throttled).
  const upsert = useCallback(list => {
    setEvents(prev => {
      const map = new Map(prev.map(e => [e.id, e]));
      list.forEach(e => map.set(e.id, e));
      const cutoff = Date.now() - rangeMs[range];
      return [...map.values()].filter(e => new Date(e.timestamp).getTime() >= cutoff).sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1)).slice(0, 1500);
    });
    setFresh(prev => { const next = new Set(prev); list.forEach(e => next.add(e.id)); return next; });
    setTimeout(() => setFresh(prev => { const next = new Set(prev); list.forEach(e => next.delete(e.id)); return next; }), 4000);
  }, [range]);
  useEffect(() => openStream(key, e => {
    if (pausedRef.current) setBuffer(b => [...b.filter(x => x.id !== e.id), e]); else upsert([e]);
    if (!refreshTimer.current) refreshTimer.current = setTimeout(() => { refreshTimer.current = null; loadSummary(); }, 1500);
  }, setStream), [key, upsert, loadSummary]);
  const flush = () => { upsert(buffer); setBuffer([]); };
  useEffect(() => { if (!paused && buffer.length) flush(); }, [paused]); // eslint-disable-line react-hooks/exhaustive-deps

  const go = (target, opts = {}) => {
    if (target === 'events') setFilters(opts);
    if (target === 'incidents') setIncidentId(opts.id || null);
    if (target === 'ghost') setGhostSession(opts.session || null);
    setPage(target); setDrawer(null); window.scrollTo({ top: 0 });
  };
  const openEvent = async id => {
    setDrawer(id); setDrawerFallback(null);
    if (!events.some(e => e.id === id)) { try { setDrawerFallback(await api(`/v1/events/${encodeURIComponent(id)}`, key)); } catch (e) { setNotice(e.message); setDrawer(null); } }
  };
  const drawerEvent = events.find(e => e.id === drawer) || (drawerFallback?.id === drawer ? drawerFallback : null);
  async function approve(id) {
    setBusy(true);
    try { const r = await api(`/v1/approvals/${encodeURIComponent(id)}/approve`, key, { method: 'POST' }); setNotice(r.executed ? 'Approved and executed.' : 'Approved, but the action was not executed.'); loadSummary(); }
    catch (e) { setNotice(e.message); } finally { setBusy(false); }
  }
  async function exportFile(kind) {
    try {
      const r = await fetch(`/v1/audit/export.${kind}?since=${encodeURIComponent(new Date(Date.now() - rangeMs[range]).toISOString())}`, { headers: { Authorization: `Bearer ${key}` } });
      if (!r.ok) throw new Error('Could not download the audit log.');
      const url = URL.createObjectURL(await r.blob()); const a = document.createElement('a'); a.href = url; a.download = `masqe-audit.${kind}`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
      setExported(true);
    } catch (e) { setNotice(e.message); }
  }
  const run = form => api('/v1/execute', key, { method: 'POST', body: JSON.stringify({ session_id: `play-${crypto.randomUUID()}`, agent: { id: 'corporate-agent', model: form.model }, action: form.action, resource: form.resource, prompt: form.prompt, original_intent: form.intent }) });
  const switchKey = k => { if (k && k !== key) { setKey(k); setEvents([]); setIncidents([]); setMe(null); setDrawer(null); initialHash.current = null; } };

  const openIncidents = incidents.filter(i => i.status !== 'resolved').length;
  const progress = useMemo(() => juryProgress({ events, incidents, policyHash: policy?.hash, initialHash: initialHash.current, exported }), [events, incidents, policy?.hash, exported]);
  const nav = demo ? [...NAV, ['playground', 'Playground']] : NAV;
  const [title, subtitle] = PAGES[page];
  const chip = (label, state, tip) => <span className={`svc ${state}`} title={tip}><i />{label}</span>;

  return <div className={`app console ${demo ? 'demo' : ''}`}>
    <aside className="sidebar">
      <div className="brand"><Mark /><span>MASQE<small>AI SECURITY CONSOLE</small></span></div>
      <nav className="nav" aria-label="Navigation">{nav.map(([id, name]) => <button key={id} className={page === id ? 'active' : ''} onClick={() => go(id)}>
        <Icon name={id} /><span>{name}</span>{id === 'incidents' && openIncidents > 0 && <b className="count">{openIncidents}</b>}
      </button>)}</nav>
      <div className="sidebar-foot">
        <label className="switch"><input type="checkbox" checked={demo} onChange={e => { setDemo(e.target.checked); if (!e.target.checked) { setGenerator(false); setJury(false); if (page === 'playground') setPage('operations'); } }} /><span />Demo mode</label>
        <div className="account"><span className="avatar">{(me?.user_id || '?')[0].toUpperCase()}</span><span><strong>{me?.user_id || 'Not connected'}</strong><small>{me?.role || 'invalid key'}</small></span></div>
        {!demo && <form className="key-form" onSubmit={e => { e.preventDefault(); switchKey(keyDraft.trim()); setKeyDraft(''); }}><input type="password" placeholder="API key" value={keyDraft} onChange={e => setKeyDraft(e.target.value)} aria-label="API key" autoComplete="off" /><button className="secondary small">Sign in</button></form>}
      </div>
    </aside>
    <main className="main">
      <header className="bar">
        <div className="bar-title"><h1>{title}</h1><p>{subtitle}</p></div>
        <div className="bar-tools">
          <div className="services">
            {chip('Gateway', health ? (health.status === 'ok' ? 'ok' : 'warn') : 'bad', health?.config_error ? 'Last configuration change rejected' : 'Gateway')}
            {chip('AI layer', health?.semantic_degraded ? 'bad' : 'ok', health?.semantic_degraded ? 'AI Guard unavailable: failing closed' : 'AI Guard')}
            {chip('PII model', health?.pii_model === 'enabled' ? 'ok' : health?.pii_model === 'degraded' ? 'bad' : 'warn', health?.pii_model === 'enabled' ? 'HerBERT (PLVeil) active' : health?.pii_model === 'degraded' ? 'Model unavailable: rules only' : health?.pii_model === 'not_installed' ? 'Model not installed in this deployment: rules only' : health?.pii_model === 'loading' ? 'Model loading: rules only for now' : 'Disabled in policy')}
            {chip('Ghost', data.ghost_shell?.available ? 'ok' : 'warn', 'Ghost Shell')}
            {chip(stream === 'live' ? 'Live' : stream === 'connecting' ? 'Connecting' : 'Offline', stream === 'live' ? 'live' : stream === 'connecting' ? 'warn' : 'bad', 'Event stream')}
          </div>
          <Segmented label="Time range" value={range} options={RANGES} onChange={r => setRange(r)} />
          <form className="search" onSubmit={e => { e.preventDefault(); go('events', { q: search }); }}><Icon name="search" /><input placeholder="Search events…" value={search} onChange={e => setSearch(e.target.value)} aria-label="Search events" /></form>
          <button className="bell" onClick={() => go('incidents')} aria-label={`Incidents: ${openIncidents}`}><Icon name="bell" />{openIncidents + approvals.length > 0 && <b>{openIncidents + approvals.length}</b>}</button>
        </div>
      </header>
      {demo && <div className="demo-bar">
        <span className="eyebrow">DEMO MODE</span>
        <label>Acting as <select value={key} onChange={e => switchKey(e.target.value)}>{DEMO_IDENTITIES.map(([k, n, r]) => <option key={k} value={k}>{n} · {r}</option>)}</select></label>
        <label className="switch small"><input type="checkbox" checked={generator} onChange={e => setGenerator(e.target.checked)} /><span />Employee traffic generator</label>
        <button className="secondary small" onClick={() => setJury(!jury)}>Jury checklist · {Object.values(progress).filter(Boolean).length}/8</button>
        <button className="secondary small" onClick={() => go('playground')}>Playground →</button>
      </div>}
      {offline && <div className="alert" role="alert">No connection to the gateway: {offline}</div>}
      {health?.config_error && <div className="alert" role="alert"><strong>The last configuration change was rejected.</strong> The previous valid policy keeps serving. <code>{health.config_error}</code></div>}
      {notice && <div className="notice" role="status">{notice}<button onClick={() => setNotice('')} aria-label="Close">×</button></div>}
      {page === 'operations' && <Operations data={data} events={events} fresh={fresh} incidents={incidents} approvals={approvals} me={me} range={range} go={go} openEvent={openEvent} approve={approve} busy={busy} paused={paused} setPaused={setPaused} buffered={buffer.length} flush={flush} demo={demo} />}
      {page === 'incidents' && <Incidents apiKey={key} incidents={incidents} selectedId={incidentId} select={setIncidentId} canTriage={can('audit.read_all')} reload={loadSummary} openGhost={id => go('ghost', { session: id })} openEvent={openEvent} />}
      {page === 'events' && <Events events={events} filters={filters} setFilters={setFilters} openEvent={openEvent} canExport={can('audit.export')} exportFile={exportFile} scope={scope} apiKey={key} canVerify={can('audit.read_all')} />}
      {page === 'ghost' && <GhostShell key={`${key}-${ghostSession}`} apiKey={key} api={api} XAI={Explanation} initialSession={ghostSession} demo={demo} />}
      {page === 'agents' && <Agents data={data} policy={policy} />}
      {page === 'policy' && <PolicyPage policy={policy} health={health} />}
      {page === 'playground' && <Playground me={me} run={run} openEvent={openEvent} openGhost={id => go('ghost', { session: id })} />}
      <footer className="foot"><span>MASQE · zero-trust gateway for AI agents</span><span>{number(events.length)} events in view · policy {policy?.hash || '—'}</span></footer>
    </main>
    {drawerEvent && <EventDrawer event={drawerEvent} onClose={() => setDrawer(null)} onSession={sid => go('events', { session: sid })} onGhost={sid => go('ghost', { session: sid })} />}
    {demo && jury && <JuryPanel progress={progress} onClose={() => setJury(false)} />}
  </div>;
}

createRoot(document.getElementById('root')).render(<React.StrictMode><App /></React.StrictMode>);
