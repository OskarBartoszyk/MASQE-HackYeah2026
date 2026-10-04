import React, { useEffect, useMemo, useRef, useState } from 'react';
import { api, openStream, ACTION, DECISION, clock, controlLabel, msf } from '../lib';
import { activityLanes, activityStatus, mergeActivity } from '../activity.mjs';

const WINDOW = 86400000;
const STEP = 290, ROW = 190, START = 240;

export function AgentGraph({ apiKey, openEvent, openGhost }) {
  const [events, setEvents] = useState([]), [agent, setAgent] = useState(''), [session, setSession] = useState('');
  const [connection, setConnection] = useState('connecting'), [error, setError] = useState(''), [loaded, setLoaded] = useState(false);
  const [selected, setSelected] = useState(''), [zoom, setZoom] = useState(1), [follow, setFollow] = useState(true);
  const [now, setNow] = useState(Date.now()), [scope, setScope] = useState('own');
  const viewport = useRef(null), drag = useRef(null);

  useEffect(() => {
    let stopped = false, pending = false, duringFetch = [];
    const controller = new AbortController();
    async function refresh() {
      if (pending || stopped) return;
      pending = true; duringFetch = [];
      try {
        const since = new Date(Date.now() - WINDOW).toISOString();
        const result = await api(`/v1/audit?limit=1000&since=${encodeURIComponent(since)}`, apiKey, { signal: controller.signal });
        if (!stopped) { setEvents(mergeActivity(result.events || [], duringFetch, Date.now() - WINDOW)); setScope(result.scope || 'own'); setError(''); setLoaded(true); }
      } catch (e) { if (!stopped) setError(e.message); }
      finally { pending = false; }
    }
    refresh();
    const close = openStream(apiKey, event => {
      if (stopped) return;
      if (pending) duringFetch.push(event);
      setEvents(old => mergeActivity(old, [event], Date.now() - WINDOW));
    }, status => { if (!stopped) { setConnection(status); if (status === 'live') refresh(); } });
    // Snapshot reconciliation recovers events missed during a disconnect.
    const timer = setInterval(() => { setNow(Date.now()); refresh(); }, 10000);
    return () => { stopped = true; controller.abort(); close(); clearInterval(timer); };
  }, [apiKey]);

  const agents = useMemo(() => [...new Set(events.map(e => e.agent).filter(Boolean))].sort(), [events]);
  const activeAgent = agent || agents[0] || '';
  const allLanes = useMemo(() => activityLanes(events, activeAgent), [events, activeAgent]);
  const lanes = useMemo(() => activityLanes(events, activeAgent, session).slice(0, 8).map(l => ({ ...l, omitted: Math.max(0, l.events.length - 40), events: l.events.slice(-40) })), [events, activeAgent, session]);
  const latest = lanes.flatMap(l => l.events).sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))[0];
  const current = events.find(e => e.id === selected) || latest;
  const width = Math.max(900, START + Math.max(1, ...lanes.map(l => l.events.length)) * STEP);
  const height = Math.max(450, lanes.length * ROW + 60);
  const active = events.filter(e => e.agent === activeAgent && activityStatus(e, now).tone === 'running');
  const latestID = latest?.id;
  useEffect(() => {
    if (!follow || !latestID || !viewport.current) return;
    const lane = lanes.findIndex(l => l.events.some(e => e.id === latestID));
    const index = lanes[lane]?.events.findIndex(e => e.id === latestID) || 0;
    viewport.current.scrollTo({ left: Math.max(0, (START + index * STEP) * zoom - viewport.current.clientWidth / 2), top: Math.max(0, lane * ROW * zoom - 40), behavior: 'smooth' });
  }, [latestID, follow, zoom]);

  function beginDrag(e) {
    if (e.button !== 0 || e.target.closest('button')) return;
    drag.current = { x: e.clientX, y: e.clientY, left: e.currentTarget.scrollLeft, top: e.currentTarget.scrollTop };
    e.currentTarget.setPointerCapture(e.pointerId); setFollow(false);
  }

  return <div className="page activity-page">
    <section className="activity-heading">
      <div><span className="eyebrow">LIVE EXECUTION MAP</span><h2>Every action. Its outcome. In context.</h2><p>Select an agent to follow its sessions and inspect each security decision.</p></div>
      <span className={`activity-live ${connection === 'live' ? 'connected' : ''}`} role="status"><i />{connection === 'live' ? 'Live updates' : connection === 'connecting' ? 'Connecting…' : 'Reconnecting…'}</span>
    </section>
    {error && <div className="alert" role="alert">Activity could not be refreshed: {error}. {events.length > 0 && 'Showing the last received records.'}</div>}
    <div className="activity-toolbar">
      <label>Agent<select aria-label="Agent" value={activeAgent} onChange={e => { setAgent(e.target.value); setSession(''); setSelected(''); }}>{!agents.length && <option value="">No observed agents</option>}{agents.map(a => <option key={a}>{a}</option>)}</select></label>
      <label>Session<select aria-label="Session" value={session} onChange={e => { setSession(e.target.value); setSelected(''); }}><option value="">Recent sessions ({allLanes.length})</option>{allLanes.map(l => <option key={l.key} value={l.key}>{l.user} · {l.session || 'Unlinked action'} · {l.events.length} actions</option>)}</select></label>
      <div className="activity-summary"><strong>{active.length}</strong> running <span>·</span> <strong>{allLanes.reduce((n, l) => n + l.events.length, 0)}</strong> observed actions</div>
      <button className={`secondary small ${follow ? 'following' : ''}`} aria-pressed={follow} onClick={() => { if (!follow) setSelected(''); setFollow(!follow); }}>{follow ? 'Following latest' : 'Follow latest'}</button>
    </div>
    <div className="activity-layout">
      <section className="activity-map" aria-label="Agent activity graph">
        <div className="activity-map-bar"><span>SESSION FLOW <small>Dashed links show observed order</small></span><div><button aria-label="Zoom out" onClick={() => setZoom(z => Math.max(.4, +(z - .15).toFixed(2)))}>−</button><button aria-label="Reset zoom" onClick={() => setZoom(1)}>{Math.round(zoom * 100)}%</button><button aria-label="Zoom in" onClick={() => setZoom(z => Math.min(1.6, +(z + .15).toFixed(2)))}>+</button></div></div>
        <div className="activity-viewport" ref={viewport} onPointerDown={beginDrag} onPointerUp={() => { drag.current = null; }} onPointerCancel={() => { drag.current = null; }} onPointerMove={e => { if (drag.current) { e.currentTarget.scrollLeft = drag.current.left - e.clientX + drag.current.x; e.currentTarget.scrollTop = drag.current.top - e.clientY + drag.current.y; } }}>
          {!lanes.length ? <div className="activity-empty"><span>◎</span><h3>{loaded ? 'Waiting for agent activity' : 'Loading activity…'}</h3><p>{loaded ? 'Run a request in Playground, your agent or Ghost Shell. Its recorded actions will appear here automatically.' : 'Connecting to the gateway audit stream.'}</p></div> : <div style={{ width: width * zoom, height: height * zoom }}><div className="activity-canvas" style={{ width, height, transform: `scale(${zoom})` }}>
            <svg width={width} height={height} className="activity-edges" aria-hidden="true"><defs><marker id="activity-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0L8 4L0 8" fill="none" stroke="#a6b6ad" /></marker></defs>{lanes.map((lane, row) => lane.events.map((event, i) => { const y = row * ROW + 103, x = START + i * STEP; return <path key={event.id} d={`M${i ? x - STEP + 240 : 195} ${y} H${x - 10}`} markerEnd="url(#activity-arrow)" />; }))}</svg>
            {lanes.map((lane, row) => <React.Fragment key={lane.key}>
              <div className="activity-session" style={{ top: row * ROW + 62 }}><span>SESSION {String(row + 1).padStart(2, '0')}</span><strong title={lane.user}>{lane.user}</strong><code title={lane.session}>{lane.session || 'No session ID'}</code>{lane.omitted > 0 && <small>Latest 40 of {lane.events.length + lane.omitted} actions</small>}</div>
              {lane.events.map((event, i) => { const state = activityStatus(event, now); return <button key={event.id} className={`activity-node ${state.tone} ${current?.id === event.id ? 'selected' : ''}`} style={{ left: START + i * STEP, top: row * ROW + 38 }} onClick={() => { setSelected(event.id); setFollow(false); }} aria-label={`${ACTION[event.action] || event.action}: ${state.label}`} aria-pressed={current?.id === event.id}>
                <span className="activity-node-top"><span className="activity-state"><i />{state.label}</span><time>{clock(event.timestamp)}</time></span><strong>{ACTION[event.action] || event.action}</strong><span className="activity-resource" title={event.resource}>{event.resource || 'No resource'}</span><span className="activity-node-foot">{DECISION[event.decision]?.[0] || event.decision}<span>{event.model || 'Tool action'}</span></span>
              </button>; })}
            </React.Fragment>)}
          </div></div>}
        </div>
        <div className="activity-legend">{[['running', 'Running'], ['done', 'Completed'], ['waiting', 'Waiting'], ['blocked', 'Stopped'], ['ghost', 'Emulated']].map(([tone, label]) => <span key={tone} className={tone}><i />{label}</span>)}<small>Drag to pan · click a step to inspect</small></div>
      </section>
      <aside className="activity-detail" aria-label="Selected action details">
        <span className="eyebrow">ACTION INSPECTOR</span>
        {current ? <><h3>{ACTION[current.action] || current.action}</h3><span className={`activity-state ${activityStatus(current, now).tone}`}><i />{activityStatus(current, now).label}</span><dl><dt>Agent</dt><dd>{current.agent}</dd><dt>User</dt><dd>{current.user}</dd><dt>Resource</dt><dd>{current.resource || '—'}</dd><dt>Recorded at</dt><dd>{clock(current.timestamp)}</dd><dt>Gateway overhead</dt><dd>{msf(current.gateway_ms)}</dd><dt>Security decision</dt><dd>{DECISION[current.decision]?.[0] || current.decision}</dd></dl><h4>Why this decision?</h4><ul>{(current.reasons || []).map((r, i) => <li key={i}>{r}</li>)}</ul>{!current.reasons?.length && <p>No additional reasons recorded.</p>}<div className="activity-controls">{(current.controls || []).map(c => <span key={c}>{controlLabel(c)}</span>)}</div><button className="secondary" onClick={() => openEvent(current.id)}>Open full event →</button>{current.session_id?.startsWith('gs_') && <button className="secondary" onClick={() => openGhost(current.session_id)}>Open Ghost Shell →</button>}<code className="activity-event-id">{current.id}</code></> : <p>Select a step in the graph to see its resource, outcome and security checks.</p>}
      </aside>
    </div>
    <p className="fineprint">{scope === 'all' ? 'All users' : 'Your events'} · Last 24 hours · Up to 1,000 records, 8 recent sessions and 40 actions per lane. Select a session to inspect it. Connections represent recorded order, not task dependencies. External tools are shown as waiting until their output is reported; older running records are marked unconfirmed.</p>
  </div>;
}
