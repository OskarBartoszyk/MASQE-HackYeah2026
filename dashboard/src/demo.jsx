import React, { useEffect, useRef } from 'react';

// Background traffic of ordinary employees, so the console looks like a real
// workday and the jury's attacks stand out against normal work.
const PROFILES = [
  ['demo-key', 'reports.read', 'reports/Q4.pdf', 'Summarize the Q4 report', 'Summarize the Q4 report'],
  ['demo-key', 'customer.read', 'customer/123', 'Look up customer 123 for the support ticket', 'Look up customer 123 for the support ticket'],
  ['demo-key', 'documents.read', 'documents/operating-summary', 'Read the operating summary', 'Read the operating summary'],
  ['support-demo-key', 'customer.read', 'customer/456', 'Check the status of customer 456', 'Check the status of customer 456'],
  ['support-demo-key', 'email.send', 'mail/outbox', 'Send the approved shipping update to the customer', 'Send the approved shipping update to the customer'],
  ['developer-demo-key', 'llm.generate', 'model/demo-local', 'Draft release notes for version 2.4', 'Draft release notes for version 2.4'],
  ['developer-demo-key', 'documents.read', 'documents/hr-policy', 'Read the HR policy summary', 'Read the HR policy summary'],
  ['viewer-demo-key', 'reports.read', 'reports/Q4.pdf', 'Show me the Q4 report', 'Show me the Q4 report'],
];

export function useTrafficGenerator(enabled) {
  const sessions = useRef({});
  useEffect(() => {
    if (!enabled) return undefined;
    let timer, alive = true;
    const started = Date.now().toString(36);
    async function tick() {
      const [key, action, resource, prompt, intent] = PROFILES[Math.floor(Math.random() * PROFILES.length)];
      // A real task is a few steps long: start a new session every 3–5 calls so
      // the runaway limit (max tool calls per session) is never hit by normal work.
      const slot = sessions.current[key + intent] ||= { n: 0, id: '' };
      if (!slot.id || slot.n >= 3 + Math.floor(Math.random() * 3)) { slot.id = `gen-${started}-${Math.random().toString(36).slice(2, 9)}`; slot.n = 0; }
      slot.n++;
      const sid = slot.id;
      try {
        await fetch('/v1/execute', { method: 'POST', headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ session_id: sid, agent: { id: 'corporate-agent', model: 'demo-local' }, action, resource, prompt, original_intent: intent }) });
      } catch { /* gateway restarting */ }
      if (alive) timer = setTimeout(tick, 2500 + Math.random() * 3500);
    }
    timer = setTimeout(tick, 800);
    return () => { alive = false; clearTimeout(timer); };
  }, [enabled]);
}

const STEPS = [
  ['allow', 'A normal task is allowed', 'Playground → “Normal task”.'],
  ['injection', 'An instruction attack is blocked', 'Your own prompt, e.g. “Ignore previous instructions…”, or the “Jailbreak” scenario.'],
  ['pii', 'Personal data is redacted', 'The “Personal data” scenario, or your own name / PESEL / e-mail / IBAN.'],
  ['signature', 'Threat-feed signature', 'Add a pattern to policies/threat-feed.yaml and send matching text.'],
  ['reload', 'Policy change without restart', 'Change e.g. mode: strict → permissive in policies/policy.yaml.'],
  ['ghost', 'Attack captured in Ghost Shell', 'Ghost Shell → “Replay attack scenario”.'],
  ['approval', 'Second-person approval', 'As Admin: delete a customer; as SecOps: approve it.'],
  ['export', 'Audit export', 'Events → Export CSV/JSON (SecOps role).'],
];

export function juryProgress({ events, incidents, policyHash, initialHash, exported }) {
  const own = events.filter(e => !String(e.session_id || '').startsWith('gen-'));
  const has = f => own.some(f);
  return {
    allow: has(e => e.decision === 'ALLOW'),
    injection: has(e => e.decision === 'BLOCK' && ((e.controls || []).some(c => ['prompt_injection', 'data_exfiltration', 'intent_lock'].includes(c)) || (e.reasons || []).some(r => r.includes('flagged') || r.includes('injection')))),
    pii: has(e => e.decision === 'REDACT' || (e.controls || []).includes('pii')),
    signature: has(e => (e.controls || []).some(c => c.startsWith('threat'))),
    reload: Boolean(initialHash && policyHash && initialHash !== policyHash),
    ghost: incidents.some(i => i.source === 'ghost_shell'),
    approval: has(e => Boolean(e.approved_by)),
    export: exported,
  };
}

export function JuryPanel({ progress, onClose }) {
  const done = STEPS.filter(([id]) => progress[id]).length;
  return <aside className="jury" aria-label="Jury checklist">
    <header><div><span className="eyebrow">DEMO MODE</span><h2>Jury checklist</h2><span className="muted small">{done} of {STEPS.length} steps · ticks itself off</span></div><button className="icon-btn" onClick={onClose} aria-label="Close">×</button></header>
    <ol>{STEPS.map(([id, title, hint]) => <li key={id} className={progress[id] ? 'done' : ''}><span>{progress[id] ? '✓' : '○'}</span><div><strong>{title}</strong><small>{hint}</small></div></li>)}</ol>
    <p className="muted small">Test suite: <code>make test</code> (Go, Python, end-to-end).</p>
  </aside>;
}
