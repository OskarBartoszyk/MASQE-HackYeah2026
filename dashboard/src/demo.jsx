import React, { useEffect, useRef } from 'react';

// Background traffic of ordinary employees, so the console looks like a real
// workday and the jury's attacks stand out against normal work.
const PROFILES = [
  ['demo-key', 'reports.read', 'reports/Q4.pdf', 'Summarize the Q4 report', 'Summarize the Q4 report'],
  ['demo-key', 'customer.read', 'customer/123', 'Look up customer 123 for the support ticket', 'Look up customer 123 for the support ticket'],
  ['demo-key', 'documents.read', 'documents/operating-summary', 'Read the operating summary', 'Read the operating summary'],
  ['support-demo-key', 'customer.read', 'customer/456', 'Check the status of customer 456', 'Check the status of customer 456'],
  ['support-demo-key', 'email.send', 'mail/outbox', 'Send the approved shipping update to the customer', 'Reply to the customer about the shipping update'],
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
      const sid = sessions.current[key + intent] ||= `gen-${started}-${Object.keys(sessions.current).length}`;
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
  ['allow', 'Zwykłe zadanie przechodzi', 'Plac testowy → „Zwykłe zadanie”.'],
  ['injection', 'Atak na instrukcje zablokowany', 'Własny prompt, np. „Ignore previous instructions…”, lub scenariusz „Jailbreak”.'],
  ['pii', 'Dane osobowe zredagowane', 'Scenariusz „Dane osobowe” albo własny PESEL / e-mail / IBAN.'],
  ['signature', 'Sygnatura z threat feed', 'Dopisz wzorzec do policies/threat-feed.yaml i wyślij pasujący tekst.'],
  ['reload', 'Zmiana polityki bez restartu', 'Zmień np. mode: strict → permissive w policies/policy.yaml.'],
  ['ghost', 'Atak przechwycony w Ghost Shell', 'Ghost Shell → „Odtwórz scenariusz ataku”.'],
  ['approval', 'Zgoda drugiej osoby', 'Jako Admin: usuń klienta; jako SecOps: zatwierdź.'],
  ['export', 'Eksport dziennika', 'Zdarzenia → Eksport CSV/JSON (rola SecOps).'],
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
  return <aside className="jury" aria-label="Scenariusz dla jury">
    <header><div><span className="eyebrow">TRYB DEMO</span><h2>Scenariusz dla jury</h2><span className="muted small">{done} z {STEPS.length} kroków · odhacza się samo</span></div><button className="icon-btn" onClick={onClose} aria-label="Zamknij">×</button></header>
    <ol>{STEPS.map(([id, title, hint]) => <li key={id} className={progress[id] ? 'done' : ''}><span>{progress[id] ? '✓' : '○'}</span><div><strong>{title}</strong><small>{hint}</small></div></li>)}</ol>
    <p className="muted small">Zestaw testów: <code>make test</code> (Go, Python, end-to-end).</p>
  </aside>;
}
