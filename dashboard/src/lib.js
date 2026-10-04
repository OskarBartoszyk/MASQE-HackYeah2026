// Shared API client, live stream, formatting and UI labels.

export async function api(path, key, options = {}) {
  const response = await fetch(path, { ...options, headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', ...(options.headers || {}) } });
  let data = {};
  try { data = await response.json(); } catch { /* empty body */ }
  if (!response.ok) throw new Error(data.error?.message || data.error || response.statusText);
  return data;
}

// Server-Sent Events over fetch(), so the API key stays in a header.
export function openStream(key, onEvent, onStatus) {
  let stopped = false, controller = null, retry = 1000;
  async function connect() {
    while (!stopped) {
      controller = new AbortController();
      onStatus('connecting');
      try {
        const response = await fetch('/v1/stream', { headers: { Authorization: `Bearer ${key}` }, signal: controller.signal });
        if (!response.ok || !response.body) throw new Error(`HTTP ${response.status}`);
        onStatus('live'); retry = 1000;
        const reader = response.body.getReader(), decoder = new TextDecoder();
        let buffer = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let cut;
          while ((cut = buffer.indexOf('\n\n')) >= 0) {
            const block = buffer.slice(0, cut); buffer = buffer.slice(cut + 2);
            const data = block.split('\n').filter(l => l.startsWith('data: ')).map(l => l.slice(6)).join('\n');
            if (data) { try { onEvent(JSON.parse(data)); } catch { /* ignore malformed */ } }
          }
        }
      } catch (error) { if (stopped) return; }
      if (stopped) return;
      onStatus('offline');
      await new Promise(r => setTimeout(r, retry)); retry = Math.min(retry * 2, 15000);
    }
  }
  connect();
  return () => { stopped = true; controller?.abort(); };
}

export const storage = {
  get(k, fallback) { try { const v = localStorage.getItem(k); return v === null ? fallback : JSON.parse(v); } catch { return fallback; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ } },
};

export const number = n => Number(n || 0).toLocaleString('en-GB');
export const percent = n => `${Math.round(Number(n || 0) * 100)}%`;
export const msf = n => `${Number(n || 0) < 10 ? Number(n || 0).toFixed(2) : Number(n || 0).toFixed(1)} ms`;
export const usd = n => `$${Number(n || 0).toFixed(Number(n || 0) < 1 ? 4 : 2)}`;
export const clock = d => d ? new Date(d).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
export const dateTime = d => d ? new Date(d).toLocaleString('en-GB', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
export function ago(d, now = Date.now()) {
  const s = Math.max(0, Math.round((now - new Date(d).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export const RANGES = [['15m', '15 min'], ['1h', '1 h'], ['24h', '24 h'], ['7d', '7 days']];
export const rangeMs = { '15m': 9e5, '1h': 36e5, '24h': 864e5, '7d': 6048e5 };

export const DECISION = {
  ALLOW: ['Allowed', 'allow'], REDACT: ['Redacted', 'redact'], GHOST: ['Isolated', 'ghost'],
  REQUIRE_APPROVAL: ['Needs approval', 'approval'], BLOCK: ['Blocked', 'block'], THROTTLE: ['Throttled', 'block'],
};
export const EXECUTION = { EXECUTED: 'Executed', EVALUATED: 'Evaluated', PENDING_APPROVAL: 'Awaiting approval', VERDICT_ONLY: 'Verdict only', EXECUTED_OUTPUT_BLOCKED: 'Output withheld', NOT_EXECUTED: 'Not executed', REJECTED: 'Rejected', AUTHORIZED_EXTERNAL: 'Authorized (SDK)', BLOCK: 'Not executed', THROTTLE: 'Not executed' };
EXECUTION.RUNNING = 'Running';

export const ACTION = {
  'reports.read': 'Read report', 'documents.read': 'Read document', 'customer.read': 'Read customer', 'customer.update': 'Update customer',
  'customer.delete': 'Delete customer', 'customer.export': 'Export customers', 'repository.analyze': 'Analyze repository', 'database.query': 'Database query',
  'database.export': 'Export database', 'api.external.call': 'External API', 'email.send': 'Send e-mail', 'memory.read': 'Read memory',
  'memory.write': 'Write memory', 'llm.generate': 'Language model', 'shell.exec': 'Terminal (Ghost Shell)',
};
export const CONTROL = {
  permission: 'Missing permission', model: 'Model not allowed', resource: 'Resource policy', session: 'Session', runaway: 'Runaway agent',
  budget: 'Budget / limit', pii: 'Personal data', secrets: 'Secrets', threat_signature: 'Attack signature', canary: 'Honeytoken',
  prompt_injection: 'Prompt injection', data_exfiltration: 'Data exfiltration', intent_lock: 'Intent Lock', privilege_drift: 'Privilege drift',
  memory_poisoning: 'Memory poisoning', output_injection: 'Indirect injection', risk: 'Critical risk', approval: 'Approval required',
  ghost: 'Ghost Session', ghost_shell: 'Ghost Shell',
};
export const controlLabel = c => c?.startsWith('threat:') ? `Signature ${c.slice(7)}` : (CONTROL[c] || c);
export const CHECK = {
  identity: 'Identity', permissions: 'Permissions', 'model allowlist': 'Model allowlist', 'resource policy': 'Resource policy', session: 'Session',
  'budget & runaway limits': 'Budget & limits', 'personal data': 'Personal data', secrets: 'Secrets', 'threat signatures': 'Attack signatures',
  honeytokens: 'Honeytokens', 'semantic analysis': 'AI analysis', 'prompt injection': 'Prompt injection', 'data exfiltration': 'Data exfiltration',
  'intent lock (alignment)': 'Intent Lock (alignment)', 'memory poisoning': 'Memory poisoning', 'privilege drift': 'Privilege drift',
  'risk engine': 'Risk engine', decision: 'Decision',
};
export const INCIDENT = {
  confirmed_exfiltration_attempt: 'Confirmed data exfiltration attempt', canary_used_outside_ghost: 'Honeytoken used outside Ghost Shell',
  honeytoken_reuse: 'Honeytoken in a request', threat_signature: 'Attack signature matched', indirect_prompt_injection: 'Indirect prompt injection',
  memory_poisoning: 'Agent memory poisoning attempt',
};
export function incidentSummary(i) {
  const source = (i.summary.match(/Correlated source: ([^ ]+?)\.?$/) || [])[1];
  switch (i.type) {
    case 'confirmed_exfiltration_attempt': return `An agent in Ghost Shell sent synthetic credentials (honeytokens) to an outbound destination. Nothing left the emulator.${source ? ` Correlated source: ${source}.` : ''}`;
    case 'canary_used_outside_ghost': return 'A honeytoken from Ghost Shell appeared in another channel (e-mail, API or prompt) and was blocked: data from an isolated session was being moved on.';
    case 'honeytoken_reuse': return 'The request contained a honeytoken from an isolated session. This is a confirmed exfiltration attempt; the request was blocked.';
    case 'threat_signature': return 'The request matched a known attack signature from the threat feed and was stopped before it reached the tool.';
    case 'indirect_prompt_injection': return 'A tool result contained a hidden instruction for the agent (indirect prompt injection). The result was withheld.';
    case 'memory_poisoning': return 'The agent tried to store a persistent instruction that weakens the rules. The write was blocked.';
    default: return i.summary;
  }
}
export const SEVERITY = { critical: ['Critical', 'block'], high: ['High', 'approval'], medium: ['Medium', 'redact'], low: ['Low', 'neutral'] };
export const STATUS = { open: 'Open', acknowledged: 'In progress', resolved: 'Resolved' };
export const GUARDS = {
  pii: ['Personal data', 'Names, PESEL, NIP, IBAN, ID cards, cards, e-mail, phone'], secrets: ['Secrets', 'API keys, tokens, passwords, private keys'],
  prompt_injection: ['Prompt injection', 'Attempts to override the agent\'s rules'], data_exfiltration: ['Data exfiltration', 'Unauthorized export of information'],
  intent_lock: ['Intent Lock', 'Deviation from the user\'s goal'], privilege_drift: ['Privilege drift', 'Risky sequences of actions'],
  memory_poisoning: ['Memory poisoning', 'Persistent instructions that weaken the rules'], output_injection: ['Indirect injection', 'Instructions hidden in tool results'],
};

// Demo identities (public sample keys from policies/policy.yaml).
export const DEMO_IDENTITIES = [
  ['secops-demo-key', 'SecOps', 'security team'], ['admin-demo-key', 'Admin', 'administrator'], ['demo-key', 'Alice', 'analyst'],
  ['support-demo-key', 'Bob', 'support'], ['developer-demo-key', 'Dev', 'developer'], ['viewer-demo-key', 'Vicky', 'viewer'],
];
