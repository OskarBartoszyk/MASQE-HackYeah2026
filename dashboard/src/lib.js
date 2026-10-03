// Shared API client, live stream, formatting and Polish labels.

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

export const number = n => Number(n || 0).toLocaleString('pl-PL');
export const percent = n => `${Math.round(Number(n || 0) * 100)}%`;
export const msf = n => `${Number(n || 0) < 10 ? Number(n || 0).toFixed(2) : Number(n || 0).toFixed(1)} ms`;
export const usd = n => `$${Number(n || 0).toFixed(Number(n || 0) < 1 ? 4 : 2)}`;
export const clock = d => d ? new Date(d).toLocaleTimeString('pl-PL', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
export const dateTime = d => d ? new Date(d).toLocaleString('pl-PL', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
export function ago(d, now = Date.now()) {
  const s = Math.max(0, Math.round((now - new Date(d).getTime()) / 1000));
  if (s < 60) return `${s} s temu`;
  if (s < 3600) return `${Math.floor(s / 60)} min temu`;
  if (s < 86400) return `${Math.floor(s / 3600)} h temu`;
  return `${Math.floor(s / 86400)} d temu`;
}

export const RANGES = [['15m', '15 min'], ['1h', '1 h'], ['24h', '24 h'], ['7d', '7 dni']];
export const rangeMs = { '15m': 9e5, '1h': 36e5, '24h': 864e5, '7d': 6048e5 };

export const DECISION = {
  ALLOW: ['Dozwolone', 'allow'], REDACT: ['Zredagowane', 'redact'], GHOST: ['Izolowane', 'ghost'],
  REQUIRE_APPROVAL: ['Wymaga zgody', 'approval'], BLOCK: ['Zablokowane', 'block'], THROTTLE: ['Spowolnione', 'block'],
};
export const EXECUTION = { EXECUTED: 'Wykonano', EVALUATED: 'Oceniono', PENDING_APPROVAL: 'Czeka na zgodę', VERDICT_ONLY: 'Tylko ocena', EXECUTED_OUTPUT_BLOCKED: 'Wynik wstrzymany', NOT_EXECUTED: 'Nie wykonano', REJECTED: 'Odrzucono', AUTHORIZED_EXTERNAL: 'Autoryzowano (SDK)', BLOCK: 'Nie wykonano', THROTTLE: 'Nie wykonano' };
export const ACTION = {
  'reports.read': 'Odczyt raportu', 'documents.read': 'Odczyt dokumentu', 'customer.read': 'Odczyt klienta', 'customer.update': 'Zmiana klienta',
  'customer.delete': 'Usunięcie klienta', 'customer.export': 'Eksport klientów', 'repository.analyze': 'Analiza repozytorium', 'database.query': 'Zapytanie do bazy',
  'database.export': 'Eksport bazy', 'api.external.call': 'Zewnętrzne API', 'email.send': 'Wysłanie e-maila', 'memory.read': 'Odczyt pamięci',
  'memory.write': 'Zapis pamięci', 'llm.generate': 'Model językowy', 'shell.exec': 'Terminal (Ghost Shell)',
};
export const CONTROL = {
  permission: 'Brak uprawnień', model: 'Niedozwolony model', resource: 'Polityka zasobu', session: 'Sesja', runaway: 'Zapętlony agent',
  budget: 'Budżet / limit', pii: 'Dane osobowe', secrets: 'Sekrety', threat_signature: 'Sygnatura ataku', canary: 'Honeytoken',
  prompt_injection: 'Zmiana instrukcji', data_exfiltration: 'Wyciek danych', intent_lock: 'Zgodność z celem', privilege_drift: 'Eskalacja uprawnień',
  memory_poisoning: 'Zatruwanie pamięci', output_injection: 'Pośredni atak', risk: 'Krytyczne ryzyko', approval: 'Wymagana zgoda',
  ghost: 'Ghost Session', ghost_shell: 'Ghost Shell',
};
export const controlLabel = c => c?.startsWith('threat:') ? `Sygnatura ${c.slice(7)}` : (CONTROL[c] || c);
export const CHECK = {
  identity: 'Tożsamość', permissions: 'Uprawnienia', 'model allowlist': 'Dozwolone modele', 'resource policy': 'Polityka zasobu', session: 'Sesja',
  'budget & runaway limits': 'Budżet i limity', 'personal data': 'Dane osobowe', secrets: 'Sekrety', 'threat signatures': 'Sygnatury ataków',
  honeytokens: 'Honeytokeny', 'semantic analysis': 'Analiza AI', 'prompt injection': 'Zmiana instrukcji', 'data exfiltration': 'Wyciek danych',
  'intent lock (alignment)': 'Zgodność z celem', 'memory poisoning': 'Zatruwanie pamięci', 'privilege drift': 'Eskalacja uprawnień',
  'risk engine': 'Silnik ryzyka', decision: 'Decyzja',
};
export const INCIDENT = {
  confirmed_exfiltration_attempt: 'Potwierdzona próba wyniesienia danych', canary_used_outside_ghost: 'Honeytoken użyty poza Ghost Shell',
  honeytoken_reuse: 'Honeytoken w żądaniu', threat_signature: 'Dopasowana sygnatura ataku', indirect_prompt_injection: 'Pośredni prompt injection',
  memory_poisoning: 'Próba zatrucia pamięci agenta',
};
export function incidentSummary(i) {
  const source = (i.summary.match(/Correlated source: ([^ ]+?)\.?$/) || [])[1];
  switch (i.type) {
    case 'confirmed_exfiltration_attempt': return `Agent w Ghost Shell wysłał syntetyczne poświadczenia (honeytokeny) na zewnętrzny adres. Nic nie opuściło emulatora.${source ? ` Powiązane źródło: ${source}.` : ''}`;
    case 'canary_used_outside_ghost': return 'Honeytoken z Ghost Shell pojawił się w innym kanale (e-mail, API lub prompt) i został zablokowany — dane z izolowanej sesji próbowano przenieść dalej.';
    case 'honeytoken_reuse': return 'Żądanie zawierało honeytoken z izolowanej sesji. To potwierdzona próba wyniesienia danych; żądanie zablokowano.';
    case 'threat_signature': return 'Żądanie pasowało do sygnatury znanego ataku z threat feed i zostało zatrzymane, zanim dotarło do narzędzia.';
    case 'indirect_prompt_injection': return 'Wynik narzędzia zawierał ukryte polecenie dla agenta (pośredni prompt injection). Wynik został wstrzymany.';
    case 'memory_poisoning': return 'Agent próbował zapisać w pamięci trwałe polecenie osłabiające zasady. Zapis zablokowano.';
    default: return i.summary;
  }
}
export const SEVERITY = { critical: ['Krytyczny', 'block'], high: ['Wysoki', 'approval'], medium: ['Średni', 'redact'], low: ['Niski', 'neutral'] };
export const STATUS = { open: 'Otwarty', acknowledged: 'W toku', resolved: 'Rozwiązany' };
export const GUARDS = {
  pii: ['Dane osobowe', 'PESEL, NIP, IBAN, dowód, karty, e-mail, telefon'], secrets: ['Sekrety', 'Klucze API, tokeny, hasła, klucze prywatne'],
  prompt_injection: ['Zmiana instrukcji', 'Próby obejścia zasad agenta'], data_exfiltration: ['Wyciek danych', 'Nieuprawniony eksport informacji'],
  intent_lock: ['Zgodność z celem', 'Odchylenie od zadania użytkownika'], privilege_drift: ['Eskalacja uprawnień', 'Ryzykowna sekwencja działań'],
  memory_poisoning: ['Zatruwanie pamięci', 'Trwałe polecenia osłabiające zasady'], output_injection: ['Pośredni atak', 'Polecenia ukryte w wynikach narzędzi'],
};

// Demo identities (public sample keys from policies/policy.yaml).
export const DEMO_IDENTITIES = [
  ['secops-demo-key', 'SecOps', 'zespół bezpieczeństwa'], ['admin-demo-key', 'Admin', 'administrator'], ['demo-key', 'Alice', 'analityk'],
  ['support-demo-key', 'Bob', 'wsparcie'], ['developer-demo-key', 'Dev', 'deweloper'], ['viewer-demo-key', 'Vicky', 'podgląd'],
];
