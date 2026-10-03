# MASQE — zero-trust runtime security gateway for Agentic AI

> **AI decides what it wants to do. MASQE decides what it is allowed to do.**

MASQE intercepts actions between users/agents and LLMs, APIs, databases,
tools, memory and documents. The agent proposes an action; MASQE makes the
final policy decision, runs the protected operation only when permitted, and
inspects the result before it reaches the agent. Decisions: `ALLOW`, `REDACT`,
`GHOST`, `REQUIRE_APPROVAL`, `THROTTLE`, `BLOCK`.

This is an executable hackathon prototype. The demo tools use isolated SQLite
fixtures and a mock outbox; `llm.generate` calls a real local Ollama model.
It is not a production MCP proxy or an OS-level container sandbox.

## Architecture

```text
 User-facing app ──POST /v1/sessions (locks the user's intent)──┐
                                                                 ▼
 Corporate Assistant (agent) ──POST /v1/execute──▶ ┌──────────────────────────────┐
                                                   │ MASQE Go Gateway              │
   1 identity bound to API key                     │  auth · RBAC · resource policy│
   2 user ∩ agent ∩ action ∩ resource permissions  │  budgets · runaway limits     │
   3 deterministic guards (PII, secrets, threats)  │  threat feed (hot reload)     │
   4 semantic guard (only when needed) ──scores──▶ │  risk engine → DECISION       │
   5 risk tiers → ALLOW/REDACT/GHOST/APPROVAL/BLOCK│  execution + OUTPUT GUARD     │
   6 tool runs with redacted input                 └──┬──────────┬─────────┬───────┘
   7 output guard: secrets, PII, signatures,          │ scores   │ audit   │ allowed
     indirect prompt injection                        ▼          ▼         ▼ actions only
                                         ┌────────────────┐ ┌────────┐ ┌──────────────────┐
                                         │ Python AI Guard │ │ SQLite │ │ tools / DB / mail│
                                         │ ML + patterns + │ │ audit, │ │ memory / Ollama  │
                                         │ Intent Lock;    │ │ budget │ └──────────────────┘
                                         │ async Gemma XAI │ └───┬────┘
                                         └────────────────┘     ▼
 policy.yaml + threat-feed.yaml (+ optional remote feed)   React dashboard
          └──────── hot reload, last valid snapshot kept ────────▶ (management + security)
```

Go is the only component that returns a security decision. Python returns
bounded scores. If the semantic service is unavailable, requests that need
semantic analysis **fail closed**; short low-risk requests keep the
deterministic fast path (no AI call, < 1 ms).

Plain-language explanations (local Ollama/Gemma, Polish) are generated
**asynchronously after** the verdict, so decision latency never includes LLM
time. The dashboard polls `/v1/events/{id}` and shows the explanation when
ready; it never labels a canned text as AI, and the engine's technical reasons
stay visible as the authoritative record.

## Run locally

Requirements: Go 1.23+, Python 3.10+, Node 20+, a C compiler (SQLite).
Ollama with `gemma3:4b` is only needed for the autonomous agent, real
`llm.generate` and AI explanations.

```bash
make setup        # .venv with scikit-learn, dashboard build, Go modules
make reset-data   # optional: start with an empty audit log
make run          # AI Guard on :8090, gateway + dashboard on http://127.0.0.1:8080
```

The gateway listens on loopback by default because the sample API keys are
public. Docker (`docker compose up --build`) binds it explicitly.

Demo keys (`policies/policy.yaml`, replace before any real use):
`demo-key` alice/analyst · `viewer-demo-key` · `support-demo-key` ·
`developer-demo-key` · `admin-demo-key` (approver) · `secops-demo-key`
(security role: full audit, export, approver).

```bash
python3 demo-agent/agent.py --action reports.read "Podsumuj raport Q4"
python3 demo-agent/agent.py --autonomous "Summarize the Q4 report"
python3 demo-agent/agent.py --action customer.delete --key admin-demo-key \
  --resource customer/123 --intent "Delete demo customer 123" "Delete demo customer 123"
```

## One-command test suite

```bash
make test         # Go + Python + demo agent + end-to-end, one PASS/FAIL line per test
make test-unit    # without the end-to-end stack
```

106 tests, no network or paid API. The end-to-end suite builds the gateway,
starts the real AI Guard and drives the jury flows over HTTP: allowed and
blocked execution, PII redaction, secrets, ad-hoc jailbreaks (DAN, fake CISO,
leetspeak, Polish slang), Intent Lock, indirect injection in a document, Ghost
Session, two-person approval, hot reload of permissions and threat feed,
invalid edits, reporting, gateway-overhead budget, and fail-closed behaviour
when the AI Guard dies. Regression tests cover every bypass found in the
security review (see below).

## Live jury flow

1. **Przegląd**: posture score with its components, decisions over the last 30
   minutes, triggered controls and signatures, budgets per scope
   (OK/WARN/THROTTLE/EXCEEDED), gateway p50/p95 latency.
2. **Test ochrony**: seven scenarios (normal, PII, exfiltration, untrusted repo,
   poisoned document, jailbreak, pasted key) or any custom prompt.
3. As `admin-demo-key` request `customer.delete`; approve once as
   `secops-demo-key`. Self-approval and replay are rejected.
4. Edit `policies/policy.yaml`: `mode: strict` → `permissive`, add
   `threshold: 0.5` to a control, set `enabled: false`, change a role. The next
   request follows the new policy. A broken edit is rejected with a red banner,
   and the previous policy keeps serving.
5. Append a signature to `policies/threat-feed.yaml` and send matching text.
6. **Zdarzenia**: filter, expand, export CSV/JSON (security role).

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | public liveness, config hash, `config_error`, `semantic_degraded` |
| `POST /v1/sessions` | register the user's intent; returns a gateway-issued `session_id` |
| `POST /v1/execute` | enforced action, guarded output |
| `POST /v1/evaluate` | dry-run verdict (no step counted, no approval opened) |
| `GET /v1/approvals`, `POST /v1/approvals/{id}/approve` | two-person approval |
| `GET /v1/telemetry` | management + performance metrics |
| `GET /v1/audit`, `GET /v1/events/{id}` | security events (own or all, by role) |
| `GET /v1/audit/export.csv`, `.json` | exportable audit (`audit.export`) |
| `GET /v1/policy` | effective policy, threat feed, config error |

Everything except `/health` requires an API key; reporting endpoints also need
the role's `console` permission.

## Central policy

`policies/policy.yaml` is the single, fully commented source for keys, roles
(agent permissions and console access), agents, models and providers,
strictness profiles, guardrail actions and thresholds, budgets and budget
alert bands, per-user/agent/model limits, resource rules, sessions, Ghost
Session, and the optional remote threat feed. Effective authority is
**user ∩ agent ∩ action ∩ resource policy**: an agent never has more authority
than the user who runs it.

* Thresholds come from the active `strictness_modes` profile; an explicit
  `threshold` on a control overrides only that control.
* `enabled: false` removes a control and its share of the aggregate risk.
* Every value is validated (actions, 0–1 ranges, risk ordering, roles, agents,
  local model URLs, regexes). An invalid edit never fails open.

## Controls

| Layer | Controls |
| --- | --- |
| Deterministic | API-key identity, RBAC, agent permissions, resource policy, model allowlist, budgets (tokens, cost, rate, steps, tool calls, runtime, session rotation), PII (PESEL, NIP, ID card, IBAN, card, e-mail, phone; checksums), secrets (API keys, JWT, AWS/GitHub/Slack/Google tokens, private keys, passwords, connection strings, base64-hidden), 26 historical-exploit signatures, Unicode canonicalisation (zero-width, full-width, homoglyphs) |
| Semantic | prompt injection and data exfiltration (local ML classifier + EN/PL patterns, chunked against dilution, leetspeak decoding), concept-based cross-lingual **Intent Lock**, **Privilege Drift** (per session and across sessions), memory poisoning, indirect injection in tool output |
| Adaptive | risk tiers → **Ghost Session** (read-only allowlist) → human approval → block |

## Threat-model alignment (OWASP Agentic AI)

| Threat | MASQE control |
| --- | --- |
| Goal hijacking / indirect injection | Semantic Guard, Intent Lock with registered sessions, output guard |
| Tool misuse / excessive agency | user ∩ agent ∩ resource permissions, Ghost Session, approvals |
| Identity and privilege abuse | key-bound identity, no client-granted permissions, cross-session Privilege Drift |
| Sensitive information disclosure | input and output redaction, secret blocking, CSV-safe export |
| Memory poisoning | `memory.write` permission + memory-poisoning detector + output guard on `memory.read` |
| Unexpected code execution / supply chain | hot-reloaded and remote signature feed (pickle, torch.load, trust_remote_code, Log4Shell, ShadowRay, SSRF, …) |
| Unbounded consumption / runaway agents | per-scope budgets with WARN/THROTTLE bands, steps, tool calls, runtime, session-rotation limit |
| Cascading failures | fail-closed semantic layer, last-valid-policy snapshot, bounded async explainer |

The table is a control mapping, not a claim of certification.

## Security review fixes

A red-team pass found and fixed: session-id rotation resetting runaway and
drift limits; raw PII reaching tools when a decision escalated above REDACT;
typos in policy actions silently disabling controls; viewers draining shared
budgets with denied or forged-usage requests; injection paraphrases skipping
the semantic layer; lexical Intent Lock (bypass by stuffing the goal's words,
false blocks across languages); missing detectors (AWS/GitHub keys, private
keys, `wget|sh`, `os.system`, unsafe YAML/joblib, base64, zero-width
characters); CSV formula injection; audit readable by every role; LLM
explanation time counted as gateway latency; broken YAML taking the gateway
offline; `max_steps` above 21 never firing; thresholds in `security:` ignored;
disabled controls still blocking; threat-feed `action` ignored. Each has a
regression test in `gateway/security_test.go`, `ai-guard/test_server.py` or
`tests/e2e_test.py`.

## Privacy and model note

Audit records exclude prompt content and detected values; personal data in
resource names is masked. They store actor, action, resource, decision,
reasons, triggered controls, policy version, scores, usage and latency.

The semantic classifier is a small offline model (TF-IDF + logistic
regression) trained at start-up from English and Polish examples, combined
with explicit patterns. It is a demonstrator, not a benchmarked production
detector. `redaction.use_model` is reserved: the supplied Polish NER checkpoint
has no weights, and validation rejects enabling it.
