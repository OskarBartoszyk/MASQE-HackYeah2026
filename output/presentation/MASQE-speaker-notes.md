# MASQE: five-minute pitch

Nine slides. Planned duration: 4 minutes 35 seconds, leaving 25 seconds for transitions.

## 1. MASQE (0:00–0:15)

MASQE is an AI control layer for agents that can access data and use tools. It checks what an agent wants to do, applies the organisation’s policy, and records the outcome so people can understand and review it.

## 2. The risk (0:15–0:40)

Consider a normal request: review this repository. The repository contains a README, and that README can contain instructions written by someone else. If the agent treats those instructions as authority, a code review can become an attempt to read credentials or send data outside the organisation. MASQE puts a policy decision between the agent’s request and the action.

## 3. Architecture (0:40–1:15)

Applications connect through an API, a Python SDK or an MCP wrapper. The Go gateway owns the final decision. It checks identity, permissions, policy and budgets, and asks the Python AI Guard for semantic risk scores when needed. Approved requests reach tools or models, and the gateway checks their output before returning it. Untrusted shell work goes to Ghost Shell. Policy and threat feeds remain separate from application code.

## 4. Hybrid controls (1:15–1:45)

The controls combine explicit rules with local semantic detection. Rules handle facts such as permissions, secrets and budget limits. The AI Guard adds signals for instruction override, task drift and malicious content in memory. The gateway can allow, redact, isolate, request approval, throttle or block. This gives us more than a single yes-or-no filter. Optional Polish PII detection uses the existing local model and needs Polish-language validation.

## 5. Live configuration (1:45–2:15)

The jury can change policy and threat feeds while the services are running. That includes permissions, allowed models and risk thresholds. Resource controls cover tokens, estimated cost, request rates, tool calls and runtime. Changes affect subsequent decisions, and invalid configuration keeps the last valid snapshot active. The console exposes the policy version and consumption, so the result of a configuration change can be observed rather than simply claimed.

## 6. Ghost Shell (2:15–3:05)

Ghost Shell is the main demonstration. An agent reads a repository whose README contains a malicious setup instruction. It appears to download and run an installer, but our deterministic Python emulator only returns a simulated result. The agent then reads a fake environment file containing marked credentials called honeytokens. When it tries to upload that file, MASQE detects the markers and records a confirmed exfiltration attempt. No command runs on the host and no outbound network request is sent. The recorder links commands and responses with hashes, which lets us verify the chain. This is an analysis environment. Legitimate commands are simulated too, so it does not replace a real CI system.

## 7. Operations console (3:05–3:40)

The operations console serves both security and management. Security teams can move from an incident to the triggering controls and the event trail. Management can see resource use, budget status and latency, and export reports. An optional local language model adds plain-language explanations after the verdict, without deciding whether the action is allowed. That explainer currently answers in Polish. If its model is unavailable, MASQE reports that honestly instead of presenting a fabricated explanation.

## 8. Test evidence (3:40–4:10)

The verified full run passed 159 automated tests. The suite includes positive cases that must remain usable and negative cases that must trigger controls. End-to-end tests start the real Go and Python services and exercise HTTP requests, live configuration changes, integrations and failure behaviour. For evaluation, the jury can enter a new prompt, change a rule, and inspect the decision and telemetry. This is functional evidence, not a claim that every possible attack is detected.

## 9. Closing (4:10–4:35)

MASQE already combines a working local gateway, several integration paths, live policy and resource controls, and a console for reviewing decisions. Ghost Shell adds a safe way to observe an agent’s attack sequence. The prototype runs without a paid API. The next work is broader adversarial evaluation and production hardening, including live-model validation. The repository contains setup instructions and the test commands. We are ready to demonstrate the system and let the jury challenge it.

## Submission reminder

The competition rules require the team name and team-member list. Add the confirmed details to the title slide before submission. Do not assume that the repository owner represents the complete team.

## Demonstration boundaries

Ghost Shell emulates commands and network activity. The optional explainer currently responds in Polish. The automated suite does not establish live model accuracy or production readiness.
