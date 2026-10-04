# MASQE: story-led jury pitch

10 slides. Planned delivery: 4 minutes 40 seconds, with 20 seconds for transitions.

## 1. The story (0:00–0:20)

An employee asks an AI agent to review a repository. Hidden inside that repository is an instruction to upload credentials. We built MASQE to control what happens next. I’ll show the attack in our implemented system, then explain how the same controls protect ordinary work.

## 2. The poisoned repository (0:20–0:45)

The user’s goal is harmless: review code quality. The README tells the agent that setup requires a downloaded script, followed by reading and uploading an environment file. This is the trap in our synthetic repository. The agent can encounter malicious instructions while doing exactly what the user asked. We need control at the point where it acts.

## 3. The first intervention (0:45–1:10)

MASQE intervenes before that repository can expose the host. A repository analysis request marked as untrusted receives a GHOST decision. The gateway opens a virtual workspace automatically, and subsequent shell requests use the Python emulator. The agent can inspect files and change directories, but commands never reach a host shell, a package manager or a network socket.

## 4. The decoy environment (1:10–1:40)

Here is our actual Ghost Shell. This screenshot comes from a fixed attack replay, not an autonomous-model success claim. The installer appears to finish. Reading the environment file returns synthetic credentials unique to this session. The emulator keeps responses consistent so we can observe the sequence. Our optional local agent can also choose its own steps, and it may recognise the attack and refuse.

## 5. Evidence and containment (1:40–2:10)

The turning point is the upload. Reading a file alone is only a signal. Finding this session’s marked credentials in an outbound payload confirms an attempted leak. Our panel records two honeytoken hits, while nothing leaves the emulator. The recorder links the commands and responses with hashes. MASQE also blocks those markers if they reappear through another channel, such as an API request. The README attribution is a correlated sequence, not proof of intent.

## 6. Beyond the shell (2:10–2:45)

The same gateway handles ordinary business work. Intent Lock and privilege-drift signals detect when an action departs from the task. Personal-data controls can redact content while secret controls block exposure. Destructive operations require both permission and a second person’s approval. Step, token and cost limits contain runaway agents. Registered user intent can be made mandatory in policy. The important point is that each response addresses a specific risk, while safe work can continue.

## 7. Live governance (2:45–3:10)

Operators can change behaviour without restarting the system. This is a tested example: the same deletion request is blocked before a permission change, then requires approval afterwards. Granting permission does not silently remove the second-person check. The jury can also change risk thresholds or threat feeds and observe subsequent decisions. Invalid edits leave the last valid configuration active.

## 8. The human side (3:10–3:40)

A blocked request is only useful if people can understand it. Our console connects live decisions to incidents and the control trace. Security teams can investigate and export evidence. Management can see usage, cost and latency. A real local language model can explain confirmed decision facts in plain English after enforcement. It does not decide whether to allow the action. Missing model service means an unavailable explanation, never a canned substitute.

## 9. Implementation (3:40–4:10)

This is the implementation behind the story. Existing applications connect through the API, Python SDK or MCP wrapper. The Go gateway enforces policy and owns the verdict. The Python AI Guard supplies local semantic scores, with optional models for PII and explanations. Tool outputs pass through checks on return. Ghost Shell is the Python execution emulator. These integration paths let us apply the same controls without rewriting every agent.

## 10. Why MASQE (4:10–4:40)

Our distinctive combination is controlled observation, evidence from session-specific decoys, and policy the operator can change live. We can show how an attempted attack unfolded while keeping that sequence away from real execution. The verified review passed 159 automated tests, including positive and negative cases. This remains a prototype, with broader adversarial and live-model validation ahead. The code is available, and the jury can challenge the running system with its own prompts and configuration changes.

## Before submission

Add the confirmed team name and member list to the cover. The replay screenshots show synthetic traffic and fixed commands, not autonomous model behaviour. The optional Polish NER model still requires Polish-language evaluation. The test count refers to the verified full review, not a new test run during presentation creation.
