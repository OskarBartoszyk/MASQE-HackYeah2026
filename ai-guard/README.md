# Python AI Guard

The Go gateway owns policy enforcement and the final security decision. This
service provides semantic risk scores, optional Polish personal-data detection,
plain-language explanations, and the isolated Ghost Shell emulator. It does not
authorize tools or execute host commands.

## Semantic analysis

`POST /analyze` returns bounded scores from a locally trained character-ngram
TF-IDF/logistic-regression classifier, combined with explicit English and
Polish patterns. The gateway uses these scores as one input to its risk engine.
Short, low-risk requests can use the deterministic fast path; if semantic
analysis is required but the service is unavailable, the gateway fails closed.

## Personal-data detection

`POST /redact` uses the fine-tuned Polish HerBERT model (PLVeil) when the
optional dependencies and model weights are available. The model loads in the
background at start-up; returned spans use UTF-8 byte offsets so the Go gateway
can safely redact the original text. Deterministic, checksum-aware rules remain
active as well. If the model is missing, loading, or fails, the configured
`redaction.on_model_failure` policy chooses between rule-only fallback and
blocking. The AI Guard reports model readiness through `/health`.

`make setup` attempts to install the optional dependencies and download model
weights. Docker builds include them by default; set
`MASQE_INSTALL_NER=false` when running `docker compose up --build` to create a
smaller rules-only image. The end-to-end tests explicitly disable model loading
so they run locally without downloading weights.

## Explanations

`POST /explain` asks a local Ollama model (default `gemma3:4b`) to explain an
already-made decision in plain Polish. The gateway sends redacted evidence, not
raw secrets. Explanations are asynchronous and do not alter the verdict or add
to decision latency. A missing model or timeout is reported as unavailable; the
service does not substitute canned text and present it as an AI explanation.
Configure the Ollama endpoint with `MASQE_EXPLAIN_OLLAMA_URL` and the model with
`MASQE_EXPLAIN_MODEL`.

## Ghost Shell

`ghost.py` implements a deterministic virtual filesystem and a deliberately
limited shell for untrusted-repository analysis. It never invokes the host
shell, Python interpreter, package manager, or network. Synthetic honeytokens
make attempted credential access/exfiltration observable; command/output
records use a hash chain. The Go gateway remains responsible for deciding when
to open a session, checking every action, and recording security incidents.

## Run and test

From the repository root, `make run` starts this service with the Go gateway.
For the full project test instructions use `make test`, `make test-unit`, or
`make test-e2e` in the root README. To run only the Python AI Guard tests after
setup:

```bash
.venv/bin/python -m unittest discover -s ai-guard -p 'test_*.py' -v
```
