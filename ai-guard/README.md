# AI Guard

The Python service never issues the final security decision. Its `/analyze`
endpoint returns semantic scores from a locally trained character-ngram
TF-IDF/logistic-regression classifier plus deterministic checks. It can
optionally blend those scores with a local Ollama model (`OLLAMA_URL`,
`OLLAMA_MODEL`). If this service is unavailable, the gateway blocks requests
requiring semantic analysis rather than silently allowing them.

The `/explain` endpoint is separate: `explain.py` calls a real local Ollama
model (`MASQE_EXPLAIN_MODEL`, default `gemma3:4b`) to generate a user-facing
Polish explanation of a decision already made by Go. Its input is redacted and
contains decision evidence, not raw secrets. It does not decide or execute
anything. A model timeout returns HTTP 503; it does not fabricate a template
under an AI label. `MASQE_EXPLAIN_OLLAMA_URL` can point to a local Ollama host.

The Polish MASQE NER model supplied in the adjacent project was inspected for
reuse, but that checkout contains tokenizer/configuration files only and no
model weights. Therefore this repository does not claim that the model runs.
Deterministic Polish PESEL/phone/e-mail/card redaction is enabled in the Go
gateway. `redaction.use_model` is a placeholder for a future checkpoint and
does not activate NER inference in the current build.
