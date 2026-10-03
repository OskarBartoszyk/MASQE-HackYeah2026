# MASQE Python SDK and MCP proxy

Standard library only — copy `masqe_sdk.py` into any project.

```python
from masqe_sdk import Masqe, MasqeBlocked

masqe = Masqe("http://127.0.0.1:8080", api_key="demo-key", agent="corporate-agent")
masqe.open_session("Answer the support ticket of customer 123")  # locks the user's goal

# 1. Guard a tool that runs in your own process
@masqe.tool("customer.read", resource="customer/{customer_id}")
def get_customer(customer_id):
    return crm.fetch(customer_id)

try:
    print(get_customer("123"))           # personal data in the result is redacted
except MasqeBlocked as blocked:
    print(blocked.decision, blocked.reasons)

# 2. Run a built-in protected action
masqe.execute("reports.read", "reports/Q4.pdf", "Summarize the Q4 report")

# 3. LLM call through the OpenAI-compatible endpoint
masqe.chat([{"role": "user", "content": "Summarize the Q4 report"}], model="gemma3:4b")
# ...or use any OpenAI SDK: OpenAI(base_url=masqe.openai_base_url, api_key="demo-key")
```

The tool action (`customer.read`) must exist in `policies/policy.yaml`; unknown
actions are blocked. Each `authorize` is single-use and bound to the caller.

## MCP proxy (stdio)

```bash
# Expose MASQE-guarded demo tools to any MCP client
python3 masqe_mcp.py --url http://127.0.0.1:8080 --key demo-key

# Guard an existing MCP server: map its tools to policy actions
python3 masqe_mcp.py --key demo-key --intent "Research the Q4 market" \
    --map web_search=documents.read --map send_mail=email.send \
    -- npx -y @your/mcp-server
```

Unmapped upstream tools are refused. Tool results pass the output guard
(PII/secret redaction, honeytokens, exploit signatures, indirect prompt
injection) before the MCP client sees them.
