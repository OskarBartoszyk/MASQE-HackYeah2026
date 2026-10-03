"""MASQE Python SDK: put any agent tool or LLM call behind the MASQE gateway.

Standard library only. Three integration styles:

1. Guard your own tool functions (they keep running in your process):

       masqe = Masqe("http://127.0.0.1:8080", "demo-key")

       @masqe.tool("customer.read", resource="customer/{customer_id}")
       def get_customer(customer_id):
           return db.fetch(customer_id)

   MASQE authorizes the call first (identity, permissions, budgets, intent,
   injection...) and inspects the result (PII redaction, secrets, honeytokens,
   indirect prompt injection) before your agent sees it.

2. Let MASQE run a built-in protected action:  masqe.execute("reports.read", ...)

3. Any OpenAI-compatible client:  OpenAI(base_url=masqe.openai_base_url, api_key=KEY)
   or masqe.chat([...], model="gemma3:4b").
"""
from __future__ import annotations

import functools
import inspect
import json
import uuid
import urllib.error
import urllib.request
from typing import Any, Callable

__all__ = ["Masqe", "MasqeError", "MasqeBlocked", "MasqeApprovalRequired"]


class MasqeError(Exception):
    """Transport or gateway error."""


class MasqeBlocked(MasqeError):
    """The gateway refused the action or withheld its output."""

    def __init__(self, decision: str, reasons: list[str], request_id: str = "", approval_id: str = ""):
        super().__init__(f"MASQE {decision}: {'; '.join(reasons) or 'blocked by policy'}")
        self.decision, self.reasons, self.request_id, self.approval_id = decision, reasons, request_id, approval_id


class MasqeApprovalRequired(MasqeBlocked):
    """A second person must approve the action before it can run."""


class Masqe:
    def __init__(self, url: str, api_key: str, agent: str = "corporate-agent", model: str = "demo-local",
                 session: str | None = None, intent: str | None = None, timeout: float = 30):
        self.url, self.api_key, self.agent, self.model, self.timeout = url.rstrip("/"), api_key, agent, model, timeout
        # One session per client keeps step counting, Privilege Drift and
        # Intent Lock meaningful (and avoids the session-rotation limit).
        self.session, self.intent = session or "sdk_" + uuid.uuid4().hex, intent

    # -- transport -------------------------------------------------------------
    def _request(self, method: str, path: str, body: Any = None, headers: dict | None = None) -> tuple[int, dict]:
        data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.api_key}")
        req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {"error": e.reason}
        except (urllib.error.URLError, TimeoutError) as e:
            raise MasqeError(f"MASQE gateway unreachable: {e}") from e

    def _call(self, path: str, body: Any) -> dict:
        status, out = self._request("POST", path, body)
        if status >= 400:
            raise MasqeError(f"HTTP {status}: {out.get('error', out)}")
        return out

    def _body(self, action: str, resource: str, prompt: str, metadata: dict | None) -> dict:
        body = {"agent": {"id": self.agent, "model": self.model}, "action": action, "resource": resource, "prompt": prompt}
        if self.session:
            body["session_id"] = self.session
        if self.intent:
            body["original_intent"] = self.intent
        if metadata:
            body["metadata"] = {k: str(v) for k, v in metadata.items()}
        return body

    @staticmethod
    def _raise_for(evaluation: dict) -> None:
        decision = evaluation.get("decision", "BLOCK")
        args = (decision, evaluation.get("reasons", []), evaluation.get("request_id", ""), evaluation.get("approval_id", ""))
        if decision == "REQUIRE_APPROVAL":
            raise MasqeApprovalRequired(*args)
        raise MasqeBlocked(*args)

    # -- sessions --------------------------------------------------------------
    def open_session(self, intent: str) -> str:
        """Register the user's goal (Intent Lock); later calls use this session."""
        out = self._call("/v1/sessions", {"agent": self.agent, "intent": intent})
        self.session, self.intent = out["session_id"], intent
        return self.session

    # -- built-in protected actions ------------------------------------------
    def execute(self, action: str, resource: str = "", prompt: str = "", **metadata) -> str:
        out = self._call("/v1/execute", self._body(action, resource, prompt, metadata))
        if not out.get("executed"):
            self._raise_for(out["evaluation"])
        if out.get("execution_error"):
            raise MasqeBlocked("OUTPUT_BLOCKED", [out["execution_error"]], out["evaluation"].get("request_id", ""))
        return out.get("result", "")

    # -- guarding your own tools ----------------------------------------------
    def authorize(self, action: str, resource: str = "", prompt: str = "", **metadata) -> dict:
        out = self._call("/v1/authorize", self._body(action, resource, prompt, metadata))
        if not out.get("allowed"):
            self._raise_for(out["evaluation"])
        return out["evaluation"]

    def check_output(self, request_id: str, output: str) -> str:
        out = self._call("/v1/outputs", {"request_id": request_id, "output": output})
        if not out.get("allowed"):
            raise MasqeBlocked("OUTPUT_BLOCKED", [out.get("reason", "output withheld")], request_id)
        return out.get("output", "")

    def tool(self, action: str, resource: str | Callable[..., str] = "", prompt: Callable[..., str] | None = None):
        """Decorator: authorize before the call, inspect the result after it.

        resource may be a format string using the function's arguments
        ("customer/{customer_id}") or a callable receiving them. If the guard
        redacts the result, the redacted text is returned instead.
        """
        def decorate(func):
            signature = inspect.signature(func)

            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()
                params = dict(bound.arguments)
                res = resource(**params) if callable(resource) else resource.format(**params)
                text = prompt(**params) if prompt else f"{func.__name__}({json.dumps(params, default=str, ensure_ascii=False)})"
                evaluation = self.authorize(action, res, text)
                result = func(*args, **kwargs)
                raw = result if isinstance(result, str) else json.dumps(result, default=str, ensure_ascii=False)
                guarded = self.check_output(evaluation["request_id"], raw)
                return result if guarded == raw else guarded
            wrapper.masqe_action = action
            return wrapper
        return decorate

    # -- LLM calls -------------------------------------------------------------
    @property
    def openai_base_url(self) -> str:
        """base_url for any OpenAI-compatible SDK; use your MASQE key as api_key."""
        return self.url + "/v1"

    def chat(self, messages: list[dict], model: str | None = None) -> str:
        headers = {"X-MASQE-Agent": self.agent}
        if self.session:
            headers["X-MASQE-Session"] = self.session
        if self.intent:
            headers["X-MASQE-Intent"] = self.intent
        status, out = self._request("POST", "/v1/chat/completions", {"model": model or self.model, "messages": messages}, headers)
        if status == 200:
            return out["choices"][0]["message"]["content"]
        error, masqe = out.get("error", {}), out.get("masqe", {})
        if masqe:
            raise MasqeBlocked(error.get("code", "BLOCK"), [error.get("message", "")], masqe.get("request_id", ""), masqe.get("approval_id", ""))
        raise MasqeError(f"HTTP {status}: {error or out}")
