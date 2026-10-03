#!/usr/bin/env python3
"""Small Corporate Assistant client used in the live demo."""
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request


TOOLS = {
    "reports.read": "reports/Q4.pdf",
    "documents.read": "documents/operating-summary",
    "customer.read": "customer/123",
    "repository.analyze": "untrusted/example-repo",
    "database.query": "database/customers",
}


def execute(url: str, key: str, session: str, model: str, intent: str,
            action: str, resource: str, prompt: str) -> dict:
    payload = {
        "session_id": session,
        "agent": {"id": "corporate-agent", "model": model},
        "action": action,
        "resource": resource,
        "prompt": prompt,
        "original_intent": intent,
    }
    request = urllib.request.Request(
        url.rstrip("/") + "/v1/execute",
        json.dumps(payload, ensure_ascii=False).encode(),
        {"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
    )
    with urllib.request.urlopen(request, timeout=65) as response:
        return json.loads(response.read())


def open_session(url: str, key: str, intent: str) -> str:
    """Register the user's goal before the agent acts (Intent Lock).

    The gateway issues the session id and keeps the intent; later requests
    from the agent cannot rewrite it.
    """
    request = urllib.request.Request(
        url.rstrip("/") + "/v1/sessions",
        json.dumps({"agent": "corporate-agent", "intent": intent}, ensure_ascii=False).encode(),
        {"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())["session_id"]


def autonomous(url: str, key: str, session: str, model: str, task: str) -> None:
    if model == "demo-local":
        model = "gemma3:4b"
    planner = (
        "You are the local Corporate Assistant. Choose one tool for the user's task. "
        "Return only JSON with fields action and resource. Available actions and "
        "example resources: " + json.dumps(TOOLS) + ". "
        "Use only one listed action. User task: " + task
    )
    planning = execute(url, key, session, model, task, "llm.generate", "model/" + model, planner)
    print("PLAN / MASQE:", planning["evaluation"]["decision"])
    if not planning.get("executed"):
        print(json.dumps(planning, ensure_ascii=False, indent=2))
        return
    try:
        raw = planning["result"]
        chosen = json.loads(raw[raw.index("{"):raw.rindex("}") + 1])
        action = str(chosen["action"])
        resource = str(chosen["resource"])
    except (ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"Local model returned no usable action: {exc}")
    if action not in TOOLS:
        raise SystemExit(f"Local model proposed an unregistered action: {action}")
    # The model may propose a resource, but the gateway remains the authority
    # for permissions, risk, redaction and whether a tool is actually invoked.
    tool = execute(url, key, session, model, task, action, resource, task)
    print("TOOL / MASQE:", json.dumps(tool, ensure_ascii=False, indent=2))
    if not tool.get("executed"):
        return
    answer_prompt = (
        "Answer the user's task in one or two sentences using only this tool "
        "result. User task: " + task + "\nTool result: " + tool.get("result", "")
    )
    answer = execute(url, key, session, model, task, "llm.generate", "model/" + model, answer_prompt)
    print("ANSWER / MASQE:", json.dumps(answer, ensure_ascii=False, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="MASQE Corporate Assistant demo")
    parser.add_argument("prompt", nargs="?", default="Summarize the Q4 report")
    parser.add_argument("--action", default="reports.read")
    parser.add_argument("--resource", default="reports/Q4.pdf")
    parser.add_argument("--key", default=os.getenv("MASQE_API_KEY", "demo-key"), help="Credential bound to a user and role in policy.yaml")
    parser.add_argument("--model", default="demo-local")
    parser.add_argument("--session", default="")
    parser.add_argument("--intent", default="Summarize the Q4 report")
    parser.add_argument("--autonomous", action="store_true", help="Local model plans, invokes one guarded tool, then answers through MASQE")
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    try:
        intent = args.prompt if args.autonomous else args.intent
        session = args.session or open_session(args.url, args.key, intent)
        if args.autonomous:
            autonomous(args.url, args.key, session, args.model, args.prompt)
        else:
            result = execute(args.url, args.key, session, args.model, args.intent,
                             args.action, args.resource, args.prompt)
            print(json.dumps(result, ensure_ascii=False, indent=2))
    except urllib.error.HTTPError as exc:
        print(exc.read().decode())
        raise SystemExit(1)


if __name__ == "__main__":
    main()
