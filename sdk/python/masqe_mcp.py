#!/usr/bin/env python3
"""MASQE MCP proxy (stdio). Puts MASQE between an MCP client and MCP tools.

Two modes:

* Built-in tools (default): exposes the MASQE demo tools to any MCP client
  (Claude Desktop, IDEs, agent frameworks). Every call runs through
  POST /v1/execute.

      python3 masqe_mcp.py --url http://127.0.0.1:8080 --key demo-key

* Proxy for an existing MCP server: starts the upstream server, forwards
  tools/list, and for each tools/call asks MASQE first (/v1/authorize) and
  inspects the result (/v1/outputs) before it reaches the client. Tools are
  mapped to policy actions; unmapped tools are refused (secure default).

      python3 masqe_mcp.py --key demo-key --map lookup=documents.read \
          -- python3 my_mcp_server.py

Messages are newline-delimited JSON-RPC 2.0 on stdin/stdout (MCP stdio transport).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from masqe_sdk import Masqe, MasqeBlocked, MasqeError  # noqa: E402

PROTOCOL = "2025-06-18"
BUILTIN = {
    "read_report": ("reports.read", "reports/{name}", "Read a business report", {"name": "Report file, e.g. Q4.pdf"}),
    "read_document": ("documents.read", "documents/{name}", "Read a company document", {"name": "Document id, e.g. operating-summary"}),
    "get_customer": ("customer.read", "customer/{id}", "Read one customer record", {"id": "Customer id, e.g. 123"}),
    "delete_customer": ("customer.delete", "customer/{id}", "Delete a customer (needs approval)", {"id": "Customer id"}),
    "query_database": ("database.query", "database/{table}", "Run a read-only database query", {"table": "Table name"}),
    "send_email": ("email.send", "mail/outbox", "Send an e-mail from the mock outbox", {"body": "Message body"}),
    "analyze_repository": ("repository.analyze", "untrusted/{repo}", "Analyse an untrusted repository", {"repo": "Repository name"}),
}


def text_result(text: str, error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": error}


class Upstream:
    """Minimal JSON-RPC client for an upstream stdio MCP server."""

    def __init__(self, command: list[str]):
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        self.lock, self.next_id = threading.Lock(), 0

    def request(self, method: str, params: dict | None = None) -> dict:
        with self.lock:
            self.next_id += 1
            msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}}
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()
            while True:
                line = self.proc.stdout.readline()
                if not line:
                    raise MasqeError("upstream MCP server exited")
                reply = json.loads(line)
                if reply.get("id") == self.next_id:
                    if "error" in reply:
                        raise MasqeError(f"upstream error: {reply['error']}")
                    return reply.get("result", {})

    def notify(self, method: str) -> None:
        with self.lock:
            self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
            self.proc.stdin.flush()


class Proxy:
    def __init__(self, masqe: Masqe, mapping: dict[str, str], upstream: Upstream | None):
        self.masqe, self.mapping, self.upstream = masqe, mapping, upstream

    def handle(self, msg: dict) -> dict | None:
        method, params = msg.get("method"), msg.get("params") or {}
        if "id" not in msg:  # notification
            return None
        try:
            if method == "initialize":
                if self.upstream:
                    self.upstream.request("initialize", params)
                    self.upstream.notify("notifications/initialized")
                if params.get("intent"):
                    self.masqe.open_session(params["intent"])
                result = {"protocolVersion": params.get("protocolVersion", PROTOCOL), "capabilities": {"tools": {}},
                          "serverInfo": {"name": "masqe-mcp-proxy", "version": "1.0"}}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = self.list_tools()
            elif method == "tools/call":
                result = self.call_tool(params.get("name", ""), params.get("arguments") or {})
            else:
                return {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": f"method not found: {method}"}}
        except MasqeError as exc:
            return {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32000, "message": str(exc)}}
        return {"jsonrpc": "2.0", "id": msg["id"], "result": result}

    def list_tools(self) -> dict:
        if self.upstream:
            return self.upstream.request("tools/list")
        return {"tools": [{"name": name, "description": f"{desc} (guarded by MASQE: {action})",
                           "inputSchema": {"type": "object", "properties": {k: {"type": "string", "description": v} for k, v in args.items()}, "required": list(args)}}
                          for name, (action, _, desc, args) in BUILTIN.items()]}

    def call_tool(self, name: str, arguments: dict) -> dict:
        prompt = f"{name}({json.dumps(arguments, ensure_ascii=False)})"
        try:
            if self.upstream:
                action = self.mapping.get(name)
                if not action:
                    return text_result(f"MASQE: tool {name!r} is not mapped to a policy action; refused.", True)
                evaluation = self.masqe.authorize(action, f"mcp/{name}", prompt)
                result = self.upstream.request("tools/call", {"name": name, "arguments": arguments})
                texts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
                return text_result(self.masqe.check_output(evaluation["request_id"], "\n".join(texts)), bool(result.get("isError")))
            if name not in BUILTIN:
                return text_result(f"unknown tool {name}", True)
            action, resource, _, _ = BUILTIN[name]
            values = {k: str(arguments.get(k, "")) for k in BUILTIN[name][3]}
            text = arguments.get("body", prompt) if action == "email.send" else prompt
            return text_result(self.masqe.execute(action, resource.format(**values), text))
        except MasqeBlocked as exc:
            return text_result(f"MASQE {exc.decision}: {'; '.join(exc.reasons)}", True)


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    upstream_cmd = []
    if "--" in argv:
        i = argv.index("--")
        argv, upstream_cmd = argv[:i], argv[i + 1:]
    parser = argparse.ArgumentParser(description="MASQE MCP proxy (stdio)")
    parser.add_argument("--url", default=os.getenv("MASQE_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--key", default=os.getenv("MASQE_API_KEY", "demo-key"))
    parser.add_argument("--agent", default="corporate-agent")
    parser.add_argument("--intent", default=None, help="User goal registered for Intent Lock")
    parser.add_argument("--map", action="append", default=[], help="tool=policy.action for upstream tools")
    args = parser.parse_args(argv)
    masqe = Masqe(args.url, args.key, agent=args.agent)
    if args.intent:
        masqe.open_session(args.intent)
    mapping = dict(item.split("=", 1) for item in args.map)
    proxy = Proxy(masqe, mapping, Upstream(upstream_cmd) if upstream_cmd else None)
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            reply = proxy.handle(msg)
        if reply is not None:
            sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
