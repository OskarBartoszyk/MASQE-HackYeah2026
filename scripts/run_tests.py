#!/usr/bin/env python3
"""MASQE security test suite runner.

Runs every suite (Go engine/gateway, Python semantic guard, demo agent, and
end-to-end tests against the real running services) and prints one PASS/FAIL
line per test case plus a summary. Exit code is non-zero on any failure.

    python3 scripts/run_tests.py            # everything
    python3 scripts/run_tests.py --unit     # skip end-to-end
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
GREEN, RED, DIM, BOLD, RESET = ("\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m") if sys.stdout.isatty() else ("",) * 5


def go_suite() -> list[tuple[str, str, float, str]]:
    env = dict(os.environ, GOCACHE=str(ROOT / ".cache/go-build"))
    proc = subprocess.run(["go", "test", "-json", "-count=1", "./..."], cwd=ROOT, env=env, capture_output=True, text=True)
    results, output = [], {}
    for line in proc.stdout.splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        test = ev.get("Test")
        if not test:
            continue
        if ev.get("Action") == "output":
            output.setdefault(test, []).append(ev.get("Output", ""))
        if ev.get("Action") in ("pass", "fail", "skip") and "/" not in test:
            results.append((test, ev["Action"].upper(), ev.get("Elapsed", 0.0), "".join(output.get(test, []))))
    if proc.returncode != 0 and not any(r[1] == "FAIL" for r in results):
        results.append(("go build", "FAIL", 0.0, proc.stdout[-2000:] + proc.stderr[-2000:]))
    return results


UNIT_LINE = re.compile(r"^(test\w+) \((?:[\w.]+)\)(?: \.\.\.)? ?(ok|FAIL|ERROR|skipped.*)?$")


def py_suite(directory: str, pattern: str) -> list[tuple[str, str, float, str]]:
    started = time.time()
    proc = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", directory, "-p", pattern, "-v"], cwd=ROOT, capture_output=True, text=True)
    results, pending = [], None
    for line in proc.stderr.splitlines():
        line = line.rstrip()
        m = UNIT_LINE.match(line)
        if m:
            name, status = m.group(1), m.group(2)
            if status:
                results.append((name, status, 0.0, ""))
                pending = None
            else:
                pending = name
            continue
        if pending and line.strip() in ("ok", "FAIL", "ERROR"):
            results.append((pending, line.strip(), 0.0, ""))
            pending = None
    # unittest prints each failure as a block headed "FAIL: name (...)" or "ERROR: name (...)".
    blocks = {}
    for block in proc.stderr.split("=" * 70)[1:]:
        header = block.strip().split("\n", 1)[0]
        m = re.match(r"(?:FAIL|ERROR): (\w+)", header)
        if m:
            blocks[m.group(1)] = block
    normalized = []
    for name, status, _, _ in results:
        status = {"ok": "PASS", "FAIL": "FAIL", "ERROR": "FAIL"}.get(status, "SKIP")
        normalized.append((name, status, 0.0, blocks.get(name, "") if status == "FAIL" else ""))
    if proc.returncode != 0 and not any(r[1] == "FAIL" for r in normalized):
        normalized.append((f"{directory} suite", "FAIL", time.time() - started, proc.stderr[-3000:]))
    return normalized


def main() -> int:
    unit_only = "--unit" in sys.argv
    suites = [
        ("Go gateway: policy engine, guards, budgets, execution, reporting", go_suite),
        ("Python AI Guard: semantic detection, Intent Lock, explanations", lambda: py_suite("ai-guard", "test_*.py")),
        ("Demo agent: autonomous plan → guarded tool → answer", lambda: py_suite("demo-agent", "test_*.py")),
    ]
    if not unit_only:
        suites.append(("End-to-end: real gateway + AI Guard, OpenAI API, SDK, MCP over HTTP", lambda: py_suite("tests", "e2e_test.py")))
    print(f"\n{BOLD}MASQE SECURITY TEST SUITE{RESET}\n")
    passed = failed = 0
    details = []
    for title, run in suites:
        print(f"{BOLD}{title}{RESET}")
        for name, status, elapsed, detail in run():
            colour = GREEN if status == "PASS" else RED if status == "FAIL" else DIM
            timing = f" {DIM}{elapsed:.2f}s{RESET}" if elapsed >= 0.05 else ""
            print(f"  {colour}{status}{RESET} {name}{timing}")
            if status == "PASS":
                passed += 1
            elif status == "FAIL":
                failed += 1
                details.append((name, detail))
        print()
    for name, detail in details:
        print(f"{RED}--- {name}{RESET}\n{detail.strip()[-2500:]}\n")
    colour = GREEN if failed == 0 else RED
    print(f"{colour}{BOLD}{passed} passed, {failed} failed{RESET}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
