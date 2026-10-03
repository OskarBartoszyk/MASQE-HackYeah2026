#!/usr/bin/env python3
"""MASQE semantic guard.

The service intentionally returns scores, never an ALLOW/BLOCK decision. Go is
the policy authority. The default offline backend combines a trained local
character-ngram classifier, multilingual attack patterns and a concept-based
Intent Lock. Set OLLAMA_URL and OLLAMA_MODEL to add local-model inference; a
slow or malformed model answer falls back to the offline scores (the model can
only raise risk, never lower it).
"""
from __future__ import annotations

import json
import math
import os
import re
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from model import predict
from explain import explain

# --- Attack vocabulary --------------------------------------------------------
# Exact phrases (kept for explainable signals) ...
INJECTION = {
    "ignore previous instructions": .86,
    "ignore all instructions": .90,
    "reveal the system prompt": .92,
    "developer message": .55,
    "jailbreak": .90,
    "bypass policy": .82,
    "zignoruj poprzednie instrukcje": .90,
    "zignoruj wszystkie instrukcje": .92,
    "ujawnij prompt systemowy": .94,
    "obejdź politykę": .86,
}
EXFILTRATION = {
    "dump all": .82,
    "export all": .76,
    "send externally": .82,
    "all available customer": .88,
    "credentials": .56,
    "secret": .48,
    "wyeksportuj wszystkie": .82,
    "wszystkie dane klientów": .90,
    "wyślij na zewnątrz": .84,
    "dane uwierzytelniające": .64,
}
# ... and patterns that generalise over wording (EN + PL).
INJECTION_PATTERNS = [
    (r"\b(?:ignore|disregard|forget|override|bypass|set aside|put aside|throw away|drop)\b.{0,40}\b(?:previous|prior|earlier|above|preceding|original|system|safety|security)\b.{0,30}\b(?:instructions?|rules|directives|guidelines|guidance|directions|commands|polic(?:y|ies)|prompts?|checks?|orders|task)\b", .90, "override-instructions"),
    (r"\b(?:ignore|disregard|forget)\b.{0,15}\b(?:all|everything|the above)\b", .80, "ignore-all"),
    (r"\byou are (?:now|no longer)\b|\bfrom now on,? you\b", .80, "persona-reset"),
    (r"\b(?:dan|stan)\b.{0,40}\b(?:mode|anything|no (?:rules|restrictions))|\bdo anything now\b|\bdeveloper mode\b|\bjailbr[e3]ak", .92, "jailbreak-persona"),
    (r"\b(?:unrestricted|uncensored|without (?:any )?(?:rules|restrictions|limits|filters))\b", .80, "unrestricted"),
    (r"\b(?:i am|i'm|as)\s+(?:the |your |an? )?(?:ciso|cto|ceo|admin\w*|security team|system owner|owner|root|developer)\b.{0,80}\b(?:authori[sz]e|allow|permit|approve|skip|bypass|override|disable|grant)", .88, "authority-claim"),
    (r"\b(?:i )?authori[sz]e you to\b|\byou (?:have|are given) (?:my )?permission to (?:skip|bypass|ignore)", .84, "fake-authorization"),
    (r"\b(?:skip|bypass|disable|turn off|ignore|circumvent|deactivate)\b.{0,25}\b(?:security|safety|guard\w*|filters?|checks?|polic(?:y|ies)|restrictions|controls?|approval)", .88, "disable-controls"),
    (r"\b(?:grandma|grandmother|granny|babci\w*)\b.{0,100}\b(?:passwords?|keys?|secrets?|credentials?|tokens?|hasł\w*|klucz\w*)", .86, "grandma-roleplay"),
    (r"\btranslat\w*\b.{0,40}\b(?:ignore|disregard|forget)\b", .84, "translation-wrapper"),
    (r"\[\s*system\s*\]|<\s*/?\s*system\s*>|\bnew (?:system )?(?:policy|instructions?)\s*[:—-]|\bimportant (?:note )?for the (?:ai|assistant|agent)\b", .84, "injected-system-message"),
    (r"\b(?:pretend|act|behave|roleplay)\b.{0,30}\b(?:no (?:rules|limits|restrictions)|unrestricted|evil|without (?:rules|filters))", .86, "malicious-roleplay"),
    (r"\b(?:zignoruj|zapomnij|pomiń|pomin|olej|porzuć|odrzuć|nie słuchaj)\b.{0,40}\b(?:instrukcj\w*|polece\w*|zasad\w*|reguł\w*|wcześniej\w*|poprzedni\w*|kazali)", .90, "pl-override-instructions"),
    (r"\b(?:jestem|jako)\b.{0,25}\b(?:administrator\w*|admin\w*|ciso|prezes\w*|szef\w*|właściciel\w*)\b.{0,80}\b(?:zezwalam|pozwalam|autoryzuj\w*|pomiń|wyłącz|zatwierdzam)", .88, "pl-authority-claim"),
    (r"\b(?:wyłącz|wylacz|pomiń|pomin|obejdź|obejdz|dezaktywuj)\b.{0,25}\b(?:zabezpiecze\w*|kontrol\w*|filtr\w*|polityk\w*|ograniczen\w*)", .88, "pl-disable-controls"),
    (r"\bod teraz (?:jesteś|jestes|działasz|dzialasz)\b|\bjesteś teraz\b", .80, "pl-persona-reset"),
]
EXFIL_PATTERNS = [
    (r"\b(?:dump|export|extract|exfiltrate|leak|send|forward|email|upload|transmit|copy|give me|list)\b.{0,40}\b(?:all|every|entire|full|whole|complete)\b.{0,30}\b(?:records?|customers?|clients?|data|database|e-?mails?|contacts?|users?|documents?|files?|secrets?|passwords?|credentials?|payroll)", .86, "bulk-extraction"),
    (r"\b(?:send|forward|email|upload|post|transmit|mail)\b.{0,80}\b(?:to|na|do)\s+\S+@\S+", .74, "send-to-address"),
    (r"\b(?:send|upload|post|transmit|forward)\b.{0,60}\b(?:external|outside|third[- ]party|attacker|personal|private)\b", .82, "send-outside"),
    (r"\b(?:passwords?|credentials?|api keys?|private keys?|access tokens?|\.env\b|ssh keys?)\b", .55, "credential-mention"),
    (r"\b(?:daj|wyślij|wyslij|wyeksportuj|prześlij|przeslij|przekaż|przekaz|pobierz|zrzuć|zrzuc|skopiuj)\b.{0,40}\b(?:wszystk\w*|cał\w*|pełn\w*)\b.{0,30}\b(?:dan\w*|mail\w*|klient\w*|rekord\w*|baz\w*|kontakt\w*|hasł\w*|sekret\w*)", .86, "pl-bulk-extraction"),
    (r"\b(?:hasł\w*|poświadcze\w*|sekret\w*|klucz\w* api|token\w*)\b", .55, "pl-credential-mention"),
]
MEMORY_PATTERNS = [
    (r"\b(?:don'?t|do not|doesn'?t|does not|no longer|never)\s+(?:need|require|ask for|check)\w*\s+(?:any\s+)?(?:authentication|authori[sz]ation|approval|verification|passwords?|mfa|2fa|login)", .92),
    (r"\b(?:from now on|always|in future|od teraz|zawsze|w przyszłości)\b.{0,60}\b(?:ignore|skip|bypass|disable|trust|approve|without|ignoruj|pomijaj|pomiń|wyłącz|ufaj|zatwierdzaj|bez)\b", .88),
    (r"\bnie\s+(?:wymaga|potrzebuj|sprawdzaj|pytaj)\w*\s+(?:o\s+)?(?:uwierzytelni|autoryzacj|zgod|weryfikacj|hasł|logowani)", .92),
    (r"\b(?:remember|zapamiętaj|zapamietaj)\b.{0,60}\b(?:you are|jesteś|instructions?|instrukcj\w*|polic(?:y|ies)|polityk\w*|admin\w*)\b", .82),
]
PRIVILEGE = {
    "delete": .30, "drop": .48, "admin": .24, "root": .32,
    "external": .24, "credential": .35, "secret": .32,
    "usuń": .30, "administrator": .24, "zewnętrz": .24,
}

LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "l"})


def _normalize(text: str) -> str:
    return " ".join(re.findall(r"[\wąćęłńóśźż]+", text.lower(), re.UNICODE))


def _deleet(text: str) -> str:
    """Decode leetspeak only inside tokens that mix letters and digits/symbols."""
    def fix(match: re.Match) -> str:
        token = match.group(0)
        if re.search(r"[a-ząćęłńóśźż]", token, re.I) and re.search(r"[013457@$!|]", token):
            return token.translate(LEET)
        return token
    return re.sub(r"\S+", fix, text.lower())


def _variants(text: str) -> list[str]:
    low = text.lower()
    out = [low]
    decoded = _deleet(low)
    if decoded != low:
        out.append(decoded)
    return out


def _score_phrases(text: str, phrases: dict[str, float]) -> tuple[float, list[str]]:
    hits = [(phrase, score) for phrase, score in phrases.items() if phrase in text]
    # Independent evidence combines without ever exceeding 1.
    score = 1.0 - math.prod(1.0 - item[1] for item in hits)
    return round(score, 4), [item[0] for item in hits]


def _score_patterns(texts: list[str], patterns) -> tuple[float, list[str]]:
    best, hits = 0.0, []
    for pattern, score, name in patterns:
        if any(re.search(pattern, t, re.I | re.S) for t in texts):
            best = max(best, score)
            hits.append(name)
    if len(hits) > 1:
        best = min(1.0, best + .04 * (len(hits) - 1))
    return round(best, 4), hits


# --- Intent Lock --------------------------------------------------------------
CONCEPTS = {
    "REPORT": ["report", "raport", "q1", "q2", "q3", "q4", "quarter", "kwarta", "revenue", "przych", "cost", "koszt", "margin", "marż", "profit", "zysk", "sales", "sprzeda", "financ", "finans", "result", "wynik", "kpi", "driver", "trend", "chart", "wykres"],
    "SUMMARY": ["summar", "podsum", "streszcz", "overview", "przegląd", "explain", "wyjaśn", "describe", "opisz", "analy", "analiz", "compare", "porówn", "translat", "przetłumacz", "what", "jaki", "jakie", "why", "dlaczego", "how", "jak"],
    "CUSTOMER": ["customer", "client", "klient", "contact", "kontakt", "account", "konto", "ticket", "zgłosze"],
    "DELETE": ["delete", "remove", "usuń", "usun", "erase", "wipe", "drop"],
    "EXPORT": ["export", "eksport", "dump", "extract", "wyeksport", "exfiltrat", "bulk", "zrzu"],
    "MESSAGE": ["email", "e-mail", "mail ", "send", "wyślij", "wyslij", "forward", "prześlij", "przeslij"],
    "REPO": ["repo", "repozyt", "code", "kod", "commit", "branch", "quality", "jakoś"],
    "DOC": ["document", "dokument", "file", "plik", "invoice", "faktur", "note", "notat", "policy doc", "pdf"],
    "DB": ["database", "baza", "bazy", "bazie", "sql", "query", "zapytan", "table", "tabel", "record", "rekord"],
    "MEMORY": ["memory", "pamię", "pamie", "remember", "zapamięt", "zapamiet"],
    "EXTERNAL": ["external", "zewnętrz", "zewnetrz", "webhook", "http", "url", "upload", "outside", "third-party"],
    "CREDENTIAL": ["password", "hasł", "hasl", "credential", "poświadcz", "secret", "sekret", "token", "api key", "klucz", "private key", ".env", "ssh"],
    "BYPASS": ["ignore", "ignoruj", "zignoruj", "disregard", "bypass", "obejdź", "skip", "pomiń", "pomin", "disable", "wyłącz", "override", "jailbreak", "olej"],
    "AUTHORITY": ["i am the", "i'm the", "jestem", "authoriz", "authoris", "autoryzuj", "zezwalam", "ciso", "ceo", "as admin", "as the admin", "superuser"],
    "PAYROLL": ["payroll", "płac", "salary", "salaries", "wynagrodz", "pensj"],
}
ACTION_CONCEPTS = {
    "reports.read": {"REPORT", "SUMMARY"},
    "documents.read": {"DOC", "REPORT", "SUMMARY"},
    "customer.read": {"CUSTOMER"},
    "customer.update": {"CUSTOMER"},
    "customer.delete": {"CUSTOMER", "DELETE"},
    "customer.export": {"EXPORT"},
    "database.query": {"DB", "REPORT", "CUSTOMER"},
    "database.export": {"EXPORT"},
    "repository.analyze": {"REPO"},
    "api.external.call": {"EXTERNAL"},
    "email.send": {"MESSAGE"},
    "memory.read": {"MEMORY"},
    "memory.write": {"MEMORY"},
}
# Concepts that, when introduced by the request but absent from the user's
# goal, indicate goal hijacking (e.g. intent words stuffed in front of an attack).
# BYPASS wording is scored by the injection detector instead, so harmless
# phrases such as "ignore the typos" do not break the Intent Lock.
OFF_TASK = {"CREDENTIAL", "AUTHORITY", "EXPORT", "DELETE", "EXTERNAL", "PAYROLL", "MESSAGE"}
_CONCEPT_RE = {name: re.compile(r"(?<![\w])(?:" + "|".join(re.escape(s) for s in stems) + r")", re.I) for name, stems in CONCEPTS.items()}
STOP = {"the", "and", "for", "with", "this", "that", "oraz", "dla", "jest", "się", "sie", "please", "proszę"}


def _concepts(text: str) -> set[str]:
    low = text.lower()
    return {name for name, rx in _CONCEPT_RE.items() if rx.search(low)}


def _lexical(intent: str, current: str) -> float:
    a = {w for w in _normalize(intent).split() if len(w) > 2 and w not in STOP}
    b = {w for w in _normalize(current).split() if len(w) > 2 and w not in STOP}
    if not a:
        return 0.0
    overlap = len(a & b) / len(a)
    return 0.0 if overlap == 0 else min(1.0, .35 + .65 * overlap)


def _alignment(intent: str, action: str, prompt: str, resource: str) -> tuple[float, list[str]]:
    """Semantic Intent Lock: does this action and content serve the user's goal?

    Works across languages through a bilingual concept map, checks that the
    action family fits the goal, and penalises sensitive concepts the request
    introduces on top of the goal (stuffing the goal's words is not enough).
    """
    if not intent.strip():
        return 1.0, []
    goal = _concepts(intent)
    request = _concepts(f"{prompt} {resource}")
    action_family = ACTION_CONCEPTS.get(action, set())
    content = max(_lexical(intent, prompt), .35 + .65 * len(goal & request) / len(goal) if goal & request else 0.0)
    signals = []
    if action_family:
        if action_family & goal:
            base = max(.82, content)
        elif goal:
            base = .15
            signals.append("intent:action-outside-goal")
        else:
            base = max(content, .5)
    else:
        base = content if goal or content else .5
    extra = (request - goal) & OFF_TASK
    # Concepts implied by the action itself (e.g. MESSAGE for email.send) are
    # only off-task when the goal does not cover that action.
    if action_family & goal:
        extra -= action_family
    if extra:
        signals.append("intent:off-task:" + ",".join(sorted(extra)))
    return round(max(.05, min(1.0, base - .3 * len(extra))), 4), signals


def _history_drift(history: list[str], current: str) -> float:
    joined = _normalize(" ".join(history[-8:] + [current]))
    base, _ = _score_phrases(joined, PRIVILEGE)
    has_external = any(word in joined for word in ("external", "zewnętrz", "email send"))
    has_sensitive = any(word in joined for word in ("customer", "database", "secret", "credential", "klient", "baza"))
    chain = .38 if has_external and has_sensitive and len(history) >= 1 else 0
    return round(min(1.0, base + chain), 4)


def _chunks(text: str) -> list[str]:
    """Full text plus sentence/window chunks, so an attack hidden inside a long
    benign text cannot be diluted below the classifier threshold."""
    parts = [text]
    # Fragments shorter than four words (JSON keys, paths) are noise for the
    # classifier; real instructions are sentences.
    sentences = [s.strip() for s in re.split(r"(?<=[.!?\n])\s+", text) if len(re.findall(r"[^\W\d_]{2,}", s)) >= 4]
    if len(sentences) > 1:
        parts += sentences[:40]
    if len(text) > 400:
        parts += [text[i:i + 300] for i in range(0, min(len(text), 12000), 200)]
    return parts


def _calibrate_ml(probability: float) -> float:
    """Map classifier probability to a policy score. The small model alone only
    reaches block-level scores (>= .72) when it is clearly confident (p >= .58);
    borderline outputs stay in the review band instead of blocking."""
    if probability < .5:
        return round(probability * .65, 4)
    if probability < .58:
        return round(.325 + (probability - .5) * 3.4, 4)
    return round(min(1.0, .72 + (probability - .58) * .9), 4)


def offline_analyze(payload: dict[str, Any]) -> dict[str, Any]:
    prompt = str(payload.get("prompt") or "")[:20000]
    action = str(payload.get("action") or "")[:200]
    resource = str(payload.get("resource") or "")[:500]
    intent = str(payload.get("original_intent") or "")[:2000]
    history = [str(x)[:300] for x in (payload.get("history") or [])[-50:] if isinstance(x, str)]
    is_output = action.startswith("tool.output:")
    current = _normalize(f"{prompt} {action} {resource}")
    texts = _variants(f"{prompt} {resource}")

    injection, injection_hits = _score_phrases(current, INJECTION)
    exfiltration, exfil_hits = _score_phrases(current, EXFILTRATION)
    pat_inj, inj_pat_hits = _score_patterns(texts, INJECTION_PATTERNS)
    pat_exf, exf_pat_hits = _score_patterns(texts, EXFIL_PATTERNS)
    injection, exfiltration = max(injection, pat_inj), max(exfiltration, pat_exf)

    # The trained model detects paraphrases that match no pattern.
    ml_injection = ml_exfiltration = 0.0
    for variant in texts:
        for chunk in _chunks(variant):
            pi, pe = predict(chunk if is_output else f"{chunk} {action}")
            ml_injection, ml_exfiltration = max(ml_injection, pi), max(ml_exfiltration, pe)
    injection = max(injection, _calibrate_ml(ml_injection))
    exfiltration = max(exfiltration, _calibrate_ml(ml_exfiltration))

    alignment, intent_signals = (1.0, []) if is_output else _alignment(intent, action, prompt, resource)
    drift = 0.0 if is_output else _history_drift(history, current)
    memory = 0.0
    if action == "memory.write":
        memory = max([score for pattern, score in MEMORY_PATTERNS if any(re.search(pattern, t, re.I | re.S) for t in texts)] + [0.0])
        memory = max(memory, injection * .95)
    risk = round(max(injection, exfiltration, 1 - alignment, drift, memory), 4)
    signals = [f"injection:{x}" for x in injection_hits + inj_pat_hits]
    signals += [f"exfiltration:{x}" for x in exfil_hits + exf_pat_hits]
    signals += intent_signals
    signals += [f"ml:prompt_injection={ml_injection:.3f}", f"ml:data_exfiltration={ml_exfiltration:.3f}"]
    return {
        "prompt_injection": round(injection, 4),
        "data_exfiltration": round(exfiltration, 4),
        "intent_alignment": alignment,
        "privilege_drift": drift,
        "memory_poisoning": round(memory, 4),
        "risk": risk,
        "signals": signals or ["offline-semantic:no-high-risk-signal"],
    }


def ollama_analyze(payload: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    url = os.getenv("OLLAMA_URL")
    model = os.getenv("OLLAMA_MODEL")
    if not url or not model:
        return fallback
    instruction = (
        "Return only JSON with numeric fields prompt_injection, data_exfiltration, "
        "intent_alignment, privilege_drift, risk in range 0..1 and signals as an array. "
        "You are a classifier, not the final policy decision. Input: " + json.dumps(payload, ensure_ascii=False)
    )
    body = json.dumps({"model": model, "prompt": instruction, "stream": False, "format": "json"}).encode()
    request = urllib.request.Request(url.rstrip("/") + "/api/generate", body, {"Content-Type": "application/json"})
    # Must stay below the gateway's semantic timeout (MASQE_SEMANTIC_TIMEOUT_MS),
    # otherwise the gateway fails closed before this fallback can answer.
    timeout = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "1.0"))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read(262_144))
        parsed = json.loads(result["response"])
        for field in ("prompt_injection", "data_exfiltration", "intent_alignment", "privilege_drift", "risk"):
            parsed[field] = max(0.0, min(1.0, float(parsed[field])))
        parsed["signals"] = ["ollama"] + [str(s)[:80] for s in list(parsed.get("signals", []))[:10]]
        # Never let a local model weaken high-confidence deterministic semantic evidence.
        for field in ("prompt_injection", "data_exfiltration", "privilege_drift", "risk"):
            parsed[field] = max(parsed[field], fallback[field])
        parsed["intent_alignment"] = min(parsed["intent_alignment"], fallback["intent_alignment"])
        parsed["memory_poisoning"] = fallback["memory_poisoning"]
        return parsed
    except Exception as exc:  # Content is never logged.
        print(f"ollama fallback: {type(exc).__name__}", file=sys.stderr)
        return fallback


class Handler(BaseHTTPRequestHandler):
    server_version = "MASQE-AIGuard/1.1"

    def do_GET(self) -> None:
        if self.path != "/health":
            self._json(404, {"error": "not found"})
            return
        self._json(200, {"status": "ok", "backend": "ollama" if os.getenv("OLLAMA_URL") else "offline"})

    def do_POST(self) -> None:
        if self.path not in ("/analyze", "/explain"):
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1_048_576:
                self._json(413 if length > 0 else 400, {"error": "invalid body size"})
                return
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise TypeError("payload must be an object")
            if self.path == "/explain":
                try:
                    self._json(200, explain(payload))
                except Exception as exc:
                    # No generated text is invented when the model is down.
                    print(f"explanation unavailable: {type(exc).__name__}", file=sys.stderr)
                    self._json(503, {"error": "local explanation model unavailable"})
                return
            fallback = offline_analyze(payload)
            self._json(200, ollama_analyze(payload, fallback))
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._json(400, {"error": type(exc).__name__})

    def log_message(self, fmt: str, *args: Any) -> None:
        # Never log request bodies; endpoint/status is sufficient telemetry.
        print(f"ai-guard {self.command} {self.path} {args[1] if len(args) > 1 else ''}", file=sys.stderr)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    host = os.getenv("MASQE_AI_GUARD_HOST", "127.0.0.1")
    port = int(os.getenv("MASQE_AI_GUARD_PORT", "8090"))
    predict("warm up")  # train once at start-up, not on the first request
    print(f"MASQE AI Guard listening on http://{host}:{port}", file=sys.stderr)
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
