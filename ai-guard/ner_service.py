"""PII detection with the fine-tuned Polish HerBERT model (PLVeil).

The model loads once in the background at start-up (~5 s, ~500 MB RAM); until
then /redact answers 503 and the gateway applies its policy fallback. Offsets
are returned in UTF-8 bytes because the Go gateway slices byte strings.
"""
from __future__ import annotations

import os
import sys
import threading

MODEL_ID = os.getenv("MASQE_NER_MODEL", "OskarBartoszyk/PLVeilBest")
MIN_SCORE = float(os.getenv("MASQE_NER_MIN_SCORE", "0.5"))

_engine = None
_error = None
_ready = threading.Event()


def _load() -> None:
    global _engine, _error
    try:
        try:
            from masqe_engine import MasqeNER
            import torch  # noqa: F401  (fail fast when the optional deps are missing)
        except ImportError as exc:
            raise ModuleNotFoundError(f"not installed (pip install -r requirements-ner.txt): {exc.name}") from exc
        _engine = MasqeNER(MODEL_ID, min_score=MIN_SCORE)
        _engine.detect("Rozgrzewka modelu.")
        print(f"NER model ready: {MODEL_ID}", file=sys.stderr)
    except Exception as exc:  # torch/transformers missing or weights unavailable
        _error = f"{type(exc).__name__}: {exc}"[:300]
        print(f"NER model unavailable: {_error}", file=sys.stderr)
    finally:
        _ready.set()


def start_loading() -> None:
    if os.getenv("MASQE_NER_DISABLED") == "1":
        globals()["_error"] = "disabled by MASQE_NER_DISABLED"
        _ready.set()
        return
    threading.Thread(target=_load, daemon=True, name="ner-load").start()


def status() -> dict:
    return {"ready": _engine is not None, "loading": not _ready.is_set(), "model": MODEL_ID, "error": _error}


class Unavailable(Exception):
    pass


def detect(text: str) -> list[dict]:
    if _engine is None:
        raise Unavailable(_error or "model is loading")
    spans = _engine.detect(text)
    out = []
    for s in spans:
        start = len(text[:s.start].encode("utf-8"))
        end = start + len(text[s.start:s.end].encode("utf-8"))
        out.append({"start": start, "end": end, "label": s.label, "score": round(float(s.score), 4), "source": s.source})
    return out
