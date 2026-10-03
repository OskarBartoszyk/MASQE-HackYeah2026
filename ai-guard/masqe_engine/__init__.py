"""Polish PII detector (HerBERT token classification + rules), vendored from
the MASQE anonymisation engine. Only text -> spans; no document handling."""
from .ner import MasqeNER
from .rules import find_rule_spans
from .spans import Span

__all__ = ["MasqeNER", "find_rule_spans", "Span"]
