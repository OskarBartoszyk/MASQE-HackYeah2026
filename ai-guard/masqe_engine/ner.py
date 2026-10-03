"""Silnik detekcji: HerBERT (token classification) + warstwa reguł.

Odpowiada za jedno: ``text -> List[Span]``. Nie wie nic o PDF-ach, DOCX-ach
ani o HTTP. Formaty dokumentów są warstwę wyżej (``masqe_engine.documents``),
dzięki czemu ten moduł da się testować na gołych stringach i podmienić model
bez ruszania reszty.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional, Sequence, Tuple

from .rules import find_rule_spans
from .spans import (
    Span,
    drop_short,
    merge_adjacent,
    resolve_overlaps,
    snap_to_word,
    tokens_to_spans,
)

logger = logging.getLogger("masqe.ner")

DEFAULT_MODEL_ID = os.getenv("MASQE_MODEL_ID", "OskarBartoszyk/PLVeilBest")

#: Ile okien sliding window liczymy w jednym przebiegu. Dobrane pod CPU:
#: powyżej ~8 rośnie zużycie pamięci bez zysku na czasie, bo i tak upieramy
#: się o rdzenie.
DEFAULT_BATCH_SIZE = 8


class MasqeNER:
    """Detektor encji. Jedna instancja na proces — model waży ~500 MB."""

    def __init__(
        self,
        model_id: str = DEFAULT_MODEL_ID,
        *,
        max_length: Optional[int] = None,
        stride: int = 64,
        min_score: float = 0.4,
        batch_size: int = DEFAULT_BATCH_SIZE,
        use_rules: bool = True,
        device: str = "cpu",
    ) -> None:
        """
        Args:
            model_id: repo HuggingFace albo ścieżka lokalna.
            max_length: limit tokenów na okno; ``None`` → z konfiguracji modelu.
            stride: zakładka między oknami, w tokenach. Encja na styku dwóch
                okien musi zmieścić się w zakładce, inaczej zostanie ucięta.
            min_score: próg odcięcia dla predykcji modelu. Reguły go nie dotyczą.
            batch_size: ile okien liczymy naraz.
            use_rules: wyłączane tylko w testach modelu w izolacji.
            device: ``cpu`` albo ``cuda``. Produkcyjnie CPU — patrz specyfikacja,
                sekcja o koszcie: wąskim gardłem jest OCR, nie model.
        """
        # Import lokalny: ``masqe_engine.rules`` i ``spans`` mają być używalne
        # bez torcha (np. w testach reguł, w skryptach walidacyjnych).
        from transformers import AutoModelForTokenClassification, AutoTokenizer
        import torch

        self._torch = torch
        self.model_id = model_id
        self.stride = stride
        self.min_score = min_score
        self.batch_size = max(1, batch_size)
        self.use_rules = use_rules

        logger.info("ładowanie modelu %s", model_id)
        self.tokenizer = AutoTokenizer.from_pretrained(model_id, use_fast=True)
        self.model = AutoModelForTokenClassification.from_pretrained(model_id)
        self.model.eval()
        self.model.to(device)
        self.device = device

        model_limit = getattr(self.model.config, "max_position_embeddings", None)
        if max_length is not None:
            self.max_length = max_length
        elif model_limit and 0 < model_limit < 10**6:
            self.max_length = min(512, model_limit - 2)
        else:
            self.max_length = 510

        #: Ile tokenów treści mieści się w oknie po odjęciu [CLS]/[SEP].
        self.window = self.max_length - 2
        if self.stride >= self.window:
            raise ValueError(f"stride ({self.stride}) musi być mniejszy niż okno ({self.window})")

        self.id2label: Dict[int, str] = {
            int(k): v for k, v in self.model.config.id2label.items()
        }
        logger.info(
            "model gotowy: okno=%d tokenów, stride=%d, etykiet=%d, device=%s",
            self.window, self.stride, len(self.id2label), device,
        )

    # ----------------------------------------------------------------- API

    def detect(self, text: str) -> List[Span]:
        """Zwróć rozłączną, posortowaną listę encji wykrytych w ``text``."""
        if not text or not text.strip():
            return []

        model_spans = self._detect_model(text)
        model_spans = [s for s in model_spans if s.score >= self.min_score]
        # Dociągnięcie do granicy wyrazu MUSI iść przed sklejaniem: dopiero
        # pełne wyrazy stykają się ze sobą tak, żeby merge_adjacent je złączył.
        model_spans = [snap_to_word(s, text) for s in model_spans]
        model_spans = merge_adjacent(model_spans)
        # Po dociągnięciu to, co dalej ma jeden znak, jest resztką, nie encją.
        model_spans = drop_short(model_spans)

        candidates = list(model_spans)
        if self.use_rules:
            candidates.extend(find_rule_spans(text))

        return resolve_overlaps(candidates)

    def detect_batch(self, texts: Sequence[str]) -> List[List[Span]]:
        """Wygodny wrapper — dokumenty wielostronicowe wołają to per strona."""
        return [self.detect(t) for t in texts]

    # ------------------------------------------------------------ wewnętrzne

    def _detect_model(self, text: str) -> List[Span]:
        windows = self._plan_windows(text)
        if not windows:
            return []

        spans: List[Span] = []
        for i in range(0, len(windows), self.batch_size):
            chunk = windows[i:i + self.batch_size]
            spans.extend(self._infer_windows(text, chunk))
        return spans

    def _plan_windows(self, text: str) -> List[Tuple[int, int]]:
        """Podziel tekst na znakowe zakresy okien z zakładką ``stride``.

        Liczymy tokeny raz, a granice okien wyrażamy w znakach, bo dalsze
        etapy (redakcja PDF, podmiana w DOCX) operują na znakach oryginału.
        """
        encoding = self.tokenizer(text, return_offsets_mapping=True, add_special_tokens=False)
        offsets = encoding["offset_mapping"]
        n = len(offsets)
        if n == 0:
            return []
        if n <= self.window:
            return [(0, len(text))]

        step = self.window - self.stride
        windows: List[Tuple[int, int]] = []
        i = 0
        while i < n:
            j = min(i + self.window, n)
            char_start = offsets[i][0]
            char_end = offsets[j - 1][1]
            if char_end > char_start:
                windows.append((char_start, char_end))
            if j >= n:
                break
            i += step
        return windows

    def _infer_windows(self, text: str, windows: Sequence[Tuple[int, int]]) -> List[Span]:
        torch = self._torch
        fragments = [text[a:b] for a, b in windows]

        encoded = self.tokenizer(
            fragments,
            return_offsets_mapping=True,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=self.max_length,
        )
        offset_mapping = encoded.pop("offset_mapping")
        encoded = {k: v.to(self.device) for k, v in encoded.items()}

        with torch.no_grad():
            logits = self.model(**encoded).logits

        probs = torch.softmax(logits, dim=-1)
        scores, ids = torch.max(probs, dim=-1)

        out: List[Span] = []
        for row, (char_start, _char_end) in enumerate(windows):
            fragment_spans = tokens_to_spans(
                text=fragments[row],
                offsets=offset_mapping[row].tolist(),
                pred_ids=ids[row].tolist(),
                pred_scores=scores[row].tolist(),
                id2label=self.id2label,
                fix_i_without_b=True,
            )
            out.extend(s.shifted(char_start) for s in fragment_spans)
        return out


# --------------------------------------------------------------------------
#  Singleton procesu
# --------------------------------------------------------------------------

_engine: Optional[MasqeNER] = None


def get_engine(**kwargs) -> MasqeNER:
    """Zwróć współdzieloną instancję. Ładowanie modelu trwa kilkanaście sekund,
    więc API woła to raz na starcie (lifespan), nie per żądanie."""
    global _engine
    if _engine is None:
        _engine = MasqeNER(**kwargs)
    return _engine


def reset_engine() -> None:
    """Tylko do testów."""
    global _engine
    _engine = None
