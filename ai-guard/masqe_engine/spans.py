"""Span — jedyna waluta silnika, i operacje na spanach.

Cały silnik operuje na ``Span``: model, reguły i użytkownik produkują to samo.
Konwersja do słowników następuje wyłącznie na granicy API. Poprzednia wersja
(veilum) mieszała dataclass ``Span`` z dictami ``{"entity": ..., "start": ...}``
w tej samej ścieżce i połowa bugów brała się z tego, że coś było raz jednym,
raz drugim.

Zawiera też agregację BIO/subword po ``offset_mapping`` — najbardziej
nietrywialny kawałek: model zwraca predykcje na subwordach, a my potrzebujemy
znakowych offsetów w oryginalnym tekście, odporne na szum BIO.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, replace
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .labels import LABEL_PRIORITY, normalize_label

#: Skąd wziął się span. Ma znaczenie w audycie i w UI:
#: ``rule`` = deterministyczne, suma kontrolna się zgadza — nie do podważenia,
#: ``model`` = statystyczne, może się mylić,
#: ``user`` = człowiek dodał ręcznie na ekranie przeglądu.
SOURCE_MODEL = "model"
SOURCE_RULE = "rule"
SOURCE_USER = "user"


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    label: str
    score: float = 1.0
    source: str = SOURCE_MODEL
    #: Stabilny identyfikator — frontend zaznacza/odznacza po nim, a /apply
    #: dostaje z powrotem listę id-ków zamiast przepisanych offsetów.
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12], compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "label", normalize_label(self.label))

    @property
    def length(self) -> int:
        return self.end - self.start

    def text_of(self, text: str) -> str:
        return text[self.start:self.end]

    def shifted(self, offset: int) -> "Span":
        return replace(self, start=self.start + offset, end=self.end + offset)


def _priority(span: Span) -> int:
    return LABEL_PRIORITY.get(span.label, 10)


def _is_special_offset(off: Optional[Sequence[int]]) -> bool:
    return off is None or (off[0] == 0 and off[1] == 0)


def _bio_parts(tag: str) -> Tuple[str, Optional[str]]:
    """Rozłóż tag BIO na (prefiks, typ). Przyjmuje ``B-X``, ``I-X``, ``O``.

    Modele bywają trenowane bez BIO — wtedy ``id2label`` trzyma gołe etykiety.
    Taki tag traktujemy jak ``B-``.
    """
    if not tag or tag == "O":
        return "O", None
    if "-" not in tag:
        return "B", tag
    prefix, ent_type = tag.split("-", 1)
    if prefix not in ("B", "I"):
        return "O", None
    return prefix, ent_type


def tokens_to_spans(
    text: str,
    offsets: Sequence[Optional[Sequence[int]]],
    pred_ids: Sequence[int],
    pred_scores: Sequence[float],
    id2label: Dict[int, str],
    *,
    fix_i_without_b: bool = True,
) -> List[Span]:
    """Zamień predykcje BIO na subwordach w znakowe spany na ``text``.

    ``fix_i_without_b`` ratuje typowy szum modelu: ``I-PESEL`` bez
    poprzedzającego ``B-PESEL``. Bez tej poprawki taki token wypada, czyli
    encja zostaje w dokumencie — fałszywy negatyw, dokładnie ten rodzaj błędu,
    który w tym produkcie jest niebezpieczny.
    """
    spans: List[Span] = []
    cur_label: Optional[str] = None
    cur_start: Optional[int] = None
    cur_end: Optional[int] = None
    cur_scores: List[float] = []

    def flush() -> None:
        nonlocal cur_label, cur_start, cur_end, cur_scores
        if cur_label is not None and cur_start is not None and cur_end is not None and cur_end > cur_start:
            score = sum(cur_scores) / max(len(cur_scores), 1)
            spans.append(Span(cur_start, cur_end, cur_label, float(score), SOURCE_MODEL))
        cur_label, cur_start, cur_end, cur_scores = None, None, None, []

    for i, off in enumerate(offsets):
        if _is_special_offset(off):
            continue
        start, end = int(off[0]), int(off[1])
        if start < 0 or end <= start or end > len(text):
            continue

        prefix, ent_type = _bio_parts(id2label.get(int(pred_ids[i]), "O"))

        if prefix == "O" or ent_type is None:
            flush()
            continue

        if prefix == "I":
            if cur_label is None:
                if not fix_i_without_b:
                    continue
                prefix = "B"
            elif cur_label != normalize_label(ent_type):
                flush()
                if not fix_i_without_b:
                    continue
                prefix = "B"

        score_i = float(pred_scores[i])
        ent_type = normalize_label(ent_type)

        if prefix == "B":
            flush()
            cur_label, cur_start, cur_end, cur_scores = ent_type, start, end, [score_i]
            continue

        # prefix == "I" przy zgodnym typie
        if cur_end is not None and start > cur_end:
            # Nieciągłość po tokenizacji — bezpieczniej zacząć nowy span niż
            # rozciągnąć stary przez tekst, którego model nie oznaczył.
            flush()
            cur_label, cur_start, cur_end, cur_scores = ent_type, start, end, [score_i]
        else:
            cur_end = end if cur_end is None else max(cur_end, end)
            cur_scores.append(score_i)

    flush()
    return [s for s in (trim_whitespace(s, text) for s in spans) if s is not None]


def trim_whitespace(span: Span, text: str) -> Optional[Span]:
    """Obetnij białe znaki na brzegach spanu. ``None``, gdy nic nie zostaje."""
    a, b = span.start, span.end
    while a < b and text[a].isspace():
        a += 1
    while b > a and text[b - 1].isspace():
        b -= 1
    if b <= a:
        return None
    if (a, b) == (span.start, span.end):
        return span
    return replace(span, start=a, end=b)


#: Minimalna długość spanu modelu w znakach. Jednoznakowy span to prawie zawsze
#: końcówka fleksyjna oderwana od reszty wyrazu (``Michalakowi`` → ``a``),
#: a nie encja. Wyjątek: ``SEX`` bywa jedną literą (``K``, ``M``).
MIN_MODEL_SPAN_LENGTH = 2
SHORT_SPAN_EXEMPT = frozenset({"SEX"})

#: Ile znaków wolno dokleić z jednej strony przy dociąganiu do granicy wyrazu.
#: Bez limitu span mógłby połknąć długi ciąg alfanumeryczny, na który model
#: nie miał żadnego dowodu.
MAX_SNAP_CHARS = 24


def _is_word_char(ch: str) -> bool:
    """Znak należący do wnętrza wyrazu. Celowo bez ``-`` i ``.``: dywiz łączy
    dwa osobne człony (``Kowalska-Nowak``), a kropka rozdziela części adresu
    e-mail i skróty."""
    return ch.isalnum()


def snap_to_word(span: Span, text: str) -> Span:
    """Rozszerz span do pełnych granic wyrazu.

    Tokenizator subwordowy tnie ``Michalakowi`` na ``Michal`` + ``a`` + ``kowi``
    i model potrafi oznaczyć tylko część. Bez dociągnięcia w pobranym dokumencie
    zostaje ``[IMIE]kowi`` — czyli wyciek. Rozszerzamy tylko, nigdy nie
    skracamy: fałszywy pozytyw kosztuje mniej niż resztka danych osobowych.
    """
    a, b = span.start, span.end
    if a >= b:
        return span
    limit_a = max(0, a - MAX_SNAP_CHARS)
    while a > limit_a and _is_word_char(text[a - 1]):
        a -= 1
    limit_b = min(len(text), b + MAX_SNAP_CHARS)
    while b < limit_b and _is_word_char(text[b]):
        b += 1
    if (a, b) == (span.start, span.end):
        return span
    return replace(span, start=a, end=b)


def drop_short(spans: Iterable[Span], *, min_length: int = MIN_MODEL_SPAN_LENGTH) -> List[Span]:
    """Odrzuć szczątkowe spany modelu. Reguły i użytkownik nie podlegają filtrowi:
    tam krótki zakres jest decyzją, nie artefaktem tokenizacji."""
    return [
        s for s in spans
        if s.source != SOURCE_MODEL
        or s.label in SHORT_SPAN_EXEMPT
        or s.length >= min_length
    ]


def merge_adjacent(spans: Iterable[Span]) -> List[Span]:
    """Sklej sąsiadujące spany tej samej etykiety (rozbicie na subwordy).

    Tolerancja jednego znaku przerwy — spacja między „Jan" a „Kowalski"
    nie powinna dawać dwóch osobnych encji NAME.
    """
    ordered = sorted(spans, key=lambda s: (s.start, s.end))
    if not ordered:
        return []
    merged: List[Span] = [ordered[0]]
    for s in ordered[1:]:
        last = merged[-1]
        if s.label == last.label and s.source == last.source and s.start <= last.end + 1:
            merged[-1] = replace(
                last,
                end=max(last.end, s.end),
                score=max(last.score, s.score),
            )
        else:
            merged.append(s)
    return merged


def resolve_overlaps(spans: Iterable[Span], *, iou_threshold: float = 0.6) -> List[Span]:
    """Rozstrzygnij nakładanie się spanów. Zwraca listę rozłączną, posortowaną.

    Kolejność rozstrzygania: źródło (reguła > model), priorytet etykiety,
    wynik, długość. Reguła z poprawną sumą kontrolną bije model zawsze —
    jeśli jedenaście cyfr przechodzi walidację PESEL, to jest PESEL, choćby
    model uważał inaczej.

    ``iou_threshold`` odróżnia duplikat (ten sam byt widziany w dwóch oknach
    sliding window) od realnego konfliktu dwóch różnych encji.
    """
    def rank(s: Span) -> Tuple[int, int, float, int]:
        return (
            2 if s.source == SOURCE_USER else 1 if s.source == SOURCE_RULE else 0,
            _priority(s),
            s.score,
            s.length,
        )

    def iou(a: Span, b: Span) -> float:
        inter = max(0, min(a.end, b.end) - max(a.start, b.start))
        union = max(a.end, b.end) - min(a.start, b.start)
        return 0.0 if union == 0 else inter / union

    # Najlepsze najpierw — pierwszy, który zajmie miejsce, je zatrzymuje.
    ordered = sorted(spans, key=lambda s: (rank(s), -s.start), reverse=True)

    accepted: List[Span] = []
    for s in ordered:
        conflict = False
        for k in accepted:
            if s.end <= k.start or s.start >= k.end:
                continue
            conflict = True
            break
        if not conflict:
            accepted.append(s)

    accepted.sort(key=lambda s: (s.start, s.end))
    return accepted


def union_cover(spans: Iterable[Span]) -> List[Span]:
    """Scal wszystko, co się nakłada, w rozłączne bloki do redakcji.

    Używane tylko przy nakładaniu redakcji: jeśli dwa spany zachodzą na siebie,
    zamazujemy sumę, nie część wspólną. Etykieta bloku to etykieta spanu
    o najwyższym priorytecie.
    """
    ordered = sorted(spans, key=lambda s: (s.start, -s.end))
    if not ordered:
        return []
    out: List[Span] = [ordered[0]]
    for s in ordered[1:]:
        last = out[-1]
        if s.start <= last.end:
            winner = s if (_priority(s), s.score) > (_priority(last), last.score) else last
            out[-1] = replace(winner, start=last.start, end=max(last.end, s.end))
        else:
            out.append(s)
    return out


def to_dict(span: Span, text: Optional[str] = None) -> Dict[str, object]:
    """Serializacja na granicy API.

    ``text`` podajemy tylko tam, gdzie wolno pokazać treść — czyli w podglądzie
    dla zalogowanego użytkownika. W audit logu nigdy.
    """
    from .labels import category_of, display_name, is_article_9

    payload: Dict[str, object] = {
        "id": span.id,
        "start": span.start,
        "end": span.end,
        "label": span.label,
        "label_pl": display_name(span.label),
        "category": category_of(span.label),
        "score": round(float(span.score), 4),
        "source": span.source,
        "sensitive": is_article_9(span.label),
    }
    if text is not None:
        payload["text"] = span.text_of(text)
    return payload
