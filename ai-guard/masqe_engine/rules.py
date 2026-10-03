"""Warstwa deterministyczna: polskie identyfikatory z sumami kontrolnymi.

Model statystyczny nie ma po co zgadywać, czy jedenaście cyfr to PESEL —
to się liczy. Ta warstwa łapie identyfikatory deterministycznie i wygrywa
z modelem przy konflikcie (patrz ``spans.resolve_overlaps``).

Dwa reżimy, świadomie różne:

``gated``   — dopasowanie bez poprawnej sumy kontrolnej jest odrzucane.
              Dotyczy PESEL, NIP, REGON, IBAN, numeru konta i karty. Powód:
              goły ciąg 9-11 cyfr występuje w dokumentach masowo (numer
              faktury, zamówienia, kwota), więc bez bramki zalalibyśmy ekran
              przeglądu szumem.

``scored``  — dopasowanie przechodzi zawsze, suma kontrolna wpływa tylko na
              wynik. Dotyczy dowodu i paszportu. Powód: format „3 litery +
              6 cyfr" sam w sobie jest rzadki, więc fałszywy pozytyw kosztuje
              sekundę uwagi, a błąd w mojej implementacji sumy kontrolnej
              kosztowałby fałszywy negatyw — czyli niezredagowany numer
              dowodu w dokumencie wysłanym na zewnątrz.

Asymetria jest celowa i wynika wprost z tego, jak kosztują oba rodzaje błędu.
"""

from __future__ import annotations

import re
from typing import Callable, List, NamedTuple, Optional

from .spans import SOURCE_RULE, Span

# --------------------------------------------------------------------------
#  Sumy kontrolne
# --------------------------------------------------------------------------

def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def valid_pesel(value: str) -> bool:
    """PESEL: 11 cyfr, waga [1,3,7,9,...] + sensowna data urodzenia.

    Sama suma kontrolna przepuszcza co dziesiąty losowy ciąg 11 cyfr, więc
    dokładamy walidację zakodowanej daty. To odsiewa większość numerów
    faktur i zamówień, które akurat trafiły w sumę.
    """
    d = _digits(value)
    if len(d) != 11:
        return False
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    total = sum(int(c) * w for c, w in zip(d, weights))
    if int(d[10]) != (10 - (total % 10)) % 10:
        return False

    month = int(d[2:4])
    day = int(d[4:6])
    # Stulecie kodowane w miesiącu: 1-12→1900, 21-32→2000, 41-52→2100,
    # 61-72→2200, 81-92→1800.
    if not any(lo <= month <= hi for lo, hi in ((1, 12), (21, 32), (41, 52), (61, 72), (81, 92))):
        return False
    return 1 <= day <= 31


def valid_nip(value: str) -> bool:
    d = _digits(value)
    if len(d) != 10:
        return False
    weights = (6, 5, 7, 2, 3, 4, 5, 6, 7)
    remainder = sum(int(c) * w for c, w in zip(d, weights)) % 11
    return remainder < 10 and remainder == int(d[9])


def valid_regon(value: str) -> bool:
    """REGON 9- lub 14-cyfrowy. Dla 14 cyfr pierwsze 9 też musi być poprawne."""
    d = _digits(value)
    if len(d) == 9:
        weights = (8, 9, 2, 3, 4, 5, 6, 7)
    elif len(d) == 14:
        if not valid_regon(d[:9]):
            return False
        weights = (2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8)
    else:
        return False
    control = sum(int(c) * w for c, w in zip(d, weights)) % 11
    return (0 if control == 10 else control) == int(d[len(weights)])


def valid_iban(value: str) -> bool:
    """IBAN wg ISO 13616: przeniesienie 4 znaków na koniec, mod 97 == 1."""
    s = re.sub(r"[\s-]", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    try:
        numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    except ValueError:
        return False
    return int(numeric) % 97 == 1


def valid_nrb(value: str) -> bool:
    """Polski NRB — 26 cyfr bez prefiksu ``PL``. Walidowany jak IBAN z ``PL00``."""
    d = _digits(value)
    if len(d) != 26:
        return False
    return valid_iban("PL" + d)


def valid_luhn(value: str) -> bool:
    d = _digits(value)
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _alnum_weighted(value: str, weights: tuple) -> Optional[int]:
    """Suma ważona dla numerów mieszanych: litera A=10 … Z=35."""
    s = value.upper()
    if len(s) != len(weights):
        return None
    total = 0
    for ch, w in zip(s, weights):
        if ch.isdigit():
            total += int(ch) * w
        elif "A" <= ch <= "Z":
            total += (ord(ch) - 55) * w
        else:
            return None
    return total


def valid_id_card(value: str) -> bool:
    """Dowód osobisty: 3 litery + 6 cyfr, cyfra kontrolna na pozycji 4."""
    total = _alnum_weighted(value.replace(" ", ""), (7, 3, 1, 9, 7, 3, 1, 7, 3))
    return total is not None and total % 10 == 0


def valid_passport(value: str) -> bool:
    """Paszport: 2 litery + 7 cyfr, cyfra kontrolna na pozycji 3."""
    total = _alnum_weighted(value.replace(" ", ""), (7, 3, 9, 1, 7, 3, 1, 7, 3))
    return total is not None and total % 10 == 0


# --------------------------------------------------------------------------
#  Reguły
# --------------------------------------------------------------------------

class Rule(NamedTuple):
    label: str
    pattern: re.Pattern
    #: ``None`` = brak sumy kontrolnej dla tego typu.
    validator: Optional[Callable[[str], bool]]
    #: True → dopasowanie bez poprawnej sumy kontrolnej wypada.
    gated: bool
    #: Wynik dla dopasowania, które nie przeszło sumy kontrolnej (tylko gdy
    #: ``gated=False``). Poniżej 1.0, żeby w UI dało się je odróżnić.
    unverified_score: float = 0.75


#: Kolejność nie wpływa na rozstrzyganie konfliktów — tym zajmuje się
#: ``resolve_overlaps`` po priorytecie etykiety — ale trzyma czytelność.
RULES: tuple = (
    Rule(
        "PESEL",
        re.compile(r"(?<!\d)\d{11}(?!\d)"),
        valid_pesel,
        gated=True,
    ),
    Rule(
        "NIP",
        # Dopuszczamy separatory w formatach XXX-XXX-XX-XX i XXX-XX-XX-XXX,
        # oraz opcjonalny prefiks kraju stosowany na fakturach UE.
        re.compile(r"(?<![\w-])(?:PL)?\s?\d{3}[-\s]?\d{3}[-\s]?\d{2}[-\s]?\d{2}(?![\d-])", re.IGNORECASE),
        valid_nip,
        gated=True,
    ),
    Rule(
        "REGON",
        re.compile(r"(?<!\d)(?:\d{14}|\d{9})(?!\d)"),
        valid_regon,
        gated=True,
    ),
    Rule(
        "IBAN",
        re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{2,4}){2,8}(?![A-Z0-9])"),
        valid_iban,
        gated=True,
    ),
    Rule(
        "BANK_ACCOUNT",
        re.compile(r"(?<![\dA-Z-])\d{2}(?:[ -]?\d{4}){6}(?![\d-])"),
        valid_nrb,
        gated=True,
    ),
    Rule(
        "CREDIT_CARD_NUMBER",
        re.compile(r"(?<![\d-])(?:\d{4}[ -]?){3}\d{1,7}(?![\d-])"),
        valid_luhn,
        gated=True,
    ),
    Rule(
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        None,
        gated=False,
    ),
    Rule(
        "PHONE",
        re.compile(
            r"(?<![\d-])(?:\+?48[-\s]?)?(?:"
            r"\d{3}[-\s]\d{3}[-\s]\d{3}"          # 123-456-789
            r"|\(\d{2}\)\s*\d{3}[-\s]?\d{2}[-\s]?\d{2}"  # (12) 345 67 89
            r"|\d{9}"                              # 123456789
            r")(?![\d-])"
        ),
        None,
        gated=False,
    ),
    Rule(
        "ID_CARD",
        re.compile(r"(?<![A-Z0-9])[A-Z]{3}\s?\d{6}(?![A-Z0-9])"),
        valid_id_card,
        gated=False,
    ),
    Rule(
        "PASSPORT",
        re.compile(r"(?<![A-Z0-9])[A-Z]{2}\s?\d{7}(?![A-Z0-9])"),
        valid_passport,
        gated=False,
    ),
)


def find_rule_spans(text: str) -> List[Span]:
    """Znajdź wszystkie identyfikatory wykrywalne deterministycznie.

    Zwraca spany ``source="rule"``. Nakładanie się z wynikami modelu
    rozstrzyga ``spans.resolve_overlaps`` — nie tutaj, żeby reguły dało się
    testować w izolacji.
    """
    out: List[Span] = []
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            value = match.group(0)
            ok = rule.validator(value) if rule.validator is not None else True
            if rule.gated and not ok:
                continue
            score = 1.0 if ok else rule.unverified_score
            start, end = match.span()
            # Prefiks „PL" w NIP i wiodące spacje nie są częścią identyfikatora,
            # ale zamazujemy je razem z nim — czytelniej w dokumencie wyjściowym.
            out.append(Span(start, end, rule.label, score, SOURCE_RULE))
    return out
