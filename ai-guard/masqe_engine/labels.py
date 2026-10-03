"""Kanoniczne etykiety encji, ich polskie nazwy i kategorie.

Jedno źródło prawdy dla całego systemu: model zwraca etykiety BIO
(``B-PESEL``/``I-PESEL``), reguły zwracają te same etykiety bez prefiksu,
frontend koloruje po ``CATEGORY_OF``. Etykieta jest zawsze UPPER_SNAKE.

Zbiór etykiet modelu pochodzi z ``config.json`` modelu PLVeilBest (51 tagów
BIO = 25 typów + O). Reguły dokładają cztery typy, których model nie zna,
bo wykrywa się je deterministycznie sumą kontrolną, nie statystycznie.
"""

from __future__ import annotations

from typing import Dict, FrozenSet

#: Typy, które potrafi rozpoznać model NER (bez prefiksów BIO).
MODEL_LABELS: FrozenSet[str] = frozenset({
    "ADDRESS", "AGE", "BANK_ACCOUNT", "CITY", "COMPANY", "CREDIT_CARD_NUMBER",
    "DATE", "DATE_OF_BIRTH", "DOCUMENT_NUMBER", "EMAIL", "ETHNICITY", "HEALTH",
    "JOB_TITLE", "NAME", "NIP", "PESEL", "PHONE", "POLITICAL_VIEW", "RELATIVE",
    "RELIGION", "SCHOOL_NAME", "SECRET", "SEX", "SEXUAL_ORIENTATION",
    "SURNAME", "USERNAME",
})

#: Typy wykrywane wyłącznie regułami z sumą kontrolną.
RULE_ONLY_LABELS: FrozenSet[str] = frozenset({
    "REGON", "IBAN", "ID_CARD", "PASSPORT",
})

ALL_LABELS: FrozenSet[str] = MODEL_LABELS | RULE_ONLY_LABELS

#: Kategoria → etykiety. Kolejność ma znaczenie: tak wyświetla się filtr.
#:
#: Kontakt i lokalizacja są rozdzielone, mimo że oba są „danymi kontaktowymi".
#: Powód jest praktyczny, nie taksonomiczny: na ekranie przeglądu człowiek
#: podejmuje wobec nich inne decyzje. Adres w umowie najmu bywa potrzebny
#: w dokumencie wychodzącym, a numer telefonu tej samej osoby już nie.
#: Wspólna kategoria wymuszałaby włączanie i wyłączanie ich razem.
CATEGORIES: Dict[str, tuple] = {
    "IDENTITY": ("NAME", "SURNAME", "RELATIVE", "USERNAME", "SEX", "AGE", "DATE_OF_BIRTH"),
    "IDENTIFIER": ("PESEL", "NIP", "REGON", "ID_CARD", "PASSPORT", "DOCUMENT_NUMBER"),
    "CONTACT": ("EMAIL", "PHONE"),
    "LOCATION": ("ADDRESS", "CITY"),
    "FINANCIAL": ("BANK_ACCOUNT", "IBAN", "CREDIT_CARD_NUMBER"),
    "SENSITIVE": ("HEALTH", "RELIGION", "ETHNICITY", "POLITICAL_VIEW", "SEXUAL_ORIENTATION", "SECRET"),
    "PROFESSIONAL": ("COMPANY", "JOB_TITLE", "SCHOOL_NAME"),
    "OTHER": ("DATE",),
}

CATEGORY_OF: Dict[str, str] = {
    label: category for category, labels in CATEGORIES.items() for label in labels
}

CATEGORY_NAMES_PL: Dict[str, str] = {
    "IDENTITY": "Osoba",
    "IDENTIFIER": "Identyfikatory",
    "CONTACT": "Kontakt",
    "LOCATION": "Adresy",
    "FINANCIAL": "Finanse",
    "SENSITIVE": "Dane wrażliwe",
    "PROFESSIONAL": "Zawodowe",
    "OTHER": "Pozostałe",
}

#: Kolory zaznaczeń — jeden na kategorię, nie na etykietę. Trzydzieści kolorów
#: jest nie do odróżnienia okiem; osiem jest. Wartości pochodzą z design systemu
#: Masqe (tokeny ``--entity-*``) i muszą się z nim zgadzać, bo frontend rysuje
#: po tych samych zmiennych CSS.
CATEGORY_COLORS: Dict[str, str] = {
    "IDENTITY": "#c14a28",
    "IDENTIFIER": "#7b4a9c",
    "CONTACT": "#2f5f7e",
    "LOCATION": "#b8801d",
    "FINANCIAL": "#3f7d62",
    "SENSITIVE": "#a33a5a",
    "PROFESSIONAL": "#5a6473",
    "OTHER": "#7d8797",
}

#: Nazwa tokenu CSS design systemu dla każdej kategorii. Frontend używa tego
#: zamiast wartości hex, żeby motyw jasny i ciemny działały bez podmiany kolorów.
CATEGORY_TOKENS: Dict[str, str] = {
    "IDENTITY": "name",
    "IDENTIFIER": "id",
    "CONTACT": "contact",
    "LOCATION": "location",
    "FINANCIAL": "financial",
    "SENSITIVE": "health",
    "PROFESSIONAL": "neutral",
    "OTHER": "neutral",
}

#: Dane szczególnych kategorii w rozumieniu art. 9 RODO. Wyróżniane w UI —
#: przeoczenie tych kosztuje nieporównanie więcej niż przeoczenie nazwy firmy.
ARTICLE_9_LABELS: FrozenSet[str] = frozenset(CATEGORIES["SENSITIVE"])

LABEL_NAMES_PL: Dict[str, str] = {
    "ADDRESS": "Adres",
    "AGE": "Wiek",
    "BANK_ACCOUNT": "Numer konta",
    "CITY": "Miasto",
    "COMPANY": "Firma",
    "CREDIT_CARD_NUMBER": "Karta płatnicza",
    "DATE": "Data",
    "DATE_OF_BIRTH": "Data urodzenia",
    "DOCUMENT_NUMBER": "Numer dokumentu",
    "EMAIL": "E-mail",
    "ETHNICITY": "Pochodzenie",
    "HEALTH": "Zdrowie",
    "IBAN": "IBAN",
    "ID_CARD": "Dowód osobisty",
    "JOB_TITLE": "Stanowisko",
    "NAME": "Imię",
    "NIP": "NIP",
    "PASSPORT": "Paszport",
    "PESEL": "PESEL",
    "PHONE": "Telefon",
    "POLITICAL_VIEW": "Poglądy polityczne",
    "REGON": "REGON",
    "RELATIVE": "Krewny",
    "RELIGION": "Wyznanie",
    "SCHOOL_NAME": "Szkoła / uczelnia",
    "SECRET": "Dane poufne",
    "SEX": "Płeć",
    "SEXUAL_ORIENTATION": "Orientacja seksualna",
    "SURNAME": "Nazwisko",
    "USERNAME": "Login",
}

#: Priorytet przy konflikcie nakładających się spanów o równym wyniku.
#: Wyższa liczba wygrywa. Identyfikator zawsze bije ogólną „datę" czy „firmę" —
#: PESEL zaklasyfikowany jako DATE nadal zostanie zredagowany, ale w raporcie
#: dla kontroli RODO chcemy widzieć, że to był PESEL.
LABEL_PRIORITY: Dict[str, int] = {
    **{label: 30 for label in CATEGORIES["IDENTIFIER"]},
    **{label: 30 for label in CATEGORIES["FINANCIAL"]},
    **{label: 25 for label in CATEGORIES["SENSITIVE"]},
    **{label: 20 for label in CATEGORIES["CONTACT"]},
    **{label: 18 for label in CATEGORIES["LOCATION"]},
    **{label: 15 for label in CATEGORIES["IDENTITY"]},
    **{label: 5 for label in CATEGORIES["PROFESSIONAL"]},
    "DATE": 1,
}


def normalize_label(raw: str) -> str:
    """Sprowadź etykietę z dowolnego źródła do formy kanonicznej.

    Przyjmuje ``B-PESEL``, ``I-pesel``, ``pesel`` → zwraca ``PESEL``.
    Etykiety nieznane przechodzą (użytkownik może dodać własny span
    z etykietą spoza słownika — nie jest to błąd).
    """
    if not raw:
        return "OTHER"
    label = raw.strip().upper().replace("-", "_")
    for prefix in ("B_", "I_", "E_", "S_"):
        if label.startswith(prefix):
            label = label[len(prefix):]
            break
    return label or "OTHER"


def category_of(label: str) -> str:
    return CATEGORY_OF.get(normalize_label(label), "OTHER")


def display_name(label: str) -> str:
    label = normalize_label(label)
    return LABEL_NAMES_PL.get(label, label.replace("_", " ").capitalize())


def is_article_9(label: str) -> bool:
    return normalize_label(label) in ARTICLE_9_LABELS


#: Odpowiedniki bez znaków diakrytycznych, do nadruku wewnątrz dokumentu.
_ASCII_FOLD = str.maketrans("ĄĆĘŁŃÓŚŹŻąćęłńóśźż", "ACELNOSZZacelnoszz")


def overlay_name(label: str) -> str:
    """Nazwa typu do nadruku NA dokumencie, bez polskich znaków.

    Wewnątrz PDF-a etykieta jest rysowana czcionką bazową (Helvetica), która
    nie ma Ę ani Ł — „[IMIĘ]" wychodzi z niej jako „[IMI?]". To samo dotyczy
    domyślnej czcionki bitmapowej Pillow przy obrazach. Zamiast dokładać do
    obrazu wdrożeniowego plik czcionki tylko po to, żeby napisać dwa słowa,
    składamy etykietę w ASCII: „[IMIE]" jest w pełni czytelne.

    Dotyczy WYŁĄCZNIE nadruku w pliku. W interfejsie i w raporcie zostaje
    ``display_name`` z pełną polszczyzną.
    """
    return display_name(label).upper().translate(_ASCII_FOLD)
