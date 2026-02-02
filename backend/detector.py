import re
import spacy
from langdetect import detect

# Chargement des modèles spaCy
nlp_fr = spacy.load("fr_core_news_md")
nlp_en = spacy.load("en_core_web_md")

# Labels NER spaCy → labels PII
SPACY_LABEL_MAP = {
    "PER": "NOM",
    "PERSON": "NOM",
    "LOC": "ADRESSE",
    "GPE": "ADRESSE",
    "ORG": "ORGANISATION",
}

# Patterns regex pour les PII
REGEX_PATTERNS = [
    {
        "label": "EMAIL",
        "pattern": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    },
    {
        "label": "TELEPHONE",
        "pattern": re.compile(
            r"(?:\+33[\s.-]?|0)[1-9](?:[\s.-]?\d{2}){4}"  # FR
            r"|(?:\+\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}"  # International
        ),
    },
    {
        "label": "SECU",
        "pattern": re.compile(r"[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}"),
    },
    {
        "label": "IBAN",
        "pattern": re.compile(r"[A-Z]{2}\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{0,4}"),
    },
]


def detect_language(text: str) -> str:
    try:
        lang = detect(text)
        return lang if lang in ("fr", "en") else "fr"
    except Exception:
        return "fr"


def detect_pii(text: str) -> list[dict]:
    """Détecte les données personnelles (PII) dans un texte.

    Retourne une liste de { text, label, start, end }.
    """
    entities = []
    seen_spans = set()

    # 1. Détection regex (prioritaire)
    for rule in REGEX_PATTERNS:
        for match in rule["pattern"].finditer(text):
            span = (match.start(), match.end())
            if span not in seen_spans:
                seen_spans.add(span)
                entities.append({
                    "text": match.group(),
                    "label": rule["label"],
                    "start": match.start(),
                    "end": match.end(),
                })

    # 2. Détection NER spaCy
    lang = detect_language(text)
    nlp = nlp_fr if lang == "fr" else nlp_en
    doc = nlp(text)

    for ent in doc.ents:
        if ent.label_ in SPACY_LABEL_MAP:
            span = (ent.start_char, ent.end_char)
            # Éviter les doublons avec les regex
            overlaps = any(
                not (span[1] <= s[0] or span[0] >= s[1]) for s in seen_spans
            )
            if not overlaps:
                seen_spans.add(span)
                entities.append({
                    "text": ent.text,
                    "label": SPACY_LABEL_MAP[ent.label_],
                    "start": ent.start_char,
                    "end": ent.end_char,
                })

    # Tri par position
    entities.sort(key=lambda e: e["start"])
    return entities
