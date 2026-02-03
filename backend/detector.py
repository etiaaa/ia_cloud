import re
import spacy
from langdetect import detect

# Chargement des modèles spaCy
nlp_fr = spacy.load("fr_core_news_md")
nlp_en = spacy.load("en_core_web_md")

# Labels NER spaCy → labels DLP
SPACY_LABEL_MAP = {
    "PER": "NOM",
    "PERSON": "NOM",
}

# Patterns regex pour la détection de données sensibles
REGEX_PATTERNS = [
    # --- Identifiants & mots de passe ---
    {
        "label": "MOT_DE_PASSE",
        "pattern": re.compile(
            r"(?i)(?:mot\s*de\s*passe|password|mdp|pwd|pass)(?:\s+\w+)?\s*[:=]\s*\S+",
        ),
    },
    {
        "label": "IDENTIFIANT",
        "pattern": re.compile(
            r"(?i)(?:login|identifiant|username|user|utilisateur)(?:\s+\w+)?\s*[:=]\s*\S+",
        ),
    },
    {
        "label": "CODE_PIN",
        "pattern": re.compile(
            r"(?i)(?:code\s*(?:pin|secret|acc[eè]s|confidentiel))\s*[:=]\s*\S+",
        ),
    },
    # --- Clés API & tokens ---
    {
        "label": "CLE_API",
        "pattern": re.compile(
            r"(?i)(?:api[_\s-]?key|api[_\s-]?secret|token|secret[_\s-]?key|access[_\s-]?key)\s*[:=]\s*\S+",
        ),
    },
    {
        "label": "CLE_API_AWS",
        "pattern": re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    },
    {
        "label": "CLE_API_GENERIC",
        "pattern": re.compile(
            r"(?i)(?:sk|pk|rk)[_-](?:live|test|prod)[_-][a-zA-Z0-9]{20,}",
        ),
    },
    {
        "label": "TOKEN_JWT",
        "pattern": re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+"),
    },
    # --- Données financières ---
    {
        "label": "CARTE_BANCAIRE",
        "pattern": re.compile(
            r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
            r"[\s.-]?\d{4}[\s.-]?\d{4}[\s.-]?\d{1,4}\b",
        ),
    },
    {
        "label": "CVV",
        "pattern": re.compile(
            r"(?i)(?:cvv|cvc|csv|code\s*s[eé]curit[eé])\s*[:=]\s*\d{3,4}",
        ),
    },
    {
        "label": "IBAN",
        "pattern": re.compile(
            r"\b[A-Z]{2}\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{0,4}\b",
        ),
    },
    # --- Données personnelles sensibles ---
    {
        "label": "SECU",
        "pattern": re.compile(r"[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}"),
    },
    {
        "label": "EMAIL",
        "pattern": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    },
    {
        "label": "TELEPHONE",
        "pattern": re.compile(
            r"(?:\+33[\s.-]?|0)[1-9](?:[\s.-]?\d{2}){4}"
            r"|(?:\+\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}",
        ),
    },
    # --- Connexion & infra ---
    {
        "label": "URL_PRIVEE",
        "pattern": re.compile(
            r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\S*",
        ),
    },
    {
        "label": "ADRESSE_IP",
        "pattern": re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
        ),
    },
    {
        "label": "CHAINE_CONNEXION",
        "pattern": re.compile(
            r"(?i)(?:mongodb|postgres|mysql|redis|amqp|jdbc)://\S+",
        ),
    },
    # --- Mots-clés de confidentialité ---
    {
        "label": "SALAIRE",
        "pattern": re.compile(
            r"(?i)(?:salaire|r[eé]mun[eé]ration|paie)\s*[:=]?\s*\d[\d\s.,]*\s*(?:€|euros?|EUR)?",
        ),
    },
]

# Niveaux de criticité par label
SEVERITY = {
    "MOT_DE_PASSE": "critique",
    "IDENTIFIANT": "critique",
    "CODE_PIN": "critique",
    "CLE_API": "critique",
    "CLE_API_AWS": "critique",
    "CLE_API_GENERIC": "critique",
    "TOKEN_JWT": "critique",
    "CHAINE_CONNEXION": "critique",
    "CARTE_BANCAIRE": "critique",
    "CVV": "critique",
    "IBAN": "élevé",
    "SECU": "élevé",
    "SALAIRE": "élevé",
    "URL_PRIVEE": "moyen",
    "ADRESSE_IP": "moyen",
    "EMAIL": "faible",
    "TELEPHONE": "faible",
    "NOM": "faible",
}


def detect_language(text: str) -> str:
    try:
        lang = detect(text)
        return lang if lang in ("fr", "en") else "fr"
    except Exception:
        return "fr"


def detect_sensitive_data(text: str) -> list[dict]:
    """Détecte les données sensibles dans un texte (prévention fuite avant envoi email).

    Retourne une liste de { text, label, start, end, severity }.
    """
    entities = []
    seen_spans = set()

    # 1. Détection regex (prioritaire)
    for rule in REGEX_PATTERNS:
        for match in rule["pattern"].finditer(text):
            span = (match.start(), match.end())
            # Vérifier qu'il n'y a pas de chevauchement
            overlaps = any(
                not (span[1] <= s[0] or span[0] >= s[1]) for s in seen_spans
            )
            if not overlaps:
                seen_spans.add(span)
                entities.append({
                    "text": match.group(),
                    "label": rule["label"],
                    "start": match.start(),
                    "end": match.end(),
                    "severity": SEVERITY.get(rule["label"], "faible"),
                })

    # 2. Détection NER spaCy (noms de personnes)
    lang = detect_language(text)
    nlp = nlp_fr if lang == "fr" else nlp_en
    doc = nlp(text)

    for ent in doc.ents:
        if ent.label_ in SPACY_LABEL_MAP:
            span = (ent.start_char, ent.end_char)
            overlaps = any(
                not (span[1] <= s[0] or span[0] >= s[1]) for s in seen_spans
            )
            if not overlaps:
                label = SPACY_LABEL_MAP[ent.label_]
                seen_spans.add(span)
                entities.append({
                    "text": ent.text,
                    "label": label,
                    "start": ent.start_char,
                    "end": ent.end_char,
                    "severity": SEVERITY.get(label, "faible"),
                })

    entities.sort(key=lambda e: e["start"])
    return entities


# Alias pour compatibilité
detect_pii = detect_sensitive_data
