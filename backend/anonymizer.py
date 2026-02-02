from backend.detector import detect_pii

# Masques par type de PII
MASKS = {
    "NOM": "[NOM]",
    "EMAIL": "[EMAIL]",
    "TELEPHONE": "[TELEPHONE]",
    "ADRESSE": "[ADRESSE]",
    "ORGANISATION": "[ORGANISATION]",
    "SECU": "[N_SECU]",
    "IBAN": "[IBAN]",
}


def anonymize(text: str, entities: list[dict] | None = None) -> str:
    """Remplace les PII détectées par des masques.

    Si entities n'est pas fourni, lance la détection automatiquement.
    """
    if entities is None:
        entities = detect_pii(text)

    # Remplacement en partant de la fin pour préserver les indices
    result = text
    for ent in sorted(entities, key=lambda e: e["start"], reverse=True):
        mask = MASKS.get(ent["label"], f"[{ent['label']}]")
        result = result[:ent["start"]] + mask + result[ent["end"]:]

    return result
