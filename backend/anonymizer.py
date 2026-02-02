from backend.detector import detect_sensitive_data

# Masques par type de donnée sensible
MASKS = {
    "MOT_DE_PASSE": "[MOT_DE_PASSE_MASQUÉ]",
    "IDENTIFIANT": "[IDENTIFIANT_MASQUÉ]",
    "CODE_PIN": "[CODE_MASQUÉ]",
    "CLE_API": "[CLÉ_API_MASQUÉE]",
    "CLE_API_AWS": "[CLÉ_AWS_MASQUÉE]",
    "CLE_API_GENERIC": "[CLÉ_MASQUÉE]",
    "TOKEN_JWT": "[TOKEN_MASQUÉ]",
    "CARTE_BANCAIRE": "[CB_MASQUÉE]",
    "CVV": "[CVV_MASQUÉ]",
    "IBAN": "[IBAN_MASQUÉ]",
    "SECU": "[N_SECU_MASQUÉ]",
    "EMAIL": "[EMAIL_MASQUÉ]",
    "TELEPHONE": "[TEL_MASQUÉ]",
    "NOM": "[NOM_MASQUÉ]",
    "URL_PRIVEE": "[URL_MASQUÉE]",
    "ADRESSE_IP": "[IP_MASQUÉE]",
    "CHAINE_CONNEXION": "[CONNEXION_MASQUÉE]",
    "SALAIRE": "[SALAIRE_MASQUÉ]",
}


def anonymize(text: str, entities: list[dict] | None = None) -> str:
    """Remplace les données sensibles détectées par des masques.

    Si entities n'est pas fourni, lance la détection automatiquement.
    """
    if entities is None:
        entities = detect_sensitive_data(text)

    result = text
    for ent in sorted(entities, key=lambda e: e["start"], reverse=True):
        mask = MASKS.get(ent["label"], f"[{ent['label']}_MASQUÉ]")
        result = result[:ent["start"]] + mask + result[ent["end"]:]

    return result
