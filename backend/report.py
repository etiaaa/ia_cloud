import io
from collections import Counter
from fpdf import FPDF


RISK_THRESHOLDS = {
    "faible": 3,
    "moyen": 7,
}

RECOMMENDATIONS = {
    "NOM": "Pseudonymiser ou supprimer les noms de personnes avant stockage.",
    "EMAIL": "Chiffrer les adresses email et limiter l'accès aux données.",
    "TELEPHONE": "Ne stocker les numéros de téléphone que si strictement nécessaire.",
    "ADRESSE": "Limiter la précision des adresses (ville au lieu de l'adresse complète).",
    "ORGANISATION": "Vérifier si le nom de l'organisation est lié à une personne physique.",
    "SECU": "CRITIQUE : ne jamais stocker de numéros de sécurité sociale en clair.",
    "IBAN": "CRITIQUE : chiffrer les données bancaires, accès restreint obligatoire.",
}


def assess_risk(entities: list[dict]) -> str:
    count = len(entities)
    has_critical = any(e["label"] in ("SECU", "IBAN") for e in entities)
    if has_critical or count > RISK_THRESHOLDS["moyen"]:
        return "élevé"
    if count > RISK_THRESHOLDS["faible"]:
        return "moyen"
    return "faible"


def generate_report(text: str, entities: list[dict]) -> bytes:
    """Génère un rapport PDF d'analyse RGPD. Retourne le contenu PDF en bytes."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Titre
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "Rapport de conformite RGPD", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(8)

    # Résumé
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Resume", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)

    risk = assess_risk(entities)
    label_counts = Counter(e["label"] for e in entities)

    pdf.cell(0, 7, f"Nombre de PII detectees : {len(entities)}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Niveau de risque : {risk}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Détail par type
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Detail par type", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)

    for label, count in label_counts.most_common():
        pdf.cell(0, 7, f"  - {label} : {count} occurrence(s)", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Recommandations
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Recommandations", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)

    detected_labels = set(e["label"] for e in entities)
    for label in detected_labels:
        rec = RECOMMENDATIONS.get(label, "Evaluer la necessite de conserver cette donnee.")
        pdf.multi_cell(0, 7, f"  [{label}] {rec}")
        pdf.ln(2)

    if not entities:
        pdf.cell(0, 7, "Aucune donnee personnelle detectee.", new_x="LMARGIN", new_y="NEXT")

    # Export en bytes
    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()
