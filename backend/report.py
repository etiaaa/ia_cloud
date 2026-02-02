import io
from collections import Counter
from fpdf import FPDF


RECOMMENDATIONS = {
    "MOT_DE_PASSE": "CRITIQUE : Ne jamais envoyer de mot de passe par email. Utilisez un gestionnaire de mots de passe ou un lien securise.",
    "IDENTIFIANT": "CRITIQUE : Les identifiants ne doivent pas transiter par email. Utilisez un canal securise.",
    "CODE_PIN": "CRITIQUE : Les codes PIN/secrets ne doivent jamais etre partages par email.",
    "CLE_API": "CRITIQUE : Les cles API doivent etre stockees dans un vault securise, jamais envoyees par email.",
    "CLE_API_AWS": "CRITIQUE : Cle AWS detectee. Revoquez-la immediatement si elle a ete exposee.",
    "CLE_API_GENERIC": "CRITIQUE : Cle d'API detectee. Ne jamais partager par email.",
    "TOKEN_JWT": "CRITIQUE : Token d'authentification detecte. Il donne acces a un compte/service.",
    "CHAINE_CONNEXION": "CRITIQUE : Chaine de connexion base de donnees detectee. Acces direct au systeme.",
    "CARTE_BANCAIRE": "CRITIQUE : Numero de carte bancaire detecte. Violation PCI-DSS.",
    "CVV": "CRITIQUE : Code de securite carte bancaire. Ne jamais transmettre par email.",
    "IBAN": "ELEVE : Coordonnees bancaires detectees. Risque de fraude.",
    "SECU": "ELEVE : Numero de securite sociale. Donnee hautement sensible.",
    "SALAIRE": "ELEVE : Information salariale detectee. Donnee confidentielle.",
    "URL_PRIVEE": "MOYEN : URL interne/privee detectee. Peut exposer l'infrastructure.",
    "ADRESSE_IP": "MOYEN : Adresse IP privee detectee. Peut exposer la topologie reseau.",
    "EMAIL": "FAIBLE : Adresse email detectee. Verifiez que le destinataire est le bon.",
    "TELEPHONE": "FAIBLE : Numero de telephone detecte. Donnee personnelle.",
    "NOM": "FAIBLE : Nom de personne detecte. Verifiez la necessite de le partager.",
}


def assess_risk(entities: list[dict]) -> str:
    """Evalue le risque global en se basant sur la sévérité des entités détectées."""
    if not entities:
        return "aucun"
    severities = [e.get("severity", "faible") for e in entities]
    if "critique" in severities:
        return "CRITIQUE - NE PAS ENVOYER"
    if "eleve" in severities or "élevé" in severities:
        return "ELEVE - ENVOI DECONSEILLE"
    if "moyen" in severities:
        return "MOYEN - A VERIFIER"
    return "FAIBLE - ATTENTION"


def generate_report(text: str, entities: list[dict]) -> bytes:
    """Génère un rapport PDF d'analyse de sécurité avant envoi. Retourne le contenu PDF en bytes."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Titre
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "Rapport de securite - Analyse avant envoi", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(8)

    # Verdict
    risk = assess_risk(entities)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, f"VERDICT : {risk}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Résumé
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Resume", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)

    label_counts = Counter(e["label"] for e in entities)
    severity_counts = Counter(e.get("severity", "faible") for e in entities)

    pdf.cell(0, 7, f"Donnees sensibles detectees : {len(entities)}", new_x="LMARGIN", new_y="NEXT")
    for sev in ["critique", "élevé", "moyen", "faible"]:
        count = severity_counts.get(sev, 0)
        if count:
            pdf.cell(0, 7, f"  - {sev.upper()} : {count}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Détail par type
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Detail des donnees detectees", new_x="LMARGIN", new_y="NEXT")
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
        rec = RECOMMENDATIONS.get(label, "Evaluer la necessite d'inclure cette donnee.")
        pdf.multi_cell(0, 7, f"  {rec}")
        pdf.ln(2)

    if not entities:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 7, "Aucune donnee sensible detectee. Envoi securise.", new_x="LMARGIN", new_y="NEXT")

    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()
