import json
import os
from anthropic import Anthropic

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY", ""))

SYSTEM_PROMPT = """Tu es un expert en sécurité des données et conformité RGPD.
Ton rôle est d'analyser le contenu d'un email AVANT son envoi pour détecter TOUTE donnée sensible qui pourrait causer une fuite de données.

Tu dois détecter et signaler :
- Mots de passe, codes PIN, codes d'accès
- Clés API, tokens, secrets
- Numéros de carte bancaire, CVV
- IBAN, RIB, coordonnées bancaires
- Adresses de crypto-monnaie, clés privées crypto, seed phrases
- Montants financiers importants (surtout associés à des actifs)
- Numéros de sécurité sociale
- Adresses physiques complètes
- Noms de personnes
- Emails, numéros de téléphone
- URLs internes, adresses IP privées
- Chaînes de connexion base de données
- Informations salariales, médicales, judiciaires
- Tout autre information confidentielle ou sensible

Pour chaque donnée sensible trouvée, retourne un objet JSON avec :
- "text": le texte exact tel qu'il apparaît dans le message
- "label": le type de donnée (ex: MOT_DE_PASSE, CLE_CRYPTO, MONTANT_SENSIBLE, ADRESSE_PHYSIQUE, NOM, etc.)
- "severity": "critique", "élevé", "moyen" ou "faible"
- "reason": une courte explication de pourquoi c'est sensible

Évalue aussi le risque global du mail :
- "risk_level": "CRITIQUE - NE PAS ENVOYER", "ELEVE - ENVOI DECONSEILLE", "MOYEN - A VERIFIER", "FAIBLE - ATTENTION" ou "aucun"
- "risk_summary": un résumé en 1-2 phrases du risque principal

Réponds UNIQUEMENT avec du JSON valide, sans markdown, dans ce format exact :
{
  "entities": [...],
  "risk_level": "...",
  "risk_summary": "..."
}"""


def analyze_with_ai(text: str) -> dict:
    """Analyse un email avec Claude pour détecter les données sensibles."""
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": f"Analyse cet email avant envoi :\n\n{text}"}
            ],
        )

        result_text = response.content[0].text.strip()
        # Nettoyer si le modèle ajoute des backticks markdown
        if result_text.startswith("```"):
            result_text = result_text.split("\n", 1)[1]
            result_text = result_text.rsplit("```", 1)[0]

        result = json.loads(result_text)
        return result

    except Exception as e:
        return {
            "entities": [],
            "risk_level": "erreur",
            "risk_summary": f"Erreur lors de l'analyse IA : {str(e)}",
        }


def merge_detections(regex_entities: list[dict], ai_result: dict) -> dict:
    """Fusionne les détections regex/NER avec l'analyse IA.

    L'IA est prioritaire pour le risk_level et le risk_summary.
    Les entités sont fusionnées en évitant les doublons.
    """
    ai_entities = ai_result.get("entities", [])
    merged = list(regex_entities)

    # Textes déjà détectés par regex
    regex_texts = {e["text"].lower().strip() for e in regex_entities}

    for ai_ent in ai_entities:
        ai_text = ai_ent.get("text", "").lower().strip()
        # Ajouter seulement si pas déjà détecté par regex
        if ai_text and ai_text not in regex_texts:
            merged.append({
                "text": ai_ent.get("text", ""),
                "label": ai_ent.get("label", "SENSIBLE"),
                "start": -1,  # Position inconnue (détecté par IA)
                "end": -1,
                "severity": ai_ent.get("severity", "moyen"),
                "reason": ai_ent.get("reason", ""),
                "source": "ai",
            })

    return {
        "entities": merged,
        "risk_level": ai_result.get("risk_level", "aucun"),
        "risk_summary": ai_result.get("risk_summary", ""),
    }
