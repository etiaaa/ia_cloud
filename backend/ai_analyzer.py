import json
import os
import requests

# Configuration : Ollama (par défaut) ou Anthropic (fallback)
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
AI_BACKEND = os.getenv("AI_BACKEND", "ollama")  # "ollama" ou "anthropic"

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


def _parse_ai_response(result_text: str) -> dict:
    """Parse la réponse JSON du LLM, en nettoyant les éventuels backticks."""
    result_text = result_text.strip()
    if result_text.startswith("```"):
        result_text = result_text.split("\n", 1)[1]
        result_text = result_text.rsplit("```", 1)[0]
    return json.loads(result_text)


def _analyze_with_ollama(text: str) -> dict:
    """Analyse via Ollama (modèle local sur GCP)."""
    response = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={
            "model": OLLAMA_MODEL,
            "prompt": f"{SYSTEM_PROMPT}\n\nAnalyse cet email avant envoi :\n\n{text}",
            "stream": False,
            "options": {"temperature": 0.1},
        },
        timeout=400,
    )
    response.raise_for_status()
    result_text = response.json()["response"]
    return _parse_ai_response(result_text)


def _analyze_with_anthropic(text: str) -> dict:
    """Analyse via l'API Anthropic (Claude)."""
    from anthropic import Anthropic

    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2000,
        system=SYSTEM_PROMPT,
        messages=[
            {"role": "user", "content": f"Analyse cet email avant envoi :\n\n{text}"}
        ],
    )
    result_text = response.content[0].text
    return _parse_ai_response(result_text)


def analyze_with_ai(text: str) -> dict:
    """Analyse un email avec le LLM configuré (Ollama ou Anthropic)."""
    try:
        if AI_BACKEND == "anthropic" and ANTHROPIC_API_KEY:
            return _analyze_with_anthropic(text)
        else:
            return _analyze_with_ollama(text)
    except Exception as e:
        return {
            "entities": [],
            "risk_level": "erreur",
            "risk_summary": f"Erreur lors de l'analyse IA : {str(e)}",
        }


def merge_detections(regex_entities: list[dict], ai_result: dict) -> dict:
    """Fusionne les détections regex/NER avec l'analyse IA."""
    ai_entities = ai_result.get("entities", [])
    merged = list(regex_entities)

    regex_texts = {e["text"].lower().strip() for e in regex_entities}

    for ai_ent in ai_entities:
        ai_text = ai_ent.get("text", "").lower().strip()
        if ai_text and ai_text not in regex_texts:
            merged.append({
                "text": ai_ent.get("text", ""),
                "label": ai_ent.get("label", "SENSIBLE"),
                "start": -1,
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
