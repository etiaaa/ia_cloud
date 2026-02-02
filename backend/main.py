import os
from fastapi import FastAPI, File, UploadFile, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional

from backend.detector import detect_sensitive_data
from backend.anonymizer import anonymize
from backend.report import generate_report, assess_risk
from backend.ai_analyzer import analyze_with_ai, merge_detections
from backend.file_parser import extract_text, is_supported

app = FastAPI(title="SecureMail - Anti-fuite de données")

AI_ENABLED = bool(os.getenv("ANTHROPIC_API_KEY"))


class TextRequest(BaseModel):
    text: str


class SensitiveEntity(BaseModel):
    text: str
    label: str
    start: int
    end: int
    severity: str
    reason: str = ""
    source: str = "regex"


class AnalyzeResponse(BaseModel):
    entities: list[SensitiveEntity]
    count: int
    risk_level: str
    risk_summary: str
    ai_enabled: bool
    attachment_name: str = ""
    attachment_text: str = ""


class AnonymizeResponse(BaseModel):
    original: str
    anonymized: str
    entities: list[SensitiveEntity]
    risk_level: str
    risk_summary: str


def full_analysis(text: str) -> dict:
    """Lance l'analyse complète : regex + IA."""
    regex_entities = detect_sensitive_data(text)
    for e in regex_entities:
        e.setdefault("reason", "")
        e.setdefault("source", "regex")

    if AI_ENABLED:
        ai_result = analyze_with_ai(text)
        merged = merge_detections(regex_entities, ai_result)
        return merged
    else:
        risk = assess_risk(regex_entities)
        return {
            "entities": regex_entities,
            "risk_level": risk,
            "risk_summary": "Analyse par règles uniquement (clé API Claude non configurée).",
        }


@app.post("/analyze")
async def analyze(
    text: str = Form(""),
    file: Optional[UploadFile] = File(None),
):
    combined_text = text
    attachment_name = ""
    attachment_text = ""

    # Extraire le texte de la pièce jointe si présente
    if file and file.filename:
        attachment_name = file.filename
        if is_supported(file.filename):
            content = await file.read()
            attachment_text = extract_text(file.filename, content)
            combined_text = f"{text}\n\n[PIÈCE JOINTE: {file.filename}]\n{attachment_text}"
        else:
            attachment_text = f"Format non supporté : {file.filename}"

    result = full_analysis(combined_text)

    return {
        "entities": result["entities"],
        "count": len(result["entities"]),
        "risk_level": result["risk_level"],
        "risk_summary": result.get("risk_summary", ""),
        "ai_enabled": AI_ENABLED,
        "attachment_name": attachment_name,
        "attachment_text": attachment_text,
    }


@app.post("/anonymize")
async def anonymize_text(
    text: str = Form(""),
    file: Optional[UploadFile] = File(None),
):
    combined_text = text
    attachment_text = ""

    if file and file.filename and is_supported(file.filename):
        content = await file.read()
        attachment_text = extract_text(file.filename, content)
        combined_text = f"{text}\n\n[PIÈCE JOINTE: {file.filename}]\n{attachment_text}"

    result = full_analysis(combined_text)
    regex_entities = [e for e in result["entities"] if e.get("start", -1) >= 0]
    anonymized = anonymize(combined_text, regex_entities)

    return {
        "original": combined_text,
        "anonymized": anonymized,
        "entities": result["entities"],
        "risk_level": result["risk_level"],
        "risk_summary": result.get("risk_summary", ""),
    }


@app.post("/report")
async def export_report(
    text: str = Form(""),
    file: Optional[UploadFile] = File(None),
):
    combined_text = text

    if file and file.filename and is_supported(file.filename):
        content = await file.read()
        attachment_text = extract_text(file.filename, content)
        combined_text = f"{text}\n\n[PIÈCE JOINTE: {file.filename}]\n{attachment_text}"

    result = full_analysis(combined_text)
    pdf_bytes = generate_report(combined_text, result["entities"])
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=rapport_securite.pdf"},
    )


# Servir le frontend
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
