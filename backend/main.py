from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

from backend.detector import detect_pii
from backend.anonymizer import anonymize
from backend.report import generate_report

app = FastAPI(title="RGPD Compliance Assistant")


class TextRequest(BaseModel):
    text: str


class PIIEntity(BaseModel):
    text: str
    label: str
    start: int
    end: int


class AnalyzeResponse(BaseModel):
    entities: list[PIIEntity]
    count: int


class AnonymizeResponse(BaseModel):
    original: str
    anonymized: str
    entities: list[PIIEntity]


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: TextRequest):
    entities = detect_pii(req.text)
    return AnalyzeResponse(entities=entities, count=len(entities))


@app.post("/anonymize", response_model=AnonymizeResponse)
def anonymize_text(req: TextRequest):
    entities = detect_pii(req.text)
    anonymized = anonymize(req.text, entities)
    return AnonymizeResponse(original=req.text, anonymized=anonymized, entities=entities)


@app.post("/report")
def export_report(req: TextRequest):
    entities = detect_pii(req.text)
    pdf_bytes = generate_report(req.text, entities)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=rapport_rgpd.pdf"},
    )


# Servir le frontend
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
