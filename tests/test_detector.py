import pytest
from backend.detector import detect_pii


def test_detect_email():
    text = "Contactez-moi à jean.dupont@email.com pour plus d'infos."
    entities = detect_pii(text)
    labels = [e["label"] for e in entities]
    assert "EMAIL" in labels


def test_detect_phone_fr():
    text = "Mon numéro est 06 12 34 56 78."
    entities = detect_pii(text)
    labels = [e["label"] for e in entities]
    assert "TELEPHONE" in labels


def test_detect_iban():
    text = "Mon IBAN est FR76 1234 5678 9012 3456 7890 123."
    entities = detect_pii(text)
    labels = [e["label"] for e in entities]
    assert "IBAN" in labels


def test_detect_secu():
    text = "Son numéro de sécurité sociale est 1 85 05 78 006 084 36."
    entities = detect_pii(text)
    labels = [e["label"] for e in entities]
    assert "SECU" in labels


def test_detect_name_fr():
    text = "Jean Dupont travaille chez Airbus à Toulouse."
    entities = detect_pii(text)
    labels = [e["label"] for e in entities]
    assert "NOM" in labels


def test_no_pii():
    text = "Le temps est beau aujourd'hui."
    entities = detect_pii(text)
    assert len(entities) == 0 or all(
        e["label"] not in ("EMAIL", "TELEPHONE", "SECU", "IBAN") for e in entities
    )


def test_multiple_pii():
    text = "Marie Martin (marie@test.fr, 01 23 45 67 89) habite à Lyon."
    entities = detect_pii(text)
    assert len(entities) >= 2
