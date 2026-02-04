from backend.detector import detect_sensitive_data


def test_detect_password():
    text = "Voici les accès : mot de passe: MonSuperMdp123!"
    entities = detect_sensitive_data(text)
    labels = [e["label"] for e in entities]
    assert "MOT_DE_PASSE" in labels


def test_detect_password_english():
    text = "Here are the credentials: password= Secret99"
    entities = detect_sensitive_data(text)
    labels = [e["label"] for e in entities]
    assert "MOT_DE_PASSE" in labels


def test_detect_password_mdp_with_context():
    """Test detection of 'mdp' abbreviation with multiple intermediate words."""
    text = "mon mdp est le suivant: admin123$"
    entities = detect_sensitive_data(text)
    labels = [e["label"] for e in entities]
    assert "MOT_DE_PASSE" in labels


def test_detect_password_variations():
    """Test various password patterns with intermediate words."""
    test_cases = [
        "mdp: secret123",
        "mdp est: password1",
        "mon mdp: test",
        "le mot de passe est: abc123",
        "voici le mdp du compte: xyz789",
    ]
    for text in test_cases:
        entities = detect_sensitive_data(text)
        labels = [e["label"] for e in entities]
        assert "MOT_DE_PASSE" in labels, f"Failed to detect password in: {text}"


def test_detect_login():
    text = "login: admin_user"
    entities = detect_sensitive_data(text)
    labels = [e["label"] for e in entities]
    assert "IDENTIFIANT" in labels


def test_detect_api_key():
    text = "Utilise cette clé : api_key= sk-abc123xyz456"
    entities = detect_sensitive_data(text)
    labels = [e["label"] for e in entities]
    assert "CLE_API" in labels


def test_detect_aws_key():
    text = "Ma clé AWS est AKIAIOSFODNN7EXAMPLE"
    entities = detect_sensitive_data(text)
    labels = [e["label"] for e in entities]
    assert "CLE_API_AWS" in labels


def test_detect_credit_card():
    text = "Ma carte est 4111 1111 1111 1111"
    entities = detect_sensitive_data(text)
    labels = [e["label"] for e in entities]
    assert "CARTE_BANCAIRE" in labels


def test_detect_iban():
    text = "Mon IBAN est FR76 1234 5678 9012 3456 7890 123"
    entities = detect_sensitive_data(text)
    labels = [e["label"] for e in entities]
    assert "IBAN" in labels


def test_detect_private_url():
    text = "Le serveur est sur http://192.168.1.100:8080/admin"
    entities = detect_sensitive_data(text)
    labels = [e["label"] for e in entities]
    assert "URL_PRIVEE" in labels


def test_detect_connection_string():
    text = "La base : postgres://admin:pass@db.internal:5432/prod"
    entities = detect_sensitive_data(text)
    labels = [e["label"] for e in entities]
    assert "CHAINE_CONNEXION" in labels


def test_detect_email():
    text = "Contactez jean.dupont@gmail.com"
    entities = detect_sensitive_data(text)
    labels = [e["label"] for e in entities]
    assert "EMAIL" in labels


def test_detect_phone():
    text = "Mon numéro est 06 12 34 56 78"
    entities = detect_sensitive_data(text)
    labels = [e["label"] for e in entities]
    assert "TELEPHONE" in labels


def test_severity_is_present():
    text = "password= test123"
    entities = detect_sensitive_data(text)
    assert len(entities) > 0
    assert all("severity" in e for e in entities)
    assert entities[0]["severity"] == "critique"


def test_clean_text():
    text = "Bonjour, la réunion est à 14h demain."
    entities = detect_sensitive_data(text)
    critical = [e for e in entities if e["severity"] == "critique"]
    assert len(critical) == 0


def test_multiple_sensitive_data():
    text = """
    Salut,
    Voici les accès au serveur :
    login: admin
    mot de passe: P@ssw0rd!
    URL: http://192.168.1.50:3000
    """
    entities = detect_sensitive_data(text)
    labels = [e["label"] for e in entities]
    assert "MOT_DE_PASSE" in labels
    assert "IDENTIFIANT" in labels
    assert "URL_PRIVEE" in labels
