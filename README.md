# SecureMail - Anti-fuite de Donnees (DLP)

> Analyse intelligente de vos emails avant envoi pour prevenir les fuites de donnees sensibles

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Table des matieres

- [Presentation](#presentation)
- [Fonctionnalites](#fonctionnalites)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Deploiement GCP](#deploiement-gcp)
- [Monitoring](#monitoring)
- [API Reference](#api-reference)
- [Securite](#securite)
- [Tests](#tests)
- [Contribution](#contribution)

---

## Presentation

**SecureMail** est une application web de prevention des fuites de donnees (DLP - Data Leak Prevention) qui analyse le contenu des emails avant leur envoi. Elle detecte automatiquement les informations sensibles telles que :

- Mots de passe et identifiants
- Cles API et tokens d'authentification
- Numeros de cartes bancaires et IBAN
- Numeros de securite sociale
- Donnees personnelles (noms, emails, telephones)
- URLs internes et adresses IP privees
- Chaines de connexion aux bases de donnees

### Cas d'usage

- **Conformite RGPD** : Prevenir l'envoi accidentel de donnees personnelles
- **Securite entreprise** : Detecter les credentials exposes dans les communications
- **Audit pre-envoi** : Verifier le contenu avant transmission externe

---

## Fonctionnalites

### Detection multi-couches

| Methode | Description | Precision |
|---------|-------------|-----------|
| **Regex** | 19 patterns pour credentials, finance, infrastructure | Rapide, deterministe |
| **NER (spaCy)** | Reconnaissance d'entites nommees (noms, lieux) | Contextuel |
| **IA (Ollama/Claude)** | Analyse semantique avancee | Comprehension profonde |

### Formats de fichiers supportes

- PDF (`.pdf`)
- Microsoft Word (`.docx`)
- Microsoft Excel (`.xlsx`, `.xls`)
- Texte brut (`.txt`)

### Niveaux de risque

| Niveau | Couleur | Action recommandee |
|--------|---------|-------------------|
| **CRITIQUE** | Rouge | Ne pas envoyer |
| **ELEVE** | Orange | Envoi deconseille |
| **MOYEN** | Bleu | A verifier |
| **FAIBLE** | Vert | Attention |

### Fonctions principales

1. **Analyse** : Detection et classification des donnees sensibles
2. **Anonymisation** : Masquage automatique des informations detectees
3. **Rapport PDF** : Generation de rapports de securite detailles

---

## Architecture

### Structure du projet

```
securemail/
├── backend/
│   ├── main.py           # Application FastAPI & endpoints
│   ├── detector.py       # Detection regex + NER
│   ├── ai_analyzer.py    # Integration Ollama/Anthropic
│   ├── anonymizer.py     # Masquage des donnees
│   ├── file_parser.py    # Extraction texte (PDF, DOCX, XLSX)
│   └── report.py         # Generation rapports PDF
├── frontend/
│   ├── index.html        # Interface utilisateur
│   ├── style.css         # Styles (theme sombre)
│   └── script.js         # Logique client
├── tests/
│   └── test_detector.py  # Tests unitaires
├── requirements.txt      # Dependances Python
└── startup.sh           # Script de deploiement Linux
```

### Flux de donnees

```
┌─────────────────┐
│   Utilisateur   │
│  (Texte/Fichier)│
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│                    BACKEND                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ File Parser │→ │  Detector   │→ │ AI Analyzer │ │
│  │ (PDF,DOCX)  │  │ (Regex+NER) │  │ (Ollama)    │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
│                          │                         │
│                          ▼                         │
│              ┌─────────────────────┐               │
│              │   Merge & Assess    │               │
│              │   (Risk Level)      │               │
│              └─────────────────────┘               │
└─────────────────────────┬───────────────────────────┘
                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
   ┌──────────┐    ┌──────────┐    ┌──────────┐
   │ /analyze │    │/anonymize│    │ /report  │
   │ (JSON)   │    │ (JSON)   │    │  (PDF)   │
   └──────────┘    └──────────┘    └──────────┘
```

### Stack technique

| Composant | Technologie |
|-----------|-------------|
| Backend | FastAPI + Uvicorn |
| NLP | spaCy (fr_core_news_md, en_core_web_md) |
| IA Locale | Ollama + Mistral |
| IA Cloud | Anthropic Claude |
| PDF | fpdf2, PyPDF2 |
| Documents | python-docx, openpyxl |
| Frontend | HTML5, CSS3, JavaScript (Vanilla) |

---

## Installation

### Prerequis

- Python 3.10+
- pip
- Git

### Installation locale

```bash
# 1. Cloner le repository
git clone https://github.com/etiaaa/ia_cloud.git
cd ia_cloud

# 2. Creer l'environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou: venv\Scripts\activate  # Windows

# 3. Installer les dependances
pip install -r requirements.txt

# 4. Telecharger les modeles spaCy
python -m spacy download fr_core_news_md
python -m spacy download en_core_web_md

# 5. Lancer l'application
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### Installation avec Ollama (IA locale)

```bash
# Installer Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Demarrer le service
sudo systemctl start ollama

# Telecharger le modele Mistral
ollama pull mistral

# Configurer les variables d'environnement
export AI_BACKEND=ollama
export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=mistral
```

---

## Configuration

### Variables d'environnement

| Variable | Defaut | Description |
|----------|--------|-------------|
| `AI_BACKEND` | `ollama` | Backend IA : `ollama` ou `anthropic` |
| `OLLAMA_URL` | `http://localhost:11434` | URL de l'API Ollama |
| `OLLAMA_MODEL` | `mistral` | Modele Ollama a utiliser |
| `ANTHROPIC_API_KEY` | - | Cle API Anthropic (si backend=anthropic) |

### Exemple de configuration

```bash
# Mode Ollama (IA locale)
export AI_BACKEND=ollama
export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=mistral

# Mode Anthropic (IA cloud)
export AI_BACKEND=anthropic
export ANTHROPIC_API_KEY=sk-ant-xxxxx
```

---

## Deploiement GCP

### Architecture Cloud

![Architecture GCP SecureMail](docs/architecture-gcp.png)

### Composants GCP utilises

| Service | Configuration |
|---------|--------------|
| **Compute Engine** | VM e2-medium, Ubuntu 22.04 |
| **Managed Instance Group** | Auto-scaling (CPU 60%) |
| **Load Balancer** | HTTP externe, port 80 |
| **Health Check** | HTTP sur port 8000, path `/` |
| **Firewall** | Regles pour health checks GCP |

### Deploiement pas a pas

#### 1. Creer le template d'instance

```bash
gcloud compute instance-templates create securemail-template \
    --machine-type=e2-medium \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size=50GB \
    --tags=http-server,https-server \
    --metadata-from-file=startup-script=startup.sh
```

#### 2. Creer le Managed Instance Group

```bash
gcloud compute instance-groups managed create securemail-mig \
    --template=securemail-template \
    --size=1 \
    --zone=us-central1-c
```

#### 3. Configurer l'auto-scaling

```bash
gcloud compute instance-groups managed set-autoscaling securemail-mig \
    --zone=us-central1-c \
    --min-num-replicas=1 \
    --max-num-replicas=5 \
    --target-cpu-utilization=0.6
```

#### 4. Creer le health check

```bash
gcloud compute health-checks create http securemail-health \
    --port=8000 \
    --request-path=/
```

#### 5. Creer le backend service

```bash
gcloud compute backend-services create securemail-backend \
    --protocol=HTTP \
    --health-checks=securemail-health \
    --global

gcloud compute backend-services add-backend securemail-backend \
    --instance-group=securemail-mig \
    --instance-group-zone=us-central1-c \
    --global
```

#### 6. Creer le load balancer

```bash
# URL map
gcloud compute url-maps create securemail-lb \
    --default-service=securemail-backend

# HTTP proxy
gcloud compute target-http-proxies create securemail-proxy \
    --url-map=securemail-lb

# Forwarding rule
gcloud compute forwarding-rules create securemail-frontend \
    --global \
    --target-http-proxy=securemail-proxy \
    --ports=80
```

#### 7. Configurer le firewall pour health checks

```bash
gcloud compute firewall-rules create allow-health-check \
    --network=default \
    --action=allow \
    --direction=ingress \
    --source-ranges=130.211.0.0/22,35.191.0.0/16 \
    --rules=tcp:8000
```

### Service systemd

Pour que l'application demarre automatiquement au boot :

```ini
# /etc/systemd/system/securemail.service
[Unit]
Description=SecureMail App
After=network.target

[Service]
User=konanetia_anaelle
WorkingDirectory=/home/konanetia_anaelle/ia_cloud
Environment="AI_BACKEND=ollama"
Environment="OLLAMA_URL=http://localhost:11434"
Environment="OLLAMA_MODEL=mistral"
ExecStart=/home/konanetia_anaelle/ia_cloud/venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable securemail
sudo systemctl start securemail
```

---

## Monitoring

### Architecture du monitoring

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│   VM Instance   │ ──► │   Cloud Monitoring   │ ──► │  Notifications  │
│  (+ Ops Agent)  │     │    (Collecte)        │     │  (Email, SMS)   │
└─────────────────┘     └──────────────────────┘     └─────────────────┘
```

### Composants

| Composant | Role |
|-----------|------|
| **Ops Agent** | Collecte les metriques detaillees depuis la VM |
| **Cloud Monitoring** | Stocke et analyse les metriques |
| **Alerting Policies** | Definit les conditions de declenchement |
| **Notification Channels** | Envoie les alertes (email, Slack, etc.) |

### Installation de l'agent Ops

L'agent Ops permet de collecter des metriques detaillees (CPU, RAM, disque, processus) depuis l'interieur de la VM.

```bash
# Telecharger et installer l'agent
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
sudo bash add-google-cloud-ops-agent-repo.sh --also-install

# Verifier le statut
sudo systemctl status google-cloud-ops-agent
```

### Types de metriques

| Type | Source | Agent requis |
|------|--------|--------------|
| **CPU utilization** | Hyperviseur GCP | Non |
| **CPU utilization (OS reported)** | Systeme d'exploitation | Oui |
| **Memory utilization** | Systeme d'exploitation | Oui |
| **Disk I/O** | Systeme d'exploitation | Oui |
| **Network traffic** | Hyperviseur GCP | Non |

### Configurer une alerte CPU

#### 1. Creer un canal de notification

```bash
# Via la console : Monitoring > Alerting > Edit notification channels
# Ajouter votre email
```

#### 2. Creer la politique d'alerte

```bash
# Via gcloud CLI
gcloud alpha monitoring policies create \
    --display-name="CPU SecureMail > 80%" \
    --condition-display-name="VM CPU High" \
    --condition-filter='resource.type="gce_instance" AND metric.type="agent.googleapis.com/cpu/utilization"' \
    --condition-threshold-value=0.8 \
    --condition-threshold-comparison=COMPARISON_GT \
    --condition-threshold-duration=60s \
    --notification-channels=<CHANNEL_ID>
```

Ou via la console Google Cloud :

1. Aller dans **Monitoring > Alerting > Create Policy**
2. **Add Condition** :
   - Resource type : `VM Instance`
   - Metric : `CPU utilization (OS reported)`
   - Threshold : `> 80%`
3. **Add Notification Channel** : Selectionner votre email
4. **Name** : `CPU SecureMail > 80%`
5. **Create Policy**

### Tester l'alerte

```bash
# Se connecter a la VM
gcloud compute ssh securemail-mig-xxxx --zone=us-central1-c

# Installer stress (si pas present)
sudo apt-get install -y stress

# Lancer un test de charge CPU (3 minutes)
stress --cpu 2 --timeout 180
```

Apres environ 1-2 minutes, vous devriez recevoir un email d'alerte.

### Alertes recommandees pour SecureMail

| Alerte | Condition | Severite |
|--------|-----------|----------|
| CPU elevee | CPU > 80% pendant 1 min | Warning |
| Memoire elevee | RAM > 85% pendant 2 min | Warning |
| Disque plein | Disk > 90% | Critical |
| Service down | Health check echoue 3x | Critical |
| Latence API | Latence > 2s pendant 5 min | Warning |

### Dashboard personnalise

Creer un dashboard dans Cloud Monitoring pour visualiser :

- Utilisation CPU en temps reel
- Utilisation memoire
- Requetes par seconde sur l'API
- Latence des endpoints
- Nombre d'instances actives (auto-scaling)

```bash
# Exemple : voir les metriques CPU via gcloud
gcloud monitoring metrics list --filter="metric.type=agent.googleapis.com/cpu/utilization"
```

---

## API Reference

### Endpoints

#### POST /analyze

Analyse le texte et/ou fichier pour detecter les donnees sensibles.

**Request:**
```bash
curl -X POST http://localhost:8000/analyze \
  -F "text=Mon mot de passe est: Secret123" \
  -F "file=@document.pdf"
```

**Response:**
```json
{
  "entities": [
    {
      "text": "mot de passe est: Secret123",
      "label": "MOT_DE_PASSE",
      "start": 4,
      "end": 31,
      "severity": "critique",
      "reason": "Mot de passe expose en clair",
      "source": "regex"
    }
  ],
  "count": 1,
  "risk_level": "CRITIQUE - NE PAS ENVOYER",
  "risk_summary": "Mot de passe detecte. Cet email ne doit pas etre envoye.",
  "ai_enabled": true,
  "attachment_name": "document.pdf",
  "attachment_text": "Contenu extrait du PDF..."
}
```

#### POST /anonymize

Masque les donnees sensibles detectees.

**Request:**
```bash
curl -X POST http://localhost:8000/anonymize \
  -F "text=Email: jean@example.com, Tel: 06 12 34 56 78"
```

**Response:**
```json
{
  "original": "Email: jean@example.com, Tel: 06 12 34 56 78",
  "anonymized": "Email: [EMAIL_MASQUE], Tel: [TEL_MASQUE]",
  "entities": [...],
  "risk_level": "FAIBLE - ATTENTION",
  "risk_summary": "Coordonnees personnelles detectees"
}
```

#### POST /report

Genere un rapport PDF de securite.

**Request:**
```bash
curl -X POST http://localhost:8000/report \
  -F "text=Contenu a analyser" \
  --output rapport.pdf
```

**Response:** Fichier PDF binaire

---

## Securite

### Types de donnees detectees

| Categorie | Patterns | Severite |
|-----------|----------|----------|
| **Credentials** | mot de passe, password, login, identifiant | CRITIQUE |
| **Cles API** | api_key, token, AWS keys (AKIA...), JWT | CRITIQUE |
| **Finance** | Cartes bancaires (Visa, MC, Amex), IBAN, CVV | CRITIQUE |
| **Identite** | Numero securite sociale, salaire | ELEVE |
| **Infrastructure** | URLs privees, IPs internes, connection strings | MOYEN |
| **Contact** | Emails, telephones | FAIBLE |
| **Noms** | Detection via NER (spaCy) | FAIBLE |

### Patterns Regex

```python
# Exemples de patterns detectes
MOT_DE_PASSE: "mot de passe: Secret123"
CLE_API_AWS: "AKIAIOSFODNN7EXAMPLE"
TOKEN_JWT: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
CARTE_BANCAIRE: "4111 1111 1111 1111"
IBAN: "FR76 1234 5678 9012 3456 7890 123"
SECU: "1 85 12 75 108 042 36"
URL_PRIVEE: "http://192.168.1.100:8080/admin"
CHAINE_CONNEXION: "postgres://user:pass@db.internal:5432/mydb"
```

### Bonnes pratiques

1. **Pas de stockage** : Les donnees analysees ne sont jamais persistees
2. **Traitement en memoire** : Les fichiers sont traites et supprimes
3. **Protection XSS** : Echappement HTML systematique cote frontend
4. **HTTPS recommande** : Utiliser un certificat SSL en production

---

## Tests

### Lancer les tests

```bash
# Installer pytest
pip install pytest

# Executer les tests
pytest tests/test_detector.py -v
```

### Couverture des tests

```
tests/test_detector.py
├── test_detect_password           # Detection mot de passe FR
├── test_detect_password_english   # Detection password EN
├── test_detect_login              # Detection identifiants
├── test_detect_api_key            # Detection cles API
├── test_detect_aws_key            # Detection cles AWS
├── test_detect_credit_card        # Detection cartes bancaires
├── test_detect_iban               # Detection IBAN
├── test_detect_private_url        # Detection URLs privees
├── test_detect_connection_string  # Detection connection strings
├── test_detect_email              # Detection emails
├── test_detect_phone              # Detection telephones
├── test_severity_is_present       # Verification champ severity
├── test_clean_text                # Texte sans donnees sensibles
└── test_multiple_sensitive_data   # Donnees multiples
```

### Exemple de test

```python
def test_detect_password():
    text = "Voici le mot de passe: MonSecret123!"
    result = detect_sensitive_data(text)
    assert len(result) > 0
    assert result[0]["label"] == "MOT_DE_PASSE"
    assert result[0]["severity"] == "critique"
```

---

## Utilisation

### Interface Web

1. Acceder a `http://localhost:8000` (ou IP du load balancer)
2. Coller le contenu de l'email dans la zone de texte
3. Optionnel : Ajouter une piece jointe (PDF, Word, Excel)
4. Cliquer sur **"Verifier la securite"**
5. Consulter le resultat avec :
   - Banniere de risque (couleur selon severite)
   - Texte avec donnees sensibles surlignees
   - Liste detaillee des entites detectees
6. Options supplementaires :
   - **"Masquer les donnees"** : Obtenir une version anonymisee
   - **"Rapport PDF"** : Telecharger un rapport de securite

### Ligne de commande

```bash
# Analyser un texte
curl -X POST http://localhost:8000/analyze \
  -F "text=Mon email est test@example.com"

# Analyser un fichier
curl -X POST http://localhost:8000/analyze \
  -F "file=@document.pdf"

# Obtenir une version anonymisee
curl -X POST http://localhost:8000/anonymize \
  -F "text=Password: secret123"

# Generer un rapport PDF
curl -X POST http://localhost:8000/report \
  -F "text=Contenu sensible" \
  --output rapport.pdf
```

---

## Contribution

### Workflow de developpement

1. Fork le repository
2. Creer une branche feature : `git checkout -b feature/ma-fonctionnalite`
3. Commiter les changements : `git commit -m "Add: nouvelle fonctionnalite"`
4. Pousser la branche : `git push origin feature/ma-fonctionnalite`
5. Ouvrir une Pull Request

### Ajouter un nouveau pattern de detection

1. Editer `backend/detector.py`
2. Ajouter le pattern dans `REGEX_PATTERNS`
3. Definir la severite dans `SEVERITY_MAP`
4. Ajouter le masque dans `backend/anonymizer.py`
5. Ajouter la recommandation dans `backend/report.py`
6. Ecrire un test dans `tests/test_detector.py`

### Standards de code

- Python : PEP 8
- Commits : Conventional Commits
- Documentation : Docstrings Google style

---

## Roadmap

- [ ] Plugin navigateur
- [ ] Plugin mail
- [ ] Patterns personnalisables par organisation

---

## Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de details.

---

