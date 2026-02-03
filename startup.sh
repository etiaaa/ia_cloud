#!/bin/bash
set -e

# Log tout dans un fichier
exec > /var/log/startup-script.log 2>&1
echo "=== Démarrage du script: $(date) ==="

# Installer les dépendances système
apt-get update
apt-get install -y python3-pip python3-venv git curl

# Installer Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Démarrer Ollama en arrière-plan
systemctl enable ollama
systemctl start ollama

# Attendre qu'Ollama soit prêt
sleep 10

# Télécharger le modèle Mistral
ollama pull mistral

# Cloner le repo
cd /opt
git clone https://github.com/etiaaa/ia_cloud.git
cd ia_cloud

# Créer et activer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances Python
pip install -r requirements.txt

# Installer les modèles spaCy
python -m spacy download fr_core_news_md
python -m spacy download en_core_web_md

# Créer un service systemd pour l'application
cat > /etc/systemd/system/securemail.service << 'EOF'
[Unit]
Description=SecureMail FastAPI Application
After=network.target ollama.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ia_cloud
Environment="AI_BACKEND=ollama"
Environment="OLLAMA_URL=http://localhost:11434"
Environment="OLLAMA_MODEL=mistral"
ExecStart=/opt/ia_cloud/venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Activer et démarrer le service
systemctl daemon-reload
systemctl enable securemail
systemctl start securemail

echo "=== Script terminé: $(date) ==="
