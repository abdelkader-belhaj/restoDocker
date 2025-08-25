#!/bin/bash
# === Startup script Symfony + Firebase ===

# Chemin du fichier attendu par Symfony
FIREBASE_PATH=/home/site/wwwroot/public/config/firebase/firebase-credentials.json

# Créer le dossier si inexistant
mkdir -p /home/site/wwwroot/public/config/firebase

# Écrire la variable d'environnement dans le fichier
echo "$FIREBASE_CREDENTIALS_JSON" > $FIREBASE_PATH
chmod 600 $FIREBASE_PATH

# Démarrer PHP-FPM et Nginx
service php8.2-fpm start
service nginx start

# Garder le conteneur actif
tail -f /dev/null
