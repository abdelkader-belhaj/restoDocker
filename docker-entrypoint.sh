#!/bin/sh

# Définir la variable FIREBASE_CREDENTIALS_PATH avec le chemin dans le container
export FIREBASE_CREDENTIALS_PATH=/app/config/firebase/symfony07-firebase-adminsdk-fbsvc-7148aaa659.json

# Lancer le serveur PHP sur le port fourni par Render ou 8000 par défaut
php -S 0.0.0.0:${PORT:-8000} -t public
