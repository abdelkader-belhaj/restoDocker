#!/bin/sh
# Lancer PHP-FPM en arrière-plan
php-fpm &

# Lancer Nginx en premier plan
nginx -g "daemon off;"
