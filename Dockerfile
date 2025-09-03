# Utiliser PHP-FPM officiel
FROM php:8.2-fpm

# Installer dépendances PHP et Nginx
RUN apt-get update && apt-get install -y \
    git unzip libicu-dev libonig-dev libzip-dev libpng-dev nginx \
    && docker-php-ext-install intl pdo pdo_mysql zip gd opcache

# Installer Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Définir répertoire de travail
WORKDIR /var/www

# Copier projet Symfony
COPY . .

# Installer vendors Symfony
RUN composer install --no-dev --optimize-autoloader --no-interaction --prefer-dist

# Copier configuration Nginx
COPY ./nginx.conf /etc/nginx/conf.d/default.conf

# Copier script de démarrage
COPY ./start.sh /start.sh
RUN chmod +x /start.sh

# Exposer le port 80
EXPOSE 80

# Lancer le conteneur
CMD ["/start.sh"]
