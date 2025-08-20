FROM php:8.2-fpm AS build



ENV COMPOSER_ALLOW_SUPERUSER=1

RUN apt-get update && apt-get install -y \
    git unzip libicu-dev libzip-dev zip \
    && docker-php-ext-install intl pdo zip

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app
COPY . .

# Configurer composer pour autoriser symfony/flex
RUN composer config --no-plugins allow-plugins.symfony/flex true

# Installer les dépendances et exécuter les commandes manuellement
RUN composer install --no-dev --optimize-autoloader && \
    php bin/console cache:clear --env=prod && \
    php bin/console cache:warmup --env=prod && \
    php bin/console assets:install public

# Étape finale (plus légère)
FROM php:8.2-fpm

RUN apt-get update && apt-get install -y \
    libicu-dev libzip-dev \
    && docker-php-ext-install intl pdo zip
    

WORKDIR /app
COPY --from=build /app .

RUN chown -R www-data:www-data /app

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8000

CMD ["/docker-entrypoint.sh"]
