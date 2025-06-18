FROM php:8.2-fpm

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libzip-dev zip unzip git curl

# Install PHP extensions
RUN docker-php-ext-install pdo pdo_mysql mysqli

# Install and enable Redis extension
RUN pecl install redis \
    && docker-php-ext-enable redis

# Install and configure Xdebug
RUN pecl install xdebug \
    && docker-php-ext-enable xdebug

# Add custom php.ini for Xdebug settings
#COPY ./xdebug.ini /usr/local/etc/php/conf.d/xdebug.ini
RUN	rm -f "$PHP_INI_DIR/conf.d/docker-php-ext-xdebug.ini";
