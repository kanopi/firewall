# PHP-FPM image for the performance harness.
#
# Deliberately close to a production PHP container: opcache on, no xdebug,
# no dev dependencies. Anything that would distort a latency measurement
# (profilers, coverage drivers, assertion overhead) is left out.
ARG PHP_VERSION=8.4
FROM php:${PHP_VERSION}-fpm-alpine

RUN apk add --no-cache --virtual .build-deps $PHPIZE_DEPS linux-headers \
    && pecl install redis \
    && docker-php-ext-enable redis \
    && docker-php-ext-install opcache pcntl \
    && apk del .build-deps \
    && apk add --no-cache git unzip

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app

# The firewall source is bind-mounted at run time; vendor/ is built into
# the image so a cold `docker compose up` is not also a composer install.
#
# `composer.lock*` is a glob on purpose: the lock is gitignored in this
# repository, so a fresh clone has none and a non-optional COPY would fail the
# build outright. When a lock is present it is honoured; when it is absent
# composer resolves against this image's PHP version, which is what you want
# for a benchmark anyway — the harness should measure the dependency set that
# this runtime would actually get.
COPY composer.json composer.lock* /app/
RUN composer install --no-dev --no-interaction --no-progress --prefer-dist --optimize-autoloader \
    && rm -rf /root/.composer

CMD ["php-fpm", "--nodaemonize"]
