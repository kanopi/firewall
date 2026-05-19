# Demo container for the Lite Firewall.
#
# Build from the repo root so the COPY pulls the whole project:
#
#   docker build -t firewall-demo -f example/demo/Dockerfile .
#   docker run --rm -p 8000:8000 firewall-demo
#
# Then open http://localhost:8000.
FROM php:8.4-cli-alpine

WORKDIR /app

# composer + git for VCS-backed packages composer.lock might reference
RUN apk add --no-cache git unzip \
    && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction --no-progress --prefer-dist

COPY . .

EXPOSE 8000

# `sh -c` so the rm runs before the server starts; without it, exec form
# would skip the cleanup.
CMD ["sh", "-c", "rm -f /tmp/firewall-demo.data && php -S 0.0.0.0:8000 -t example/demo example/demo/index.php"]
