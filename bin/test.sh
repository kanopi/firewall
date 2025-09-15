#!/bin/bash

set -e

PHP_IMAGE=${PHP_IMAGE:-"cimg/php"}
PHP_VERSION=${PHP_VERSION:-"8.2"}

CONTAINER_NAME="firewall-test-${PHP_VERSION}"

export DOCKER_CLI_HINTS=false

echo "Checking For Left Over Tests"
docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME" && docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

echo "Pull New Version"
docker pull -q $PHP_IMAGE:${PHP_VERSION} >/dev/null 2>&1

echo "Start Container"
docker run --rm -it -d --name $CONTAINER_NAME $PHP_IMAGE:${PHP_VERSION} bash -c 'tail -f /dev/null' >/dev/null 2>&1

echo "Check Directory"
PROJECT_ROOT=$(docker exec -it $CONTAINER_NAME bash -c 'pwd' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
docker cp ./ $CONTAINER_NAME:${PROJECT_ROOT} >/dev/null 2>&1

docker exec -it $CONTAINER_NAME bash -c "rm -rf composer.lock vendor || true"  >/dev/null 2>&1

# Unset set on error
set +e

echo "Running Composer Install"
docker exec -it $CONTAINER_NAME bash -c "composer -q install"

if [[ $? != 0 ]]; then
  echo "Error running composer install"
  exit 1
fi

echo ""
echo "Running Tests..."

echo "Running Quality..."
docker exec -it $CONTAINER_NAME bash -c "composer run check:code"

echo "Running PHPStan..."
docker exec -it $CONTAINER_NAME bash -c "composer run check:security"

echo "Running Rector..."
docker exec -it $CONTAINER_NAME bash -c "composer run check:rector"

#echo "Running PHPUnit..."
#docker exec -it $CONTAINER_NAME bash -c "composer run phpunit"

# Set back exit on error
set -e

echo ""

echo "Cleaning up test artifacts"
docker rm -f $CONTAINER_NAME >/dev/null 2>&1 || true