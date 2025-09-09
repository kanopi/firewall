#!/bin/bash

set -e

# Config
APP_ROOT=$(pwd)
BUILD_DIR="/tmp/firewall"
PHP_VERSION_DEFAULT=$(php -r '$version=explode(".", phpversion()); echo sprintf("%s.%s", $version[0], $version[1]);' | tr -d '[:space:]' )
PHP_VERSION=${PHP_VERSION:-$PHP_VERSION_DEFAULT}
ZIP_FILE="/tmp/firewall-${PHP_VERSION}.zip"

# Step 1: Clean up previous builds
echo "Cleaning previous builds..."
rm -rf "$BUILD_DIR" "$ZIP_FILE" || true
mkdir -p "$BUILD_DIR"

# Step 2: Copy project files (excluding unwanted folders)
echo "Copying project files..."
rsync -av \
  --exclude-from=".circleci/exclude-build-files.txt" \
  "$APP_ROOT/" "$BUILD_DIR/"

# Include the load.php file as part of the build.
cp -f \
  "$APP_ROOT/.circleci/assets/load.php" "$BUILD_DIR/"

cd "$BUILD_DIR"

# Step 3: Install dependencies without dev packages
echo "Installing production dependencies with Composer..."
composer install --no-dev --optimize-autoloader
rm -rf composer.lock composer.json

# Step 4: Zip the build directory
echo "Creating zip archive..."
cd ..
zip -r "$ZIP_FILE" "firewall"

echo "✅ Build complete: $ZIP_FILE"
