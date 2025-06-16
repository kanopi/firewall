#!/bin/bash

set -e

# Config
APP_ROOT=$(pwd)
BUILD_DIR="/tmp/build"
ZIP_FILE="/tmp/firewall.zip"

# Step 1: Clean up previous builds
echo "Cleaning previous builds..."
rm -rf "$BUILD_DIR" "$ZIP_FILE" || true
mkdir -p "$BUILD_DIR"

# Step 2: Copy project files (excluding unwanted folders)
echo "Copying project files..."
rsync -av \
  --exclude-from=".circleci/exclude-build-files.txt" \
  "$APP_ROOT/" "$BUILD_DIR/"

cd "$BUILD_DIR"

# Step 3: Install dependencies without dev packages
echo "Installing production dependencies with Composer..."
composer install --no-dev --optimize-autoloader
rm -rf composer.lock composer.json

# Step 4: Zip the build directory
echo "Creating zip archive..."
zip -r "$ZIP_FILE" .

echo "✅ Build complete: $ZIP_FILE"
