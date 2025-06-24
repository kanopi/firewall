#!/usr/bin/env bash

# Firewall Performance Test - Local Runner
# This script sets up and runs performance tests locally

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Firewall Performance Test Runner ===${NC}\n"

# Check if composer dependencies are installed
if [ ! -d "vendor" ]; then
    echo -e "${YELLOW}Installing composer dependencies...${NC}"
    composer install --quiet
fi

# Check for MaxMind license key
if [ -z "$MAXMIND_LICENSE_KEY" ]; then
    echo -e "${YELLOW}Warning: MAXMIND_LICENSE_KEY not set${NC}"
    echo "You can get a free license key at: https://www.maxmind.com/en/geolite2/signup"
    echo -e "Using example GeoIP databases if available...\n"
else
    # Download/update GeoIP databases
    GEOIP_DIR="/tmp/geoip"
    if [ ! -d "$GEOIP_DIR" ] || [ ! -f "$GEOIP_DIR/GeoLite2-City.mmdb" ]; then
        echo -e "${GREEN}Downloading GeoIP databases...${NC}"
        mkdir -p $GEOIP_DIR
        bash bin/update_geoip.sh "$MAXMIND_LICENSE_KEY" "$GEOIP_DIR"
    else
        echo -e "${GREEN}GeoIP databases found in $GEOIP_DIR${NC}"
        echo "To update, run: bash bin/update_geoip.sh \$MAXMIND_LICENSE_KEY $GEOIP_DIR"
    fi
    
    # Set environment variables
    export GEOIP_DB_PATH="$GEOIP_DIR/GeoLite2-City.mmdb"
    export ASN_DB_PATH="$GEOIP_DIR/GeoLite2-ASN.mmdb"
fi

# Check if test app is already running
if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "${RED}Error: Port 8080 is already in use${NC}"
    echo "Please stop the existing process or change the port"
    exit 1
fi

# Start test application in background
echo -e "${GREEN}Starting test application on http://localhost:8080${NC}"
php -S localhost:8080 tests/Performance/test-app.php > /tmp/firewall-test-app.log 2>&1 &
TEST_APP_PID=$!

# Wait for test app to start
sleep 2

# Check if test app started successfully
if ! kill -0 $TEST_APP_PID 2>/dev/null; then
    echo -e "${RED}Error: Failed to start test application${NC}"
    cat /tmp/firewall-test-app.log
    exit 1
fi

echo -e "${GREEN}Test application started (PID: $TEST_APP_PID)${NC}\n"

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    kill $TEST_APP_PID 2>/dev/null || true
    echo -e "${GREEN}Test application stopped${NC}"
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Set test URL
export FIREWALL_TEST_URL="http://localhost:8080"

# Run performance test
CONFIG_FILE="${1:-tests/Performance/benchmark-config.yml}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Error: Configuration file not found: $CONFIG_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}Running performance test with config: $CONFIG_FILE${NC}\n"

# Run the benchmark
php tests/Performance/run-benchmark.php --config="$CONFIG_FILE"

# Check results
if [ -f "reports/performance/results.json" ]; then
    echo -e "\n${GREEN}Checking success criteria...${NC}"
    php tests/Performance/check-criteria.php reports/performance/results.json
    
    echo -e "\n${GREEN}Reports generated:${NC}"
    echo "- HTML Report: reports/performance/report.html"
    echo "- JSON Data: reports/performance/results.json"
    
    # Try to open HTML report in browser (macOS/Linux)
    if command -v open >/dev/null 2>&1; then
        open reports/performance/report.html
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open reports/performance/report.html
    else
        echo -e "\n${YELLOW}Open reports/performance/report.html in your browser to view the detailed report${NC}"
    fi
else
    echo -e "${RED}Error: No results file generated${NC}"
    exit 1
fi