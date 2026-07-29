#!/usr/bin/env bash
#
# Run the firewall performance benchmark.
#
# For each scenario this script recreates the php-fpm container with that
# scenario selected, waits for it to answer, warms it, then points k6 at it
# for a fixed duration. Recreating the container between scenarios is the
# whole reason the numbers are comparable: opcache, the CRS rule cache, and
# php-fpm's worker pool all carry state that would otherwise let whichever
# scenario ran second inherit the first one's warm-up.
#
# Usage:
#   bin/run.sh                          # every scenario, default load
#   bin/run.sh crs all-on               # just these two
#   PERF_VUS=500 PERF_DURATION=2m bin/run.sh
#
# Environment:
#   PERF_VUS            Virtual users at peak            (default 200)
#   PERF_DURATION       Hold time at peak                (default 45s)
#   PERF_RAMP           Ramp-up time                     (default 15s)
#   PERF_WARMUP         Warm-up seconds before measuring (default 10)
#   PERF_FPM_WORKERS    php-fpm static worker count      (default 64)
#   PERF_APP_WORK_MS    Simulated app CPU per request    (default 0)
#   PERF_PHP_VERSION    PHP version to build             (default 8.4)
#   PERF_IP_POOL_SIZE   Distinct client IPs              (default 5000)
#   PERF_KEEP_UP        Leave the stack running at exit  (default 0)
#   GEOIP_LICENSE       MaxMind key; without it the GeoIP scenarios are skipped
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERF_DIR="$(dirname "$HERE")"
REPO_ROOT="$(cd "$PERF_DIR/../.." && pwd)"

cd "$PERF_DIR"

export PERF_VUS="${PERF_VUS:-200}"
export PERF_DURATION="${PERF_DURATION:-45s}"
export PERF_RAMP="${PERF_RAMP:-15s}"
export PERF_FPM_WORKERS="${PERF_FPM_WORKERS:-64}"
export PERF_APP_WORK_MS="${PERF_APP_WORK_MS:-0}"
export PERF_PHP_VERSION="${PERF_PHP_VERSION:-8.4}"
export PERF_IP_HEADER="${PERF_IP_HEADER:-X-Perf-Client-Ip}"
PERF_WARMUP="${PERF_WARMUP:-10}"
PERF_IP_POOL_SIZE="${PERF_IP_POOL_SIZE:-5000}"
PERF_KEEP_UP="${PERF_KEEP_UP:-0}"

# Ordered deliberately: baseline and bootstrap first so the reference points
# exist before anything is compared to them, then cheap plugins to dear ones,
# then the combined configurations.
ALL_SCENARIOS=(
    baseline
    bootstrap
    ip-address
    url
    user-agent
    geolocation
    asn
    vulnerability-score
    abuseipdb
    rate-limit
    rate-limit-redis
    crs
    all-on
    all-on-redis
)

# Scenarios that cannot run without a MaxMind database.
GEOIP_SCENARIOS=(geolocation asn vulnerability-score all-on all-on-redis)

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

contains() {
    local needle="$1"; shift
    local item
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

command -v docker >/dev/null 2>&1 || die "docker is required"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"

# ---------------------------------------------------------------------------
# Which scenarios to run
# ---------------------------------------------------------------------------

if [[ $# -gt 0 ]]; then
    SCENARIOS=("$@")
    for s in "${SCENARIOS[@]}"; do
        if [[ "$s" != "baseline" && ! -f "scenarios/${s}.yml" ]]; then
            die "unknown scenario '${s}' (no scenarios/${s}.yml)"
        fi
    done
else
    SCENARIOS=("${ALL_SCENARIOS[@]}")

    # Guard against a scenario file being added without being added to the
    # ordered list above, which would otherwise silently never be measured.
    for f in scenarios/*.yml; do
        name="$(basename "$f" .yml)"
        if ! contains "$name" "${ALL_SCENARIOS[@]}"; then
            warn "scenarios/${name}.yml is not in ALL_SCENARIOS and will not run"
        fi
    done
fi

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

cleanup() {
    local code=$?
    if [[ "$PERF_KEEP_UP" == "1" ]]; then
        log "PERF_KEEP_UP=1, leaving the stack running (docker compose down to stop it)"
    else
        log "Tearing down"
        docker compose down --remove-orphans >/dev/null 2>&1 || true
    fi
    exit "$code"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Build and fixtures
# ---------------------------------------------------------------------------

log "Building the php image (PHP ${PERF_PHP_VERSION})"
docker compose build php

log "Generating the client IP pool (${PERF_IP_POOL_SIZE} addresses)"
docker compose run --rm seed \
    /app/tests/Performance/bin/generate-ip-pool.php \
    --size="$PERF_IP_POOL_SIZE" \
    --out=/app/tests/Performance/k6/ip-pool.json

# GeoIP databases. bin/update_geoip.sh already exists in the repo for CI, so
# reuse it rather than reimplementing the MaxMind download here.
GEOIP_READY=0
if docker compose run --rm --no-deps --entrypoint sh seed \
        -c 'test -f /geoip/GeoLite2-City.mmdb && test -f /geoip/GeoLite2-ASN.mmdb && test -f /geoip/GeoLite2-Country.mmdb' \
        >/dev/null 2>&1; then
    log "GeoIP databases already present in the volume"
    GEOIP_READY=1
elif [[ -n "${GEOIP_LICENSE:-}" ]]; then
    log "Downloading GeoIP databases"
    if docker compose run --rm --no-deps --entrypoint sh seed \
            -c "apk add --no-cache bash curl >/dev/null && bash /app/bin/update_geoip.sh '${GEOIP_LICENSE}' /geoip/"; then
        GEOIP_READY=1
    else
        warn "GeoIP download failed"
    fi
else
    warn "GEOIP_LICENSE is not set"
fi

if [[ "$GEOIP_READY" != "1" ]]; then
    warn "Skipping the GeoIP-dependent scenarios: ${GEOIP_SCENARIOS[*]}"
    warn "Set GEOIP_LICENSE to a MaxMind key to include them."
    FILTERED=()
    for s in "${SCENARIOS[@]}"; do
        contains "$s" "${GEOIP_SCENARIOS[@]}" || FILTERED+=("$s")
    done
    SCENARIOS=("${FILTERED[@]}")
fi

[[ ${#SCENARIOS[@]} -gt 0 ]] || die "no scenarios left to run"

log "Seeding the AbuseIPDB cache"
docker compose run --rm seed \
    /app/tests/Performance/bin/seed-abuseipdb-cache.php \
    --pool=/app/tests/Performance/k6/ip-pool.json \
    --dir=/perf-cache/abuseipdb

# Redis comes up before validation, not after, so the two Redis-backed
# scenarios are actually validated rather than skipped for want of a reachable
# server — they are the ones whose storage config is easiest to get wrong.
log "Starting redis"
docker compose up -d redis

# Cheap and worth doing before committing twenty minutes to a benchmark: a
# scenario whose config half-failed to load still produces a full set of
# plausible numbers, for a firewall that was not running the rules you think
# it was. Validation is a correctness check, not a timing one, so unlike the
# benchmark it is safe to treat as a hard gate.
log "Validating scenario configs"
VALIDATE_ARGS=()
[[ "$GEOIP_READY" == "1" ]] || VALIDATE_ARGS+=(--skip-geoip)
docker compose run --rm --no-deps -e REDIS_HOST=redis -e REDIS_PORT=6379 seed \
    /app/tests/Performance/bin/validate-scenarios.php "${VALIDATE_ARGS[@]+"${VALIDATE_ARGS[@]}"}" \
    || die "scenario validation failed; not benchmarking a broken configuration"

mkdir -p results
rm -f results/*.json

log "Starting nginx"
docker compose up -d nginx

# ---------------------------------------------------------------------------
# Per-scenario measurement
# ---------------------------------------------------------------------------

# --no-deps on every k6 invocation is load-bearing, not tidiness. Without it
# `docker compose run` reconciles the k6 service's depends_on chain and can
# recreate the php container mid-scenario — silently discarding the warm-up
# and, worse, restarting it with whatever PERF_SCENARIO the environment held
# at that moment. The measurement would still produce numbers; they would just
# belong to a different scenario than the filename claims.
wait_for_app() {
    local scenario="$1" attempt body
    for attempt in $(seq 1 60); do
        body="$(docker compose run --rm --no-deps --entrypoint sh k6 -c \
            "wget -q -S -O /dev/null http://nginx/ 2>&1 | grep -i 'X-Fw-Scenario' || true" 2>/dev/null || true)"
        if [[ "$body" == *"$scenario"* ]]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

RUN_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
FAILED_SCENARIOS=()

for scenario in "${SCENARIOS[@]}"; do
    log "Scenario: ${scenario}"

    export PERF_SCENARIO="$scenario"

    # --force-recreate is what guarantees a cold, identical starting state.
    #
    # nginx is recreated alongside php, not left running: it resolves the
    # `php` upstream once at startup and caches the address, so a recreated
    # php container leaves nginx holding a stale IP and answering 502. That
    # failure is intermittent — Docker sometimes reuses the address — which
    # makes it exactly the kind of bug that shows up as one inexplicably bad
    # scenario in a nightly run.
    docker compose up -d --force-recreate php nginx

    if ! wait_for_app "$scenario"; then
        warn "scenario '${scenario}' never reported itself healthy; skipping"
        docker compose logs --tail=40 php >&2 || true
        FAILED_SCENARIOS+=("$scenario")
        continue
    fi

    # Warm up without recording. The first requests each worker serves pay for
    # opcache compilation and, for CRS, rule-cache construction. Those are real
    # costs but they are one-off, and letting them into the sample would make
    # p99 a measure of cold start rather than of steady-state behaviour.
    if [[ "$PERF_WARMUP" -gt 0 ]]; then
        log "  warming up for ${PERF_WARMUP}s"
        docker compose run --rm --no-deps \
            -e PERF_SCENARIO="warmup-${scenario}" \
            -e PERF_DURATION="${PERF_WARMUP}s" \
            -e PERF_RAMP="2s" \
            k6 run --quiet /scripts/load.js >/dev/null 2>&1 || true
        rm -f "results/warmup-${scenario}.json"
    fi

    log "  measuring: ${PERF_VUS} VUs, ${PERF_RAMP} ramp, ${PERF_DURATION} hold"
    if ! docker compose run --rm --no-deps k6 run /scripts/load.js; then
        warn "k6 exited non-zero for '${scenario}'; results may be partial"
        FAILED_SCENARIOS+=("$scenario")
    fi
done

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

log "Generating the report"
docker compose run --rm seed \
    /app/tests/Performance/bin/report.php \
    --results=/app/tests/Performance/results \
    --started="$RUN_STARTED" \
    --php-version="$PERF_PHP_VERSION" \
    --vus="$PERF_VUS" \
    --workers="$PERF_FPM_WORKERS" \
    --app-work-ms="$PERF_APP_WORK_MS"

if [[ ${#FAILED_SCENARIOS[@]} -gt 0 ]]; then
    warn "scenarios with problems: ${FAILED_SCENARIOS[*]}"
fi

log "Done. Results in ${PERF_DIR}/results/"
