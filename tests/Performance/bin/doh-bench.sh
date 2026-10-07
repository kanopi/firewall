#!/usr/bin/env bash
#
# Benchmark DnsOverHttpResolver under concurrency and a degraded provider (#480).
#
# #245 measured reverse-DNS verification with PHP's own lookups, stubbed at a fixed
# delay. The claim #475 makes for DnsOverHttpResolver is different, and needs curl in
# the loop to test: that the slowest request is capped by `timeout_ms`, whatever the
# provider does. A public provider can't be made slow on demand, so each case runs
# against fake-doh-server.py on 127.0.0.1, over TLS with a throwaway certificate,
# pinned the way a built-in provider pins its address.
#
# Usage:
#   tests/Performance/bin/doh-bench.sh [workers] [--public]
#
# --public also runs the healthy case against the real cloudflare and google
# providers. That depends on this machine's network, so it is reported apart.
#
# Needs php (with curl), python3 and openssl.

set -euo pipefail

workers=25
public=0

for arg in "$@"; do
  case "$arg" in
    --public) public=1 ;;
    *) workers="$arg" ;;
  esac
done

here="$(cd "$(dirname "$0")" && pwd)"
export FW_ROOT="$(cd "$here/../../.." && pwd)"
probe="$here/reverse-dns-probe.php"
server="$here/fake-doh-server.py"
work="$(mktemp -d "${TMPDIR:-/tmp}/fw-doh-bench.XXXXXX")"
port=18443
server_pid=""

cleanup() {
  [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# A certificate for doh.test, which the endpoint names; the pinned address makes it
# resolve to 127.0.0.1 without touching any resolver.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$work/key.pem" -out "$work/cert.pem" \
  -subj "/CN=doh.test" -addext "subjectAltName=DNS:doh.test" >/dev/null 2>&1

endpoint="https://doh.test:$port/dns-query?name={{ dns.name }}&type={{ dns.type }}"

start_server() {
  [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null && wait "$server_pid" 2>/dev/null || true
  python3 "$server" --cert "$work/cert.pem" --key "$work/key.pem" --port "$port" "$@" >>"$work/server.log" 2>&1 &
  server_pid=$!

  # Wait until it accepts connections, rather than for a guessed interval.
  for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      return
    fi
    sleep 0.1
  done

  echo "fake DoH server did not start" >&2
  exit 1
}

# run <label> <timeout-ms> <claim-wait-ms> [endpoint] [address] [cainfo]
run() {
  local label="$1" timeout="$2" wait="$3"
  local ep="${4:-$endpoint}" address="${5-127.0.0.1}" cainfo="${6-$work/cert.pem}"

  echo "== $label"
  FW_RDNS_RESOLVER=doh \
  FW_RDNS_DOH_ENDPOINT="$ep" \
  FW_RDNS_DOH_ADDRESS="$address" \
  FW_RDNS_DOH_TIMEOUT_MS="$timeout" \
  FW_RDNS_CLAIM_WAIT_MS="$wait" \
  FW_RDNS_CAINFO="$cainfo" \
    php "$probe" "$workers" 0 | grep -v '^resolver'
  echo
}

# The limit covers the whole request -- connecting and the TLS handshake included -- so
# a provider answering just under timeout_ms still runs out of time.
for delay in 0 50 140 290 400; do
  start_server --delay-ms "$delay"
  run "provider answers in ${delay} ms, timeout_ms 300" 300 0
done

start_server --mode hang
run "provider never answers, timeout_ms 300" 300 0

# A verification is two lookups, so waiting for another worker's verdict has to cover
# both, not one as with #245's stubbed resolver.
start_server --delay-ms 50
run "provider answers in 50 ms, verify_claim_wait_ms 100" 300 100
run "provider answers in 50 ms, verify_claim_wait_ms 200" 300 200

start_server --delay-ms 140
run "provider answers in 140 ms, verify_claim_wait_ms 400" 300 400

start_server --mode servfail
run "provider answers SERVFAIL" 300 0

start_server --mode many-ptr
run "PTR lists 15 invented googlebot.com names" 300 0

if [[ "$public" == 1 ]]; then
  run "public: cloudflare" 300 0 "https://cloudflare-dns.com/dns-query?name={{ dns.name }}&type={{ dns.type }}" 1.1.1.1 ""
  run "public: google" 300 0 "https://dns.google/resolve?name={{ dns.name }}&type={{ dns.type }}" 8.8.8.8 ""

  # One process, six verifications in a row and no verdict cache: the first pays for the
  # TLS handshake, the rest reuse the connection, as a PHP-FPM worker does.
  echo "== public: connection reuse, one process"
  php -r '
    require getenv("FW_ROOT") . "/vendor/autoload.php";
    $providers = [
      "cloudflare" => ["https://cloudflare-dns.com/dns-query?name={{ dns.name }}&type={{ dns.type }}", "1.1.1.1"],
      "google" => ["https://dns.google/resolve?name={{ dns.name }}&type={{ dns.type }}", "8.8.8.8"],
    ];
    foreach ($providers as $name => [$endpoint, $address]) {
      $resolver = new Kanopi\Firewall\Utility\ReverseDns\DnsOverHttpResolver(["endpoint" => $endpoint, "address" => $address]);
      $times = [];
      for ($i = 0; $i < 6; $i++) {
        $started = microtime(true);
        $resolver->reverse("66.249.66.1");
        $resolver->forward("crawl-66-249-66-1.googlebot.com", "A");
        $times[] = sprintf("%.1f", (microtime(true) - $started) * 1000);
      }
      printf("%-10s : %s ms per verification\n", $name, implode(" / ", $times));
    }'
fi
