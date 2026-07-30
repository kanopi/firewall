# Firewall Performance Harness

Measures what the firewall costs a real PHP deployment, per plugin, under
concurrent load.

It exists to answer three questions:

1. **What does each plugin cost per request?**
2. **Does the firewall bottleneck PHP?** — i.e. does it reduce how many
   requests a fixed worker pool can serve?
3. **Is it still blocking what it should** while under that load?

The stack is nginx → php-fpm → the firewall, driven by [k6](https://k6.io/)
running in the same Docker network. Everything is containerised; the only host
dependency is Docker with Compose v2.

```
bin/run.sh                  # run everything
bin/run.sh crs all-on       # run named scenarios
PERF_VUS=500 bin/run.sh     # 500 concurrent virtual users
```

Results land in `results/`: `report.md`, `report.html`, `summary.json`, and one
raw k6 summary per scenario.

---

## How it works

### One container per scenario

Each scenario gets a **freshly recreated php-fpm container**. This is the single
most important property of the harness. opcache, the CRS rule cache, and the
php-fpm worker pool all hold state that would otherwise let whichever scenario
ran second inherit the first one's warm-up, and the resulting numbers would
describe run order rather than plugin cost.

After the container comes up, a warm-up phase runs at full load with its results
discarded, so the measured sample is steady state rather than cold start.

### Spoofing the client IP

A load generator has one source address, but the most interesting plugins —
`IpAddress`, `GeoLocation`, `Asn`, `RateLimit`, `AbuseIpdb`, `VulnerabilityScore`
— all key off the client IP. Benchmarking them against a single address would
measure one cache entry over and over.

So `app/prepend.php` is registered as PHP's `auto_prepend_file`. It runs before
every request and rewrites `$_SERVER['REMOTE_ADDR']` from the `X-Perf-Client-Ip`
header, letting one k6 container present thousands of distinct clients.

**Why a prepend rather than `X-Forwarded-For` + trusted proxies:** Symfony's
trusted-proxy handling is part of what we are measuring. Routing the spoof
through `X-Forwarded-For` would pull the firewall's own header parsing into the
measurement and change what plugins see depending on proxy configuration.
Rewriting `REMOTE_ADDR` before the app starts keeps the substitution invisible
to the code under test — as far as the firewall is concerned, that really is the
peer address.

The prepend is **inert unless `FIREWALL_PERF=1`**, which is set only by this
directory's `docker-compose.yml`, and it validates the header with
`FILTER_VALIDATE_IP` before using it.

### A fixed client population

`bin/generate-ip-pool.php` builds a seeded, reproducible set of addresses drawn
from real per-country allocations, written to `k6/ip-pool.json`. Fixed rather
than random because:

- **Rate limiting needs repeat visitors.** Random addresses give every request a
  fresh counter and nothing is ever limited.
- **AbuseIpdb's cache must be pre-seeded**, and you cannot seed an unbounded set.
- **Runs have to be comparable.** A different IP mix moves the GeoLocation and
  Asn block rates, and then a plugin looks slower when it was really handed
  different traffic.

The first 50 entries are the "burst slice", used only by the rate-limit traffic
profile — concentrating the flood on a small client set is what makes the
limiter actually trip.

### Measuring the firewall, not the plumbing

`app/index.php` reports its own timings as response headers, which k6 records as
metrics:

| Header | Meaning |
|---|---|
| `X-Fw-Boot-Us` | µs in `Firewall::create()` — config parse and plugin wiring |
| `X-Fw-Eval-Us` | µs in `Firewall::evaluate()` — the actual decision |
| `X-Fw-Total-Us` | µs for the whole PHP request |
| `X-Fw-Mem-Kb` | peak memory for the request |
| `X-Fw-Outcome` | `allow` / `block` / `challenge` / `error` |

This is what lets the report separate firewall cost from end-to-end latency.
Wall-clock alone cannot make that split: a request that spent 40ms waiting for a
free php-fpm worker and 2ms in the firewall looks identical to one that spent
42ms in the firewall.

---

## Scenarios

| Scenario | What it isolates |
|---|---|
| `baseline` | nginx + php-fpm + autoloader, **no firewall at all**. The floor. |
| `bootstrap` | Firewall wired up with **zero plugins**. The fixed cost of having it. |
| `ip-address` | CIDR matching against a realistically long block list |
| `url` | The two shipped URL presets — several hundred rules, many regexes |
| `user-agent` | `matomo/device-detector` parsing |
| `geolocation` | MaxMind City database lookup |
| `asn` | MaxMind ASN database lookup |
| `vulnerability-score` | Multi-factor scoring; performs both mmdb lookups |
| `abuseipdb` | Reputation check on the **cache-hit** path (see below) |
| `rate-limit` | Rate limiting with the backend I/O removed |
| `rate-limit-redis` | Rate limiting with genuinely shared counters |
| `crs` | OWASP Core Rule Set at paranoia 1 |
| `all-on` | Every plugin, ordered by weight |
| `all-on-redis` | `all-on` with Redis-backed rate limiting |

`baseline` and `bootstrap` are the two reference points. Subtracting `baseline`
from `bootstrap` gives the cost of the firewall existing; subtracting
`bootstrap` from a plugin scenario gives that plugin's own work, which is what
the report's per-plugin table shows.

`all-on` should measure **less** than the sum of the individual scenarios,
because cheap plugins short-circuit the chain before expensive ones run. The
report checks this and says so explicitly when it does not hold.

---

## What is deliberately not measured

**AbuseIPDB's cold path.** The plugin calls a third-party API on a cache miss.
Benchmarking that would measure AbuseIPDB's network latency, burn the daily
quota in seconds, and be rude. `bin/seed-abuseipdb-cache.php` pre-seeds the file
cache for every address in the pool, so every lookup is a hit — which is also
the path a production site takes for effectively all its traffic once warm. If
you need the miss-path number, measure your own API round-trip and add it; the
plugin fails open after `timeout` seconds regardless.

The seeder writes the cache format directly (`{cache_dir}/abuseipdb-{sha1(ip)}.json`).
If that format changes in `src/Plugins/AbuseIpdb.php`, the seeder goes stale and
the scenario starts making real network calls — which shows up immediately as a
collapse in that scenario's throughput. That is the intended failure signal.

**Durable storage backends.** `FileStorage` and `DatabaseStorage` back the
repeat-offender blocklist. They are not benchmarked because under sustained load
`FileStorage` accumulates every blocked address into one file that is re-read on
every request — a file that grows without bound for the length of the run. The
resulting curve describes a pathology, not a deployment. All scenarios use
`InMemoryStorage` for the durable blocklist; only the rate limiter's storage is
varied. Benchmarking durable storage properly needs its own harness with
bounded, pre-populated data sets.

**Challenge flows.** The interstitial and its solve/verify round trip are a
different shape of test — stateful, multi-request, browser-driven — and would
need their own harness.

---

## Interpreting the results

The report **never fails the build**. CircleCI runners are shared hardware; an
absolute latency gate would flake far more often than it would catch a real
regression. Judgement is left to whoever reads the artifact.

Numbers are comparable **only within a single run**. Compare each scenario to
the `baseline` row in the same table, never to a previous job's milliseconds.

- **"Does it bottleneck PHP?"** — read `Throughput vs baseline`. Above ~90% of
  baseline RPS, the firewall is not the constraint. Well below it, the firewall
  is consuming enough CPU per request to reduce what the same worker pool can
  serve.
- **A wide gap between `Firewall p95` and `End-to-end p95`** means the time is
  going somewhere other than the firewall — usually requests queueing for a
  worker. Raise `PERF_FPM_WORKERS` or lower `PERF_VUS`; if the gap closes, you
  found the pool size, not a firewall problem.
- **`Firewall p99` far above `Firewall p95`** points at a per-worker cache still
  warming. Relevant for CRS in particular.

### Absolute vs relative overhead

By default the app under test does no work — it is a hello-world, so the
firewall's *relative* cost looks as bad as it possibly can. The *absolute*
millisecond figures are real and transferable; the percentages are worst-case.

Set `PERF_APP_WORK_MS` to your application's median response time to get a
representative ratio:

```bash
PERF_APP_WORK_MS=120 bin/run.sh     # model a typical Drupal page
```

This burns CPU rather than sleeping, on purpose: sleeping would release the
processor and let far more workers run concurrently than a real PHP app ever
would, understating contention.

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PERF_VUS` | `200` | Virtual users at peak |
| `PERF_DURATION` | `45s` | Hold time at peak |
| `PERF_RAMP` | `15s` | Ramp-up time |
| `PERF_WARMUP` | `10` | Discarded warm-up seconds |
| `PERF_FPM_WORKERS` | `64` | php-fpm static worker count |
| `PERF_APP_WORK_MS` | `0` | Simulated app CPU per request |
| `PERF_PHP_VERSION` | `8.4` | PHP version to build |
| `PERF_IP_POOL_SIZE` | `5000` | Distinct client addresses |
| `PERF_HOST_PORT` | `8099` | Host port, for debugging by hand |
| `PERF_KEEP_UP` | `0` | Leave the stack running at exit |
| `GEOIP_LICENSE` | — | MaxMind key; without it the GeoIP scenarios skip |

`PERF_PHP_VERSION` defaults to 8.4 because that is the fastest supported
runtime, not because anything below it is unavailable — the lock installs on
8.1 through 8.5. Comparing two runtimes is a legitimate use of this harness:

```bash
PERF_PHP_VERSION=8.1 bin/run.sh bootstrap crs all-on
PERF_PHP_VERSION=8.4 bin/run.sh bootstrap crs all-on
```

Note that the two runs write to the same `results/` filenames, so copy the
directory aside between them.

---

## Validating scenarios without benchmarking

```bash
php tests/Performance/bin/validate-scenarios.php --skip-geoip
```

Loads every scenario config through the real `Firewall` and evaluates a probe
request per traffic profile, in a couple of seconds.

This matters more than it looks. `Firewall::create()` does **not** throw when a
config fails to load — it logs the failure and carries on with a partial
ruleset. A benchmark over a partial ruleset produces a complete, plausible set
of numbers for a firewall that was not running your rules. The validator treats
any config load error as a hard failure, and `bin/run.sh` gates on it.

Unlike the benchmark, this checks correctness rather than timing, so it is safe
to gate CI on and cheap enough to run on every PR.

---

## Debugging a scenario by hand

```bash
cd tests/Performance
PERF_SCENARIO=crs docker compose up -d
curl -i -H 'X-Perf-Client-Ip: 203.0.113.42' http://localhost:8099/
docker compose logs -f php
docker compose down
```

Every response carries the `X-Fw-*` timing headers, so a single curl tells you
what a scenario costs before committing to a full run.
