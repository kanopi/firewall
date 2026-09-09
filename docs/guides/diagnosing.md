# Diagnosing an Installation

`bin/firewall-doctor` runs against the environment it is in and reports what is wrong with
it.

```bash
vendor/bin/firewall-doctor firewall.yml
```

```
  ✓ Config loads
      2 rules configured
  ! Trusted proxies could not be verified from the command line
      Request::setTrustedProxies() is called by your application bootstrap, which a
      command-line process does not run — so this cannot be checked from here.
      See docs/configuration/global.md#trusted-proxies
  ✗ The block list is running without its store
      Kanopi\Firewall\Storage\RedisStorage could not be reached: Connection refused
  ✗ GeoIP database not found
      /srv/geoip/GeoLite2-City.mmdb — every rule reading location or ASN will not match.

  2 errors, 1 warning, 1 check passed
```

| Option | |
|---|---|
| `--json` | A parseable document on stdout, and nothing else on it. |
| `--quiet` | Only warnings and errors. |

| Exit code | |
|---|---|
| `0` | Nothing wrong, **or warnings only** |
| `1` | At least one error — something configured is not happening |
| `2` | The configuration itself could not be read |

**A warning does not fail the command.** A stale GeoIP database should not block a deploy;
a rule that is not running should.

## It is not a config linter

It runs against the environment, not against the file: it opens the storage path, reaches
the database, reads the GeoIP database's mtime, and **builds every rule to find out whether
it can be built**. The same configuration diagnoses differently on a laptop and in
production, which is the point.

Two consequences worth knowing:

- **Building a rule opens its storage connection**, so reachability is tested rather than
  assumed. That is the cost, and it is why this belongs in a deploy hook or a status page
  rather than on a request path.
- **A table that does not exist yet is created**, because the declared schema lives on the
  class that owns it and there is no way to ask without building it.

Whether a rule can *ever* match is a static question, and belongs to
[`firewall-check --lint`](checking-requests.md#linting-a-config).

## What it checks

| | |
|---|---|
| **Config** | Every file loaded; anything that degraded on the way |
| **Trusted proxies** | Whether the client IP can be trusted — see below |
| **Rule sources** | Fetched, and still inside their `ttl` |
| **Rules** | Every configured rule constructed, via [`getFailedRules()`](error-handling.md#checking-that-every-rule-is-running) |
| **Backends** | Anything running without its store, via [`getDegradedBackends()`](error-handling.md#checking-that-a-backend-can-reach-its-server) |
| **Schema** | Tables behind what this release declares, via [`pendingSchemaChanges()`](schema-migrations.md) |
| **Storage** | File-backed paths that exist and can be written |
| **GeoIP** | Databases present, and how old they are |

Sources are checked **before** the rules, deliberately: building a rule is what fetches its
sources, so asking afterwards would report the cache this command had just warmed rather
than the one it found.

## The trusted-proxy check, and what it cannot tell you

Getting trusted proxies wrong is the sharpest edge in the product: every IP rule, allow list
and per-IP rate limit becomes spoofable through a forged `X-Forwarded-For`.

It is also the one thing this command **cannot settle from a terminal.**
`Request::setTrustedProxies()` is called by your application's bootstrap — a `settings.php`,
a middleware, a `functions.php` — and a CLI process runs none of that. So from the command
line it reports what it can see and says plainly that it cannot verify the rest:

```
  ! Trusted proxies could not be verified from the command line
      … Config asserts behind_proxy: true with require_trusted_proxies: true,
      so the firewall will refuse to start without them.
```

That is a warning rather than a pass **even when the configuration looks right**, because an
`ok` there would read as confirmation the site is not spoofable, which this cannot give you.

Run through a web SAPI — from a status page, where the bootstrap has run — and it answers
properly: an error when `behind_proxy: true` and no proxies are configured, a warning when
nothing is asserted either way.

## In a deploy pipeline

```bash
vendor/bin/firewall-doctor firewall.yml --quiet || exit 1
```

Or, to act on the detail:

```bash
vendor/bin/firewall-doctor firewall.yml --json > diagnosis.json
```

Errors are written to stderr and everything else to stdout, so a CI log shows the failures
even when stdout is captured — and `--json` keeps stdout parseable.

## From your own code

The command is a thin shell over `Kanopi\Firewall\Diagnostics\Doctor`, which is what an
integration with its own status report should use:

```php
use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Diagnostics\Doctor;

$findings = (new Doctor([__DIR__ . '/firewall.yml']))->run();

foreach ($findings as $finding) {
    // $finding->status is Diagnosis::OK | WARNING | ERROR
    $status->add($finding->status, $finding->title, $finding->detail);
}

$tally = Doctor::tally($findings);
```

Running it under a web SAPI is also what makes the trusted-proxy check meaningful, so a
status page gets a better answer than the terminal does.
