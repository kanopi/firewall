# Changelog

Every release, newest first, with a one-line summary and a link to its full notes.

The full notes are the real record — they explain *why* a change was made and what changes
on upgrade, and they are written per release on
[GitHub Releases](https://github.com/kanopi/firewall/releases). This file exists so that
"what changed between 2.12 and 2.19" is one page rather than twenty.

This project follows [Semantic Versioning](https://semver.org/). A patch release carries
fixes with no new configuration keys and no changed semantics for a value that already
works; anything needing a new key waits for a minor.

## [2.23.0](https://github.com/kanopi/firewall/releases/tag/v2.23.0) — 2026-09-09

Tell the operator what is wrong: a doctor command that diagnoses a live installation, a linter for the rules, a generator for the first config — and the five defects that building the first real consumer of 2.22.0's health APIs turned up in them.

## [2.22.0](https://github.com/kanopi/firewall/releases/tag/v2.22.0) — 2026-09-08

A store that can evict, and the caching that needs one: Redis for the block list, opt-in cross-request GeoIP caching on top of it, and database tables that migrate instead of asking to be dropped.

## [2.21.0](https://github.com/kanopi/firewall/releases/tag/v2.21.0) — 2026-09-08

The cost of a request, measured: the fixed work the firewall did on every one of them whether or not a rule matched.

## [2.20.0](https://github.com/kanopi/firewall/releases/tag/v2.20.0) — 2026-09-08

The gaps a patch could not carry — a preset whose own header explained how to bypass it, two documented behaviours the code did not have, and per-rule observe mode.

## [2.19.2](https://github.com/kanopi/firewall/releases/tag/v2.19.2) — 2026-09-07

Three fixes, and they share a shape: each is a place where the library did not hold a guarantee it already makes.

## [2.19.1](https://github.com/kanopi/firewall/releases/tag/v2.19.1) — 2026-09-07

One fix, and it exists because v2.19.0's own headline feature made the problem countable.

## [2.19.0](https://github.com/kanopi/firewall/releases/tag/v2.19.0) — 2026-09-07

Firewall events can now go to a database table, so what the firewall did to traffic becomes a query rather than a `grep`.

## [2.18.0](https://github.com/kanopi/firewall/releases/tag/v2.18.0) — 2026-09-06

Plugin rules can now come from lists that live somewhere else — a file, a URL, a feed someone else publishes — in whatever format they are already published in.

## [2.17.0](https://github.com/kanopi/firewall/releases/tag/v2.17.0) — 2026-09-03

Challenge rules can now pick their own provider, so the friction fits the rule rather than the deployment.

## [2.16.0](https://github.com/kanopi/firewall/releases/tag/v2.16.0) — 2026-08-30

One addition: storage can now say *when* a key's offenses happened, not only how many there were.

## [2.15.3](https://github.com/kanopi/firewall/releases/tag/v2.15.3) — 2026-08-29

One fix, and the last of three that together make `DatabaseStorage` round-trip what it is given. All three affect **database storage only** — `FileStorage` and `InMemoryStorage` were never…

## [2.15.2](https://github.com/kanopi/firewall/releases/tag/v2.15.2) — 2026-08-29

One fix, and the other half of the one in v2.15.1. Both affect **database storage only** — `FileStorage` and `InMemoryStorage` were never involved.

## [2.15.1](https://github.com/kanopi/firewall/releases/tag/v2.15.1) — 2026-08-29

One fix, for a defect that only reaches sites using **database storage together with a `response: challenge` rule**.

## [2.15.0](https://github.com/kanopi/firewall/releases/tag/v2.15.0) — 2026-08-19

Three fixes to where the firewall writes and what it tells you when it cannot. Relative paths in a config file now mean what the documentation has always said they mean, and a database it…

## [2.14.0](https://github.com/kanopi/firewall/releases/tag/v2.14.0) — 2026-08-09

Two new built-in challenge providers — Cloudflare Turnstile and Google reCAPTCHA — plus a fix for a crafted POST that turned into a 500 from the host application.

## [2.13.0](https://github.com/kanopi/firewall/releases/tag/v2.13.0) — 2026-08-03

`kanopi/firewall` now installs on Drupal 12, and brings 19 fewer packages with it.

## [2.12.0](https://github.com/kanopi/firewall/releases/tag/v2.12.0) — 2026-07-31

Configuration can now read a file from a path you write directly, without routing it through an environment variable.

## [2.11.1](https://github.com/kanopi/firewall/releases/tag/v2.11.1) — 2026-07-30

One fix, for a defect introduced by v2.11.0's user-agent caching.

## [2.11.0](https://github.com/kanopi/firewall/releases/tag/v2.11.0) — 2026-07-30

A performance and tooling release. The `UserAgent` plugin was recompiling a 1.7 MB regex corpus in every PHP process — **~618 ms**, paid again by every php-fpm worker on its first request. T

## [2.10.0](https://github.com/kanopi/firewall/releases/tag/v2.10.0) — 2026-07-29

One change with a config surface: `global.behind_proxy` lets an operator assert whether a proxy sits in front of the deployment, which is the fact the library cannot detect for itself. If…

## [2.9.0](https://github.com/kanopi/firewall/releases/tag/v2.9.0) — 2026-07-29

Two changes: a new AbuseIPDB reputation plugin, and the CRS plugin now requires `crs-engine` ^1.0 — the first version of the engine that actually enforces. **If you run the `Crs` plugin…

## [2.8.1](https://github.com/kanopi/firewall/releases/tag/v2.8.1) — 2026-07-27

A single-fix patch release. **If you enabled the `Crs` plugin in v2.8.0, upgrade immediately** — its verdict was inverted, so it blocked legitimate traffic and allowed the attacks it was…

## [2.8.0](https://github.com/kanopi/firewall/releases/tag/v2.8.0) — 2026-07-26

The largest release in the 2.x line: a full security audit of the library (14 findings across two passes), a new challenge/interstitial response type with two providers, OWASP CRS rule…

## [2.7.0](https://github.com/kanopi/firewall/releases/tag/v2.7.0) — 2026-01-25

Introduced the canonical `plugins:` array format, which supports multiple instances of the same plugin and explicit per-rule control.

## [2.6.0](https://github.com/kanopi/firewall/releases/tag/v2.6.0) — 2025-12-19

Configuration path handling, and a `{presets_dir}` token for cleaner preset references.

## [2.5.0](https://github.com/kanopi/firewall/releases/tag/v2.5.0) — 2025-12-19

Three security presets ready to include: malicious requests, malicious URLs, and rate limiting.

## [2.4.0](https://github.com/kanopi/firewall/releases/tag/v2.4.0) — 2025-12-17

Documentation updates.

## [2.3.0](https://github.com/kanopi/firewall/releases/tag/v2.3.0) — 2025-12-17

`$_SERVER` variables can be used alongside environment variables in `%env()%` substitution.

## [2.2.0](https://github.com/kanopi/firewall/releases/tag/v2.2.0) — 2025-12-17

Version constraint fixes.

## [2.1.1](https://github.com/kanopi/firewall/releases/tag/v2.1.1) — 2025-10-10

Validate that the port parameter is an integer.

## [2.1.0](https://github.com/kanopi/firewall/releases/tag/v2.1.0) — 2025-10-10

Configuration format evolution.

## [2.0.0](https://github.com/kanopi/firewall/releases/tag/v2.0.0) — 2025-10-09

First stable 2.x release.

## [2.0.0-beta2](https://github.com/kanopi/firewall/releases/tag/v2.0.0-beta2) — 2025-10-09

Updated `geoip2` version constraints.

## [2.0.0-beta1](https://github.com/kanopi/firewall/releases/tag/v2.0.0-beta1) — 2025-09-25

Beta release.

## [2.0.0-alpha2](https://github.com/kanopi/firewall/releases/tag/v2.0.0-alpha2) — 2025-07-08

**Breaking:** storage interface changed from v2.0.0-alpha1.

## [2.0.0-alpha1](https://github.com/kanopi/firewall/releases/tag/v2.0.0-alpha1) — 2025-06-25

Completely new code. No upgrade path from v1.

## [1.1.0](https://github.com/kanopi/firewall/releases/tag/v1.1.0) — 2025-05-06

Added a WordPress integration example.

## [1.0.0](https://github.com/kanopi/firewall/releases/tag/v1.0.0) — 2025-05-06

Initial release.
