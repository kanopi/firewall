# Changelog

Every release, newest first, with a one-line summary and a link to its full notes.

The full notes are the real record — they explain *why* a change was made and what changes
on upgrade, and they are written per release on
[GitHub Releases](https://github.com/kanopi/firewall/releases). This file exists so that
"what changed between 2.12 and 2.19" is one page rather than twenty.

This project follows [Semantic Versioning](https://semver.org/). A patch release carries
fixes with no new configuration keys and no changed semantics for a value that already
works; anything needing a new key waits for a minor.

## [2.37.0](https://github.com/kanopi/firewall/releases/tag/v2.37.0) — 2026-10-02

The challenge, block and lockdown pages can carry a site's own wording, language and colours, or be its own HTML. `challenge.page` sets the interstitial's `lang`, `title`, `heading`, `intro`, `button`, `error_message`, `styles` and `stylesheet` (#451). `global.block_page` and `global.lockdown_page` serve a block or a lockdown as an HTML page on the same card, with a strict `Content-Security-Policy`, instead of one line of text. A rule can carry its own `metadata.block_page` and `metadata.banning_message`, `{{block.status}}` and `{{block.rule}}` are new placeholders, and `banning_json` answers an API client with JSON (#452). A `template` replaces the built-in document with the site's own, filled through `{{page.message}}`, `{{page.heading}}`, `{{page.title}}` and `{{page.lang}}` (#456). Every colour on those pages is a `--fw-*` custom property, so `:root { --fw-accent: … }` themes all three (#454). The compiled config cache now hits on web requests: under PHP-FPM, `$_SERVER` and `getenv()` carry per-request values, and fingerprinting them made every request re-parse and rewrite it (#445). A config whose `%env()%` reads a request-scoped value such as `SERVER_NAME` is parsed per request instead of cached, so one host is never served another's config (#467). The cache can also live in a PSR-6 pool through `Config::setConfigCachePool()`, or be kept off disk with `KANOPI_FIREWALL_CONFIG_FILE_CACHE` (#447). `presets/storage-pantheon.yml` decodes `PRESSFLOW_SETTINGS` for every connection value; only `dbname` did, so on Pantheon it connected to `db:3306` and the firewall failed open (#446). The database log handler writes a flush as multi-row `INSERT`s (#460), indexes `firewall_log` by rule in both orders (#458), and prunes in batches of `prune_batch_size`, enough of them per winning flush to keep up with what it wrote, up to `prune_max_batches` (#459, #464). Its own warnings now reach the PHP error log. **On upgrade:** run `bin/firewall-migrate` to add the new `firewall_log` indexes to an existing table, and `bin/firewall-log-prune` once if the table has a backlog.

## [2.36.1](https://github.com/kanopi/firewall/releases/tag/v2.36.1) — 2026-09-30

Equality on a number now compares as a number. `port`, `query_count` (new in 2.36.0), `asn` and GeoLocation's database fields resolve to an integer or float, and every rule value is text, whether written in YAML or substituted from a rule source. Compared strictly, `port:8443` never matched port 8443, `port@in:8443,9443` and `query_count.f@equals:4` never matched, and `not_equals` matched every request, so a block rule on `query_count.f@not_equals:0` refused everybody. `equals`, `not_equals` and `in` now read the rule's value as a number when the request's value is one, and two strings still compare exactly, so `query.page:01` doesn't match `?page=1` (#443). Also: `ChallengeRequiredException::getRenderContext()` is typed `array<string, mixed>`, as the provider interface is, because `notices` is a list. The old `array<string, string>` told static analysis a host's `is_array()` check could never be true (#442).

## [2.36.0](https://github.com/kanopi/firewall/releases/tag/v2.36.0) — 2026-09-30

`query_count.<name>` is how many values the client sent for one query parameter, so a rule can cap facet crawling: `query_count.f@greater_than:3`. Bots walk search pages through every facet combination (`?f[0]=…&f[1]=…&f[2]=…&f[3]=…`), each one an uncacheable faceted search, and there was no rule a bot couldn't get past by changing how it wrote the URL. A list under `query.f` resolves to nothing by design, PHP keeps only the last of `f=a&f=b`, and the regex workaround missed sparse keys, repeated names and anything interleaved. The count is taken from the raw query string, so `f[0]=`, `f[]=`, sparse and named keys, encoded brackets and repeated `f=` all count the same. `query_count` alone counts every parameter. A "Stop facet crawling" recipe recommends `response: challenge`, since a `block` rule also bans the address, and `presets/drupal.yml` carries a commented-out entry for Search API facets.

## [2.35.1](https://github.com/kanopi/firewall/releases/tag/v2.35.1) — 2026-09-30

Two holes in the rate-limit lint that 2.35.0 added, both found in review. An earlier entry that *covers* a later one hid it without a word, as long as the two paths weren't identical. That meant a wildcard (`/log*` before `/login`) or, since paths now ignore case, a case variant (`/login` before `/LOGIN`), and the linter then warned that the path was limited by identity but not by address, the reverse of what the firewall did. It's now reported as the unreachable entry, naming the one that takes the request. And a rule with `enable: false` counted as address coverage, so switching the address limit off silenced the very warning that said brute-force protection was gone. Lint only: nothing the firewall enforces changes.

## [2.35.0](https://github.com/kanopi/firewall/releases/tag/v2.35.0) — 2026-09-30

Eight reports from the WordPress and Drupal integrations, and each one was a place where a rule said one thing and did another. **ASN rules never matched:** MaxMind returns the number as an integer and every rule value is text, so `asn:16509`, the documented example, never fired, and `asn@not_equals:` matched every visitor, the named network included. They now compare as a number, with an optional `AS` prefix. **The path every rule sees is normalised:** `//wp-json/…` and `/%77p-json/…` reached WordPress as the REST API while missing a rule on `/wp-json/`. `..` is deliberately kept as written, because resolving it would let `/wp-json/a/../../x` walk out of that same rule. **A solved challenge could redirect off-site:** a tab after the first slash passed the guard and became `//evil.example` in the browser. **WordPress's presets match at any depth,** so core in its own directory (`/wp/wp-login.php`) and subdirectory installs are covered (preset version 2). **A host can put a notice on the challenge page** with the new `challenge.notice` key, or `RequestChallenged::addNotice()` from a listener, to say why a visitor is being asked again. Plus: rate-limit paths ignore case as URL rules do, the linter reports a second rate-limit entry for one path (it never runs, and the docs had recommended it), and the log line names a directly served file's URL without a trailing slash.

## [2.34.1](https://github.com/kanopi/firewall/releases/tag/v2.34.1) — 2026-09-29

Every response the firewall writes (the challenge interstitial, the challenge verify answer, block, lockdown and redirect) now sends `Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0` with `Pragma`, `Expires`, `Surrogate-Control` and `CDN-Cache-Control`. The interstitial used to send `no-store` alone, which Pantheon's Global CDN caches, so every visitor to a challenged URL got the same single-use ALTCHA challenge. The first to solve it got through, and everyone after was refused and sent back to the same cached page, in a loop. A block sent no cache header at all. A spent solution that comes back from a different client now logs a `warning` naming a cached challenge page as the likely cause, and the interstitial ignores a second submit while the first is in flight, so a double click no longer posts the same solution twice. `mode: exception` hosts can send the same set from `Kanopi\Firewall\Utility\NoStore::HEADERS`.

## [2.34.0](https://github.com/kanopi/firewall/releases/tag/v2.34.0) — 2026-09-29

`global.path_source: script_name` matches the file the web server ran, not the path relative to the front controller. Under the default, a file the server runs directly (WordPress's `wp-login.php`, `xmlrpc.php` and every `/wp-admin/*.php`, Drupal's `core/install.php`) is matched as `/`. So the WordPress preset and every `/wp-login.php` rate limit never fired on the pages they name, and the search-bot preset's negated exclusion let a crawler through to exactly the back end it was meant to keep out. Nothing reported it, and `firewall-check` said the rules matched. The path comes from `SCRIPT_NAME`, not the raw URL, so `/./wp-login.php` and `/%77p-login.php` are the same login page and count against the same limit. `global.base_path` covers subdirectory installs, `firewall-check --script-name` checks a request the way the site receives it, `firewall-doctor` reports which source is in use, and the WordPress docs now set it. Block records also stop naming a direct file's URL with a trailing slash. The default is unchanged, and front-controller applications (Laravel, Symfony, Drupal's routes) should keep it.

`matomo/device-detector` is now required at `^6.5.2`, up from `^6.4`. 6.5.2 adds Nikto to its bot database, so a `bot:true` rule now matches Nikto on every install rather than depending on which version was installed.

## [2.33.2](https://github.com/kanopi/firewall/releases/tag/v2.33.2) — 2026-09-28

A rate-limit `key:` naming a `post`, `cookie` or `query` field with a capital in it, `post.userName` for instance, now counts that field. Before, every component was lower-cased, so the key read a field that was never there, every request resolved to the same empty value, and the limit shared one counter across all visitors, refusing everybody at once once it tripped. Header names are still case-insensitive, and every key that already worked hashes to the same counter after the upgrade.

## [2.33.1](https://github.com/kanopi/firewall/releases/tag/v2.33.1) — 2026-09-28

Three fixes, and each is something the library accepted in one place and quietly failed on in another.

`firewall-check` now reports a request that matches a `response: redirect` rule as **REDIRECTED**, exit `3`, and names where the visitor is sent and with which status. Before, the redirect was never caught, so the tool said "evaluation threw unexpectedly" and exited `70`, the internal-error code, and a CI gate asserting that a redirect rule works could not pass.

`global.lockdown_allow` now honours a `start-end` range, the notation the `IpAddress` rule has always taken. Before, a range matched nobody, with no error at startup and no log line, so an office listed as `203.0.113.10-203.0.113.20` was locked out by the lockdown meant to keep it in. `firewall-doctor` now names every allowlist entry that can never match, an error while lockdown is on, and recognises `lockdown: true` as active rather than only the `mode: lockdown` shorthand.

`firewall-check` had the same blind spot: it set lockdown aside for the check only when it was switched on with `mode: lockdown`, so with the `lockdown: true` flag (the one a `mode: exception` host has to use) every request came back BLOCKED by the lockdown and said nothing about which rule would match. Both spellings are now set aside for the check and reported beside the verdict.

## [2.33.0](https://github.com/kanopi/firewall/releases/tag/v2.33.0) — 2026-09-27

Everything in YAML: four things a site could only set up from PHP now have a key — a Memcached or Redis cache named by a DSN, a connection declared once and handed to anything that takes a client, decision listeners and the StatsD exporter, and trusted proxies — each scoped so it cannot reach past the firewall: trusted proxies apply for one evaluation and the host's own call still wins, and a cache read back from a shared server refuses to hand over an object. Memcached ships as a block list too, answering range searches from a sharded index that says when it has lost part of itself. Plus two things the firewall had been getting quietly wrong: the rule-sources offline flag switched reverse-DNS verification off with no way back and no warning, and a request with no client address crashed `IpAddress` and put every such visitor on one shared ban.

## [2.32.0](https://github.com/kanopi/firewall/releases/tag/v2.32.0) — 2026-09-19

The last thing the client chose: how long a challenge pass lasted was still a number the visitor's own browser proposed and the firewall clamped, because the submission arrives at the challenge path rather than at the protected URL and by then nothing says which rule sent them — it now rides in the signed token the interstitial already carries, so there is nothing left to propose. A page rendered before the upgrade still verifies and falls back to the ceiling 2.30.0 added, which is exactly what that ceiling was written to be. One item, because the other one in this milestone turned out to need a design decision rather than a fix and moved to 3.x.

## [2.31.0](https://github.com/kanopi/firewall/releases/tag/v2.31.0) — 2026-09-18

What the firewall writes down, in both directions: a block record kept the visitor's whole cookie jar and header set — session cookie, `Authorization`, challenge pass — in the one artifact operators paste into tickets and replicate across a fleet, and every remote log handler shipped its records over a blocking HTTPS round trip inside the request, which is the hazard 2.30.0 deliberately refused for metrics with nothing stopping it one directory over. Both were found by reviewing the previous release's own work rather than by planning, and the second turned up a third thing on the way past: wrapping any Monolog handler was impossible from YAML, which is why the documented answer for `FingersCrossed` and `Buffer` had always been to write PHP instead.

## [2.30.0](https://github.com/kanopi/firewall/releases/tag/v2.30.0) — 2026-09-17

Input the operator did not write: five places where a value nobody typed became a decision the firewall enforced, each one failing in a way that looked like the firewall working — an entry in a published feed that refuses every visitor while `--lint` reports the configuration clean, a challenge pass whose lifetime was chosen by the visitor's own browser and could reach thirty-one years, a rule source nothing checked was the file its publisher meant to publish, one with no ceiling on its size in either direction across the wire or out of a gzip, and a pass already issued that could not be withdrawn without re-challenging everybody holding one. Plus the two that were actually planned: StatsD and Prometheus exporters over the decision events, and a tarpit that refuses to hold more workers than the pool can spare.

## [2.29.0](https://github.com/kanopi/firewall/releases/tag/v2.29.0) — 2026-09-16

A block that travels: a ban earned on one node now applies to the whole fleet, with a local copy underneath it so an unreachable shared store does not leave the site unguarded — and three places the firewall stopped short of saying what it was doing, each found by using it rather than by reading it: a `record` rule that failed to start and was reported as healthy, Redis storage that took the whole firewall down when the extension was missing rather than degrading, and a challenge no human could complete on a site served from a subdirectory.

## [2.28.0](https://github.com/kanopi/firewall/releases/tag/v2.28.0) — 2026-09-15

Getting here from there: the four questions a host has to answer before the firewall behaves and how to get them out of your own environment, what an existing Wordfence, ModSecurity or Cloudflare rule translates to here, a reputation rule that can score the email somebody submitted rather than only the address it came from — and a log destination that does not exist on this host no longer stopping the firewall from starting, which is what running the first of those found.

## [2.27.0](https://github.com/kanopi/firewall/releases/tag/v2.27.0) — 2026-09-14

Notice more: a rate limit can count the account rather than the IP, a rule can ask a reputation service of your choosing or read the bot score and TLS fingerprint a CDN already computed at the edge, and any rule can be given a window — so what a rule notices, and when it notices it, stop being fixed to the client address and always-on.

## [2.26.0](https://github.com/kanopi/firewall/releases/tag/v2.26.0) — 2026-09-12

More than block or allow: refusing and recording come apart, so a honeypot can record without refusing and a lockdown can refuse without recording — plus `redirect` and `mark` response actions, and a fix for a silent permanent lockout in `mode: exception` with per-rule challenge providers.

## [2.25.0](https://github.com/kanopi/firewall/releases/tag/v2.25.0) — 2026-09-11

Ready 2.x to be an old version: documentation sorted into a shape worth freezing and then frozen with a version selector, presets carrying their own version and enforcement changelog, and a written support policy — so that when 3.0 ships, a 2.x operator is not reading 3.x documentation or taking preset changes they never asked for.

## [2.24.0](https://github.com/kanopi/firewall/releases/tag/v2.24.0) — 2026-09-10

Let the operator act: lift a block, change a rule, turn the firewall down mid-incident and react to a decision in your own code — four things the library could already do internally and gave nobody a way to reach.

## [2.23.1](https://github.com/kanopi/firewall/releases/tag/v2.23.1) — 2026-09-09

`firewall-doctor` now says how stale a rule source is, not just that it is stale — one second past its ttl and two days past it were the same line, and only one of them is a fetcher that has been failing since Monday.

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
