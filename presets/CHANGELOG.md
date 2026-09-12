# Preset Changelog

What each shipped rule set **blocks**, and when that changed.

This is separate from the library's [`CHANGELOG.md`](../CHANGELOG.md) on purpose. Presets
ship *inside* the package, so `composer update` can change what gets blocked on a production
site without a single line of your configuration changing. An operator pinned to a minor
line still needs to know that `malicious-requests.yml` grew forty new patterns — and that is
not a library change, so it does not belong in the library's changelog.

Each rule set carries `# Preset-Version: N` in its header. Bump it in the same commit that
changes what the preset matches.

## What counts as a change worth a version

Bump the version when the set of traffic affected changes:

- a rule added, removed, or widened
- a pattern made stricter or looser
- a `response` changed (`block` → `challenge`, say)
- a `weight` change that alters which rule wins

Not a version bump: comments, formatting, a `name` added to a rule for the log, or anything
else that leaves the matched traffic identical.

---

## Version 1

**2026-09-11** — the baseline. Every shipped rule set starts here.

Versioning begins with this release (2.25.0). Version 1 is "whatever the preset contained
when versioning was introduced" rather than a reconstruction of its history — the history
before this point is in the git log, and pretending otherwise would be inventing a record.

| Preset | What it does |
|---|---|
| `ai-answer-engines.yml` | Blocks AI answer-engine and summariser crawlers |
| `ai-crawlers-challenge.yml` | Challenges AI training crawlers instead of blocking them |
| `ai-crawlers.yml` | Blocks AI training and dataset crawlers |
| `drupal-admin.yml` | Blocks Drupal `/admin` and authentication routes |
| `drupal.yml` | Drupal hardening: version disclosure, installer routes, build artefacts |
| `honeypot.yml` | Paths no legitimate client fetches; anything that does earns a durable block from its next request (added 2.26.0) |
| `malicious-requests.yml` | Vulnerability scoring for SQLi, XSS, RCE, traversal, scanners |
| `malicious-urls.yml` | URL-pattern blocks for known-bad paths |
| `rate-limiting.yml` | Per-path rate limits across auth, API, admin, forms, static assets |
| `search-bots.yml` | Allows verified search crawlers past block rules |
| `wordpress.yml` | WordPress endpoint hardening |

Not versioned, and why:

| File | |
|---|---|
| `config.yml`, `logging-pantheon.yml`, `storage-pantheon.yml` | Configure infrastructure, not enforcement — changing them cannot change which traffic is affected |
| `example-*.yml` | Documentation. Not meant to be included in a real configuration |
