# Firewall Presets

This directory contains pre-configured firewall rule sets (presets) that can be
included in your main configuration to block common attack patterns and
malicious requests.

**Full preset documentation:
[Presets](../docs/presets/index.md)**

| Page | Covers |
|---|---|
| [Available Presets](../docs/presets/available.md) | What each shipped preset blocks, including the Pantheon platform presets |
| [Using Presets](../docs/presets/usage.md) | Including, combining, and overriding presets; storage and GeoIP options |
| [Tuning & False Positives](../docs/presets/tuning.md) | Regex delimiters, the generic PHP block, and common false positives |
| [Testing Presets](../docs/presets/testing.md) | `curl` commands to verify each preset is doing its job |
| [Custom Presets](../docs/presets/custom.md) | Writing your own reusable rule sets |
| [Rate Limiting Reference](../docs/reference/rate-limiting.md) | Every rule in `rate-limiting.yml`, with the reasoning behind each limit |

## Files in this directory

| File | Purpose |
|---|---|
| `malicious-requests.yml` | Vulnerability-scoring rules for SQLi, XSS, RCE, traversal, and scanners. The recommended starting point. |
| `malicious-urls.yml` | URL-pattern blocks for known-bad paths. |
| `rate-limiting.yml` | Per-path rate limits across auth, API, admin, forms, and static assets. |
| `wordpress.yml` | WordPress-specific hardening. |
| `storage-pantheon.yml` | Storage wiring for Pantheon-hosted sites. |
| `logging-pantheon.yml` | Logging wiring for Pantheon-hosted sites. |
| `config.yml` | Convenience bundle of the two URL-pattern presets (`malicious-urls.yml` + `wordpress.yml`). No rate limiting or vulnerability scoring. |
| `example-*.yml` | Worked examples referenced from the docs. |

## Quick start

```yaml
# firewall-config.yml
configs:
  - "{presets_dir}/malicious-requests.yml"

storage:
  type: "Kanopi\\Firewall\\Storage\\FileStorage"
  config:
    storage_file: /var/log/firewall/blocked.data
```

`{presets_dir}` expands to this directory inside `vendor/`, so the include works
regardless of your vendor layout.

## Editing these docs

The pages above are built from [`docs/presets/`](../docs/presets/). Change the
Markdown there, not this file. See
[Writing Documentation](../docs/contributing/documentation.md).
