# Firewall Example Setup

This directory contains a working example of the Kanopi Firewall library
running in a local Docker environment. Use it to test configurations,
experiment with plugins, and understand how the firewall behaves.

**Full documentation:
[Local Example Environment](https://kanopi.github.io/firewall/guides/example-environment/)**

| Page | Covers |
|---|---|
| [Local Example Environment](https://kanopi.github.io/firewall/guides/example-environment/) | Starting and stopping the Docker stack, spoofing client IPs with `X-Forwarded-For`, the config files here, worked blocking examples, and troubleshooting |
| [GeoIP Setup](https://kanopi.github.io/firewall/guides/geoip-setup/) | Downloading GeoLite2 databases, the MaxMind web service, and Docker volume mounting |
| [Demo Application](https://kanopi.github.io/firewall/guides/demo/) | The runnable demo in [`demo/`](demo/) — challenge flow and repeat-offender escalation |

## Quick start

```bash
# From the project root
composer server:start        # docker compose up -d --build
composer server:stop
composer server:destroy
```

Then visit <http://localhost:8080>.

## Files in this directory

| File | Purpose |
|---|---|
| `index.php` | Entry point that boots the firewall and echoes request details. |
| `config.yml` | Default example configuration. |
| `config.ip.yml` | IP allow/block list example. |
| `config.notes.yml` | Annotated configuration walkthrough. |
| `config.vulnerability-score.yml` | Vulnerability-scoring example. |
| `test-vulnerability-score.php` | CLI harness for the scoring plugin. |
| `demo/` | The standalone demo app (`composer demo`). |

## Editing these docs

The pages above are built from [`docs/guides/`](../docs/guides/). Change the
Markdown there, not this file. See
[Writing Documentation](https://kanopi.github.io/firewall/contributing/documentation/).
