# Lite Firewall

**Lite Firewall** is a powerful, extensible request-evaluation library for PHP-based systems. It analyzes HTTP requests and applies configurable rules to allow, challenge, or block access based on IP addresses, geolocation, user agents, URLs, ASN (Autonomous System Numbers), rate limits, vulnerability scoring, and the OWASP Core Rule Set.

It is framework agnostic — it works with Drupal, WordPress, Symfony, Laravel, or any standalone PHP application.

## 📖 Documentation

**Start at the [documentation index](docs/index.md).**

This README is a short introduction. Everything else — the complete configuration
reference, every plugin, the shipped presets, platform integration, and the
contribution guide — is in [`docs/`](docs/), and published at
[kanopi.github.io/firewall](https://kanopi.github.io/firewall/).

| | |
|---|---|
| [Getting Started](docs/getting-started/index.md) | Install, configure, and block your first request |
| [Configuration](docs/configuration/index.md) | Every YAML key, with defaults |
| [Plugins](docs/plugins/index.md) | The ten built-in request evaluators |
| [Presets](docs/presets/available.md) | Ready-made rule sets you can include in one line |
| [Guides](docs/guides/index.md) | Error handling, custom plugins, custom storage, GeoIP setup |
| [Reference](docs/reference/index.md) | Rate-limit rules and the legacy config format |
| [Contributing](docs/contributing/index.md) | Development setup, tests, and the PR checklist |

The docs source is the [`docs/`](docs/) directory in this repository. See
[Writing Documentation](docs/contributing/documentation.md)
to contribute a change.

## Features

- **Flexible Plugin System**: Modular architecture allows for easy extension and customization
- **Multiple Storage Backends**: In-memory, file-based, and database storage for blocked clients, plus in-memory, file, database, PSR-6 cache, and Redis backends for rate-limit counters — or bring your own
- **Comprehensive Request Analysis**: Evaluate requests based on IP, location, ASN, user agent, URL patterns, and more
- **OWASP Core Rule Set**: Real CRS rules (SQLi, XSS, LFI/RFI, RCE, scanners) with tunable paranoia levels
- **IP Reputation**: Turn away addresses reported to AbuseIPDB, cached to stay inside the free tier and failing open when the service is unreachable
- **Vulnerability Scoring**: Advanced risk assessment based on multiple factors with configurable thresholds
- **Rate Limiting**: Built-in rate limiting with configurable storage backends
- **Challenge Responses**: Serve a proof-of-effort interstitial instead of a hard block, with HMAC-signed, IP-bound pass tokens
- **GeoIP Integration**: Full support for MaxMind GeoIP2 databases (both local and web service)
- **Advanced Conditional Logic**: Support for simple, complex, and grouped conditional rules
- **Escalating Bans**: Repeat offenders can be banned for progressively longer, up to permanently
- **Remote Configuration Support**: Load configuration files from remote URLs with local caching
- **PSR-3 Compatible Logging**: Integration with Monolog for flexible logging, with sensitive headers redacted by default
- **Framework Agnostic**: Works with any PHP application or framework — block, log-only, or throw exceptions for your framework to handle

## Requirements

- PHP 8.1 or higher
- Composer
- Optional: MaxMind GeoIP2 databases for geolocation features
- Optional: Redis for distributed rate limiting

## Installation

```bash
composer require kanopi/firewall
```

## Quick Start

Place the following in your application's entry point (`index.php`, `wp-config.php`, or Drupal's `settings.php`):

```php
<?php
require_once __DIR__ . '/vendor/autoload.php';

if (class_exists('\Kanopi\Firewall\Firewall')) {
    \Kanopi\Firewall\Firewall::create([__DIR__ . '/config/firewall.yml'])->evaluate();
}
```

> **⚠️ Configure trusted proxies before calling `Firewall::create()`**
>
> Every plugin evaluates `$request->getClientIp()`. Symfony only honors `X-Forwarded-For` / `Forwarded` / `X-Real-IP` when you have called `Request::setTrustedProxies(...)`. If your application sits behind a load balancer, CDN, or reverse proxy and you skip this, **attackers can spoof their source IP and bypass IP allow-lists, block-lists, and per-IP rate limits**.
>
> ```php
> use Symfony\Component\HttpFoundation\Request;
>
> Request::setTrustedProxies(
>     ['10.0.0.0/8', '192.168.0.0/16'],                  // YOUR proxy CIDRs
>     Request::HEADER_X_FORWARDED_FOR | Request::HEADER_X_FORWARDED_PROTO
> );
> ```
>
> See [Trusted Proxies](docs/configuration/global.md#trusted-proxies).

Create a `config/firewall.yml`:

```yaml
# Where blocked clients are stored
storage:
  type: "Kanopi\\Firewall\\Storage\\FileStorage"
  config:
    storage_file: /var/log/firewall/blocked.data

# Plugins evaluated for every request
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: block
    enable: true
    config:
      - 192.168.1.100
      - 10.0.0.0/24

# Optional: log firewall events
logger:
  - class: Monolog\Handler\StreamHandler
    args:
      - logs/firewall.log   # relative to this YAML's directory
      - Monolog\Level::Info
```

Want a preset instead of writing rules by hand?

```yaml
configs:
  - "{presets_dir}/malicious-requests.yml"
```

Continue with the [Quick Start](docs/getting-started/quick-start.md)
or the five-minute [Test Drive](docs/getting-started/test-drive.md).

## Local Development

```bash
composer install     # Install dependencies
composer test        # Run the test suite
composer cs          # Check code style
composer stan        # Run static analysis
composer demo        # Run the demo app at http://localhost:8000
```

To preview the documentation site locally:

```bash
python3 -m venv .venv-docs
source .venv-docs/bin/activate
pip install -r docs/requirements.txt
mkdocs serve         # http://127.0.0.1:8000
```

## Contributing

We welcome contributions. See the
[Contributing Guide](docs/contributing/index.md) for
development setup, branch and commit conventions, testing requirements, and
the PR checklist.

## Support

- **Documentation**: [kanopi.github.io/firewall](https://kanopi.github.io/firewall/) (source in [`docs/`](docs/))
- **Issues**: [github.com/kanopi/firewall/issues](https://github.com/kanopi/firewall/issues)
- **Discussions**: [github.com/kanopi/firewall/discussions](https://github.com/kanopi/firewall/discussions)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Credits

Lite Firewall is developed and maintained by [Kanopi Studios](https://kanopi.com).

Special thanks to:
- The Symfony team for the excellent HttpFoundation component
- MaxMind for the GeoIP2 databases
- The Monolog team for the flexible logging library
