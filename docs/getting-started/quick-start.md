# Quick Start

## Generate a configuration

```bash
vendor/bin/firewall-init
```

```
  Platform?              WORDPRESS / drupal / other: drupal
  Behind a CDN?          NONE / cloudflare / pantheon / wpengine / fastly: pantheon
  Storage?               FILE / database / redis: file
  Start enforcing?       LOG / block:

  Wrote config/firewall.yml
```

It writes a commented starter that includes the presets for your platform, asserts the
right proxy posture for your CDN, and **starts in observe mode** — every rule is evaluated
and every match logged, and nothing is refused. Read the log for a week before switching to
`block`; turning an unfamiliar rule set straight on is how a site finds its false positives
in production.

Every answer is also a flag, and with no terminal attached it takes the defaults rather than
prompting — so it is safe inside a scaffolding script or a container build:

```bash
vendor/bin/firewall-init --platform=drupal --cdn=pantheon --storage=database --mode=log
```

Then check it:

```bash
vendor/bin/firewall-check --config=config/firewall.yml --lint   # are the rules sane?
vendor/bin/firewall-doctor config/firewall.yml                  # does this environment work?
```

The rest of this page is what that file contains, and how to wire it in.

## Basic Implementation

Place the following code in your application's entry point (e.g., `index.php`, `wp-config.php`, or Drupal's `settings.php`):

```php
<?php
// Include composer autoloader if not already loaded
require_once __DIR__ . '/vendor/autoload.php';

// Initialize and evaluate the firewall
if (class_exists('\Kanopi\Firewall\Firewall')) {
    \Kanopi\Firewall\Firewall::create([__DIR__ . '/config/firewall.yml'])->evaluate();
}
```

> **⚠️ Important: Configure trusted proxies before calling `Firewall::create()`**
>
> Every plugin in this library evaluates `$request->getClientIp()`. Symfony only honors `X-Forwarded-For` / `Forwarded` / `X-Real-IP` when the integrator has called `Symfony\Component\HttpFoundation\Request::setTrustedProxies(...)`. If your application sits behind a load balancer, CDN, or reverse proxy and you skip this step, **attackers can spoof their source IP via `X-Forwarded-For` and bypass IP/CIDR allow-lists, block-lists, and per-IP rate limits**.
>
> ```php
> use Symfony\Component\HttpFoundation\Request;
>
> Request::setTrustedProxies(
>     ['10.0.0.0/8', '192.168.0.0/16'],                  // YOUR proxy CIDRs
>     Request::HEADER_X_FORWARDED_FOR | Request::HEADER_X_FORWARDED_PROTO
> );
>
> \Kanopi\Firewall\Firewall::create([__DIR__ . '/config/firewall.yml'])->evaluate();
> ```
>
> When trusted proxies are not configured, `Firewall::create()` logs a warning to the configured logger. To make a missing trusted-proxies setup a hard startup failure instead, set `global.require_trusted_proxies: true` in your config — the library will then throw `ConfigurationException` rather than start in a spoofable state.

## Minimal Configuration Example

Create a `config/firewall.yml` file:

```yaml
# Storage configuration - where blocked IPs are stored
storage:
  type: "Kanopi\\Firewall\\Storage\\FileStorage"
  config:
    storage_file: /var/log/firewall/blocked.data

# Plugins evaluated for every request
plugins:
  # Block malicious IPs
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: block
    enable: true
    config:
      - 192.168.1.100
      - 10.0.0.0/24

  # Optional: Enable vulnerability scoring for advanced threat detection
  # - plugin: "Kanopi\\Firewall\\Plugins\\VulnerabilityScore"
  #   response: block
  #   enable: true
  #   config:
  #     scoring:
  #       patterns:
  #         - pattern: "/<script|union.*select/i"
  #           score: 50
  #           type: regex
  #           locations: ["uri", "query_string"]
  #     risk_levels:
  #       high:
  #         threshold: 40
  #         block: true

# Optional: Configure logging
logger:
  - class: Monolog\Handler\StreamHandler
    args:
      - logs/firewall.log   # relative to this YAML's directory
      - Monolog\Level::Info
```
