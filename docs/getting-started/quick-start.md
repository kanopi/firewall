# Quick Start

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
    file: /var/log/firewall/blocked.data

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
