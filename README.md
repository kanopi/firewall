# Simple Firewall

**Simple Firewall** is an extensible request-evaluation library for PHP-based systems. It analyzes HTTP requests and applies rules to either allow or block access based on IPs, geolocation, user agents, URLs, ASN, and rate limits. It's designed for use with frameworks like Drupal, WordPress, or standalone PHP applications.

---

## 🛠️ Installation & Setup

### Add to Your Application

Place the following in your application's entry point:

```php
if (class_exists('\Kanopi\Firewall\Firewall')) {
    \Kanopi\Firewall\Firewall::create([ __DIR__ . '/config.yml' ])->evaluate();
}
```

This initializes the firewall using your YAML configuration.

---

## ⚙️ Configuration Overview

The firewall accepts:

- A **YAML file** path.
- An **array of configuration data**.

It includes four core sections:

| Key       | Purpose                                                                  |
|------------|--------------------------------------------------------------------------|
| `storage`  | Defines where blocked IP addresses are stored.                           |
| `bypass`   | Plugins to allow trusted traffic.                                        |
| `block`    | Plugins to deny harmful or suspicious traffic.                           |
| `logger`   | Log handlers using Monolog.                                              |

---

## 🧱 Storage Configuration

Storage defines how blocked IPs are persisted.

### Available Storage Classes

| Class                                     | Description                     |
|-------------------------------------------|---------------------------------|
| `\Kanopi\Firewall\Storage\InMemoryStorage` | Non-persistent, resets per request |
| `\Kanopi\Firewall\Storage\FileStorage`     | Saves IPs to disk              |
| `\Kanopi\Firewall\Storage\DatabaseStorage` | Persists data in SQL databases |

### File Example

```yaml
storage:
  type: \Kanopi\Firewall\Storage\FileStorage
  config:
    file: /tmp/firewall.data
```

### Database Example

```yaml
storage:
  type: \Kanopi\Firewall\Storage\DatabaseStorage
  config:
    storage-table: firewall-storage
    connection:
      dsn: "pdo-mysql://user:user@127.0.0.1:33066/default?serverVersion=10.6"
```

---

## 🔌 Plugin Architecture (bypass / block)

Plugins are modular evaluators. They can be enabled for:

- `bypass`: allow specific requests.
- `block`: reject specific requests.

### Common Plugin Properties

Each plugin accepts:

```yaml
PluginNamespace:
  priority: 0
  enable: true
  metadata: { ... }
  config: { ... }
```

- `priority`: execution order (-100 is higher priority than 100).
- `enable`: whether the plugin is active.

### Supported Plugins

| Plugin | Description |
|--------|-------------|
| `IpAddress` | Match IPv4/IPv6, CIDR, and IP ranges |
| `GeoLocation` | Match by country, continent, city (via MaxMind) |
| `Url` | Match method, path, host, query, post vars |
| `UserAgent` | Analyze client/bot/device info |
| `Asn` | Match ASN number or org |
| `RateLimit` | Limit traffic rate per path or globally |

---

## ⏱️ Rate Limit Plugin

Use `RateLimit` to restrict traffic bursts or bot attacks.

### Metadata Options

```yaml
metadata:
  default_rate: 10
  default_sample: 10
  default_expiration_time: 300
```

### Storage Backends

| Class | Description |
|-------|-------------|
| `InMemoryRateLimitStorage` | Non-persistent memory storage |
| `RedisRateLimitStorage` | Uses Redis |
| `FileRateLimitStorage` | File-based tracking |
| `DatabaseRateLimitStorage` | SQL-based tracking |

### Example

```yaml
\Kanopi\Firewall\Plugins\RateLimit:
  enable: true
  metadata:
    default_rate: 5
    storage:
      type: \Kanopi\Firewall\Plugins\RateLimitStorage\RedisRateLimitStorage
      config:
        redis:
          host: 127.0.0.1
          port: 6379
          auth: ['username', 'password']
  config:
    - path: "/"
      rate: 1
      sample: 10
```

---

## 🧠 Conditional Formatting

Detailed logic to evaluate request values. Three formats:

### Simple

```yaml
- "method:POST"
- "host@starts_with:api."
- "!path@contains:/admin"
- "rate > 100"
```

### Complex

```yaml
- variable: method
  operator: in
  value: [GET, POST]
  negate: false
  case_sensitive: false
```

### Grouped

```yaml
- type: AND
  rules:
    - variable: host
      operator: regex
      value: ".*\.example\.com"
    - "method:POST"
```

---

## 📝 Logger

Uses [Monolog](https://seldaek.github.io/monolog/). Logs request actions, blocked entries, etc.

```yaml
logger:
  -
    class: Monolog\Handler\StreamHandler
    args:
      - /tmp/firewall.log
      - Monolog\Level::Debug
    formatter:
      class: Monolog\Formatter\LineFormatter
      args:
        - "[%datetime%] [%context.plugin%] %message% %context%\n"
        - "Y-m-d\TH:i:sP"
```

---

## 🔄 Overrides

Dynamic environments (Docker, multi-site, etc.) can override YAML with array-based syntax.

```php
[
  '[logger][0][args][0]' => __DIR__ . '/data/firewall.log',
  '[block][\Kanopi\Firewall\Plugins\GeoLocation][metadata][reader][db]' => __DIR__ . '/GeoLite2-City.mmdb',
]
```

Uses Symfony's PropertyAccess syntax.

---

## 🌐 Platform Integration

### Drupal

In `settings.php`, before `$settings['container_yamls'][]`:

```php
\Kanopi\Firewall\Firewall::create([ __DIR__ . '/config.yml' ])->evaluate();
```

### WordPress

In `wp-config.php`, early in the file:

```php
if ( class_exists('\Kanopi\Firewall\Firewall') ) {
    \Kanopi\Firewall\Firewall::create([ __DIR__ . '/firewall/config.yml' ])->evaluate();
}
```

### Standalone PHP

```php
require_once __DIR__ . '/vendor/autoload.php';
\Kanopi\Firewall\Firewall::create([ __DIR__ . '/config.yml' ])->evaluate();
```

---

## 🧪 Testing

_TBD_: PHPUnit-based validation and plugin mocking coming soon.


---

## 🧰 Extended Code Samples

### Initialize with Array Configuration

```php
use \Kanopi\Firewall\Firewall;

$config = [
  'storage' => [
    'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
  ],
  'block' => [
    'Kanopi\Firewall\Plugins\IpAddress' => [
      'enable' => true,
      'priority' => 0,
      'config' => ['127.0.0.1']
    ]
  ]
];

Firewall::create([$config])->evaluate();
```

### Custom Plugin Implementation

```php
namespace Custom\Firewall\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;

class MyCustomPlugin implements PluginInterface {
    public function process($request, $context): bool {
        // Custom logic
        return false;
    }
}
```

Add it in config:

```yaml
block:
  Custom\Firewall\Plugins\MyCustomPlugin:
    enable: true
    config: []
```

---

## 🗺️ Architecture Diagram

```text
+--------------------+
|  HTTP Request      |
+--------------------+
          |
          v
+------------------------+
| Firewall::evaluate()   |
+------------------------+
          |
          v
+---------------------------+
| Apply Bypass Plugins      | --(if matched)--> Allow Request
+---------------------------+
          |
          v
+---------------------------+
| Apply Block Plugins       | --(if matched)--> Block Request
+---------------------------+
          |
          v
+---------------------------+
| Log (via Monolog)         |
+---------------------------+
          |
          v
+------------------------+
| Return Request Outcome |
+------------------------+
```

---

## ✅ Testing Guide (Coming Soon)

In future releases:

- PHPUnit test suite for plugin behavior
- Mock request objects
- Integration test using sample configuration
- CI-ready test harness

Example test outline:

```php
public function testFirewallBlocksIp() {
    $firewall = Firewall::create([ __DIR__ . '/fixtures/block_ip_config.yml' ]);
    $request = new MockRequest('127.0.0.1');

    $this->assertTrue($firewall->evaluate($request));
}
```

---

## 📎 Related Resources

- [Symfony PropertyAccess](https://symfony.com/doc/current/components/property_access.html)
- [MaxMind GeoIP2 PHP](https://github.com/maxmind/GeoIP2-php)
- [Monolog Logging](https://seldaek.github.io/monolog/)


---

## 🧱 Custom Plugin Scaffolding

To build your own plugin, implement the `\Kanopi\Firewall\Plugins\PluginInterface`.

### Example Custom Plugin

```php
<?php

namespace Custom\Firewall\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;
use Kanopi\Firewall\Exception\BlockAccessException;

class MyCustomPlugin implements PluginInterface {
    public function getName(): string {
        return 'MyCustomPlugin';
    }

    public function getDescription(): string {
        return 'Blocks all requests from a hardcoded header value.';
    }

    public function evaluate(Request $request): bool {
        if ($request->headers->get('X-Block-Me') === 'true') {
            throw new BlockAccessException('Blocked by MyCustomPlugin.');
        }

        return true;
    }

    public function getStatusCode(): int {
        return 403;
    }

    public function getExpirationTime(): int {
        return 3600;
    }
}
```

Once created, register it in your `config.yml`:

```yaml
block:
  \Custom\Firewall\Plugins\MyCustomPlugin:
    enable: true
    config: []
```
