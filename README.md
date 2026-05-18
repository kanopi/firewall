# Lite Firewall

**Lite Firewall** is a powerful, extensible request-evaluation library for PHP-based systems. It provides comprehensive protection by analyzing HTTP requests and applying configurable rules to either allow or block access based on IP addresses, geolocation, user agents, URLs, ASN (Autonomous System Numbers), and rate limits. The library is designed to work seamlessly with popular frameworks like Drupal, WordPress, Symfony, or any standalone PHP application.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration Overview](#configuration-overview)
- [Configuration Loading & Includes](#configuration-loading--includes)
- [Environment Variables in YAML](#environment-variables-in-yaml)
- [Global Configuration](#global-configuration)
  - [Multiple Offenses Defense](#multiple-offenses-defense)
- [Storage Configuration](#storage-configuration)
- [Plugin Architecture](#plugin-architecture)
- [Available Plugins](#available-plugins)
  - [IP Address Plugin](#ip-address-plugin)
  - [GeoLocation Plugin](#geolocation-plugin)
  - [URL Plugin](#url-plugin)
  - [User Agent Plugin](#user-agent-plugin)
  - [ASN Plugin](#asn-plugin)
  - [Rate Limit Plugin](#rate-limit-plugin)
  - [Vulnerability Score Plugin](#vulnerability-score-plugin)
  - [CRS (OWASP Core Rule Set) Plugin](#crs-owasp-core-rule-set-plugin)
- [Conditional Logic](#conditional-logic)
- [Logging Configuration](#logging-configuration)
- [Dynamic Configuration Overrides](#dynamic-configuration-overrides)
- [Platform Integration](#platform-integration)
- [Advanced Examples](#advanced-examples)
- [Testing](#testing)
- [Contributing](#contributing)

## Features

- **Flexible Plugin System**: Modular architecture allows for easy extension and customization
- **Multiple Storage Backends**: Support for in-memory, file-based, database, and Redis storage
- **Comprehensive Request Analysis**: Evaluate requests based on IP, location, user agent, URL patterns, and more
- **Vulnerability Scoring**: Advanced risk assessment based on multiple factors with configurable thresholds
- **Rate Limiting**: Built-in rate limiting with configurable storage backends
- **GeoIP Integration**: Full support for MaxMind GeoIP2 databases (both local and web service)
- **Advanced Conditional Logic**: Support for simple, complex, and grouped conditional rules
- **Remote Configuration Support**: Load configuration files from remote URLs with local caching
- **PSR-3 Compatible Logging**: Integration with Monolog for flexible logging
- **Framework Agnostic**: Works with any PHP application or framework

## Requirements

- PHP 8.1 or higher
- Composer
- Optional: MaxMind GeoIP2 databases for geolocation features
- Optional: Redis for distributed rate limiting

## Installation

Install via Composer:

```bash
composer require kanopi/firewall
```

## Quick Start

### Basic Implementation

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

### Minimal Configuration Example

Create a `config/firewall.yml` file:

```yaml
# Storage configuration - where blocked IPs are stored
storage:
  type: "Kanopi\\Firewall\\Storage\\FileStorage"
  config:
    file: /var/log/firewall/blocked.data

# Block malicious IPs
block:
  "Kanopi\\Firewall\\Plugins\\IpAddress":
    enable: true
    config:
      - 192.168.1.100
      - 10.0.0.0/24

  # Optional: Enable vulnerability scoring for advanced threat detection
  # "Kanopi\\Firewall\\Plugins\\VulnerabilityScore":
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


### Test Drive

Follow these steps to quickly test Lite Firewall locally in a clean environment:

#### 🧪 Quick Test Drive Setup

1. **Create a temporary folder**
   ```bash
   mkdir testdrive
   cd testdrive
   touch firewall.data
   ```

2. **Install Lite Firewall via Composer**
   ```bash
   composer require kanopi/firewall
   ```

3. **Create a basic `firewall.yml` configuration**

   ```yaml
    storage:
        type: "Kanopi\\Firewall\\Storage\\FileStorage"
        config:
            storage_file: firewall.data

    block:
        "Kanopi\\Firewall\\Plugins\\Url":
            enable: true
            config:
                - "query.block:1"   # Block any request that includes ?block=1
   ```

4. **Create an `index.php` file**

   ```php
   <?php
   require __DIR__ . '/vendor/autoload.php';

   use Kanopi\Firewall\Firewall;

   // Initialize firewall
   Firewall::create([__DIR__ . '/firewall.yml'])->evaluate();

   echo "Hello, world!";
   ```

5. **Start a PHP built-in web server**
   ```bash
   php -S localhost:8000
   ```

6. **Open your browser and test**

   - Visit [http://localhost:8000](http://localhost:8000) — you should see:
     ```
     Hello, world!
     ```

   - Visit [http://localhost:8000?block=1](http://localhost:8000?block=1) — you should see:
     ```
     Request Blocked
     ```

   - Visit [http://localhost:8000](http://localhost:8000) — you should see:
     ```
     Request Blocked
     ```

This simple example demonstrates how the firewall intercepts requests using YAML configuration and shows how easy it is to add rule-based blocking.

To start over empty the contents of the Storage file

```bash
echo "" > firewall.data
```


## Configuration Overview

The firewall configuration consists of four main sections:

| Section   | Purpose                                                  | Required |
|-----------|----------------------------------------------------------|----------|
| `global`  | Defines global configuration settings                    | No       |
| `storage` | Defines where blocked IP addresses are persisted         | Yes      |
| `bypass`  | Plugins that allow trusted traffic through               | No       |
| `block`   | Plugins that deny harmful or suspicious traffic          | No       |
| `logger`  | Monolog handlers for logging firewall events             | No       |

## Configuration Loading & Includes

The firewall supports **modular configuration** via a top‑level `configs:` key in any YAML file. Paths listed under `configs:` are loaded and **merged** into the current file.

**Rules & behavior**

- Paths in `configs:` can be:
  - **Relative** (resolved against the directory of the YAML file that declares them)
  - **Absolute**
  - **Remote URLs** (e.g., `https://example.com/firewall-rules.yml`; cached locally with configurable TTL)
  - Use the `{config_dir}` token (expanded to the current YAML's directory)
  - **Glob patterns** (e.g., `more/*.yml`; matched files are sorted alphabetically)
  - **Environment-driven** using `%env(...)%` (must resolve to a string path)
- **Merge semantics**:
  - Objects (associative arrays) are merged **deeply**; later files override earlier keys
  - Lists (numeric arrays) are **replaced as a whole** by later files
- Safety: circular includes are prevented and excessive include depth is rejected.

**Remote Configuration Files**

Configuration files can be loaded from remote URLs, which is useful for centralized management across multiple servers:

```yaml
configs:
  - "https://cdn.example.com/firewall/base-rules.yml"
  - "https://cdn.example.com/firewall/ip-blocklist.yml"
```

Remote files are cached locally to improve performance and reduce external dependencies. You can control caching behavior using PHP constants:

```php
<?php
// Define before initializing the firewall
define('KANOPI_FIREWALL_CACHE_DIR', '/var/cache/firewall');  // Default: /tmp/cache
define('KANOPI_FIREWALL_CACHE_TTL', 7200);                   // Default: 3600 (1 hour)
define('KANOPI_FIREWALL_CACHE_TIMEOUT', 10.0);               // Default: 5.0 seconds

\Kanopi\Firewall\Firewall::create([__DIR__ . '/config.yml'])->evaluate();
```

**Example**

```yaml
# base: config/firewall.yml
configs:
  - "{config_dir}/sites/*.yml"       # include all site-specific configs
  - "config/extra.yml"               # include another file relative to this YAML
  - "%env(string:EXTRA_CFG)%"        # include a path from env var

logger:
  - class: Monolog\Handler\StreamHandler
    args: ["logs/firewall.log", "Monolog\\Level::Info"]

block:
  "Kanopi\\Firewall\\Plugins\\GeoLocation":
    enable: true
    metadata:
      reader:
        type: reader
        db: "geo/GeoLite2-City.mmdb"   # relative path resolved against this file's directory
```

In the example above, the log file and GeoIP database paths are **relative to the YAML file** (not the PHP current working directory). This makes configs portable regardless of where your app bootstraps from.

## Environment Variables in YAML

You can reference OS environment variables inside YAML using Symfony‑style tokens: `%env(NAME)%`.

- When a YAML scalar is **exactly** a single token (e.g., `port: '%env(int:APP_PORT)%'`), the value is returned as a **native type** based on the processor (int, float, bool, array, or string).
- When a token appears **inside a larger string**, it is interpolated as text.
- Remember to **quote** tokens in YAML (e.g., `' %env(...)% '`) because `%` is a reserved indicator in YAML.

### Variable Resolution with `$_SERVER` Fallback

The firewall checks environment variables in the following order:

1. **`getenv()`** - PHP environment variables (set via `putenv()`, shell environment, or PHP-FPM/Apache configuration)
2. **`$_SERVER`** - PHP superglobal (fallback when `getenv()` returns false)

This fallback behavior is particularly useful in web contexts (Drupal, WordPress, Symfony, Laravel) where configuration is often stored in `$_SERVER` by the web server or application framework.

**Example use case: Nested Array Keys**

```php
// In Drupal's settings.php, Pantheon sets database credentials in $_SERVER
$_SERVER['DB_SETTINGS'] = '{"databases":{"default":{"default":{"username":"db_user","password":"db_pass","host":"dbhost","port":"3306"}}}}';
```

```yaml
# In firewall.yml, you can extract nested values from the JSON
storage:
  type: "Kanopi\\Firewall\\Storage\\DatabaseStorage"
  config:
    connection:
      # Extract values from nested JSON path: databases.default.default.*
      # Each 'key:' processor navigates one level deeper into the JSON structure
      user: '%env(json:key:databases:key:default:key:default:key:username:DB_SETTINGS)%'
      password: '%env(json:key:databases:key:default:key:default:key:password:DB_SETTINGS)%'
      host: '%env(json:key:databases:key:default:key:default:key:host:DB_SETTINGS)%'
      port: '%env(json:key:databases:key:default:key:default:key:port:DB_SETTINGS)%'
```

**Important**: When extracting nested keys from JSON, you must chain `key:` processors for each level of nesting. For example, to access `obj.a.b.c`, use: `json:key:a:key:b:key:c:VAR_NAME`.

**Priority**: When a variable exists in both `getenv()` and `$_SERVER`, `getenv()` takes precedence. This allows you to override server-level configuration with environment-specific values.

**Supported processors (can be chained left→right):**

- **Type Processors**: `string`, `int`, `float`, `bool`, `json` (→ array), `base64`
- **File Operations**: `file` (reads file contents), `resolve` (resolves relative paths)
- **String Operations**: `trim`, `lower`, `upper`, `urlencode`, `urldecode`
- **Array/List Operations**: `csv` (→ list), `query_string` (→ array, preserves duplicate keys), `url` (→ array from `parse_url`)
- **Special Processors**:
  - `default:value` - Provides fallback value if variable doesn't exist
  - `defined` - Returns boolean indicating if variable exists
  - `const` - Retrieves PHP constant instead of environment variable
  - `key:name` - Extracts a key from an array (chain multiple for nested keys)
  - `not` - Logical NOT (negates boolean value)

**Examples**

```yaml
app:
  # Basic type conversions
  env: '%env(string:APP_ENV)%'           # "dev"
  port: '%env(int:APP_PORT)%'            # 8080 (int)
  debug: '%env(bool:APP_DEBUG)%'         # true/false (bool)
  options: '%env(json:APP_JSON)%'        # { key: value } (array)
  secret: '%env(file:SECRET_PATH)%'      # file contents as string
  list: '%env(csv:ALLOWED)%'             # ["a","b","c"]
  params: '%env(query_string:QS)%'       # { foo: "1", bar: ["2","3"] }
  note: "running on %env(APP_ENV)%"      # string interpolation

  # Default values (fallback when variable doesn't exist)
  environment: '%env(default:production:APP_ENV)%'              # Use "production" if not set
  max_size: '%env(int:default:100:MAX_SIZE)%'                   # Default to 100
  enable_feature: '%env(bool:default:false:FEATURE_ENABLED)%'   # Default to false
  cache_dir: '%env(default:/tmp/cache:CACHE_DIR)%'              # Default path

  # Check if variable exists (in getenv() or $_SERVER)
  has_config: '%env(defined:OPTIONAL_CONFIG)%'  # true/false (bool)

  # Use PHP constants
  cache_path: '%env(const:KANOPI_FIREWALL_CACHE_DIR)%'  # From define()

  # Nested JSON key extraction
  db_host: '%env(json:key:database:key:host:CONFIG_JSON)%'
```

**Path resolution for common keys**

Some metadata values are commonly file paths. The loader automatically rewrites **relative** values to **absolute** when they exist on disk, using the **YAML file's directory** as the base. You can target keys with dot‑path patterns and lightweight alternation:

- `*` matches any key at that level
- Alternation per segment: `block|allow`, `{block,allow}`, or `(block|allow)`

**Useful patterns**

```text
logger.*.args.0
(block|allow).Kanopi\Firewall\Plugins\GeoLocation.metadata.reader.db
(block|allow).Kanopi\Firewall\Plugins\Asn.metadata.reader.db
(block|allow).Kanopi\Firewall\Plugins\RateLimit.metadata.storage.config.file
```

With these patterns, paths like `logs/app.log`, `geo/GeoLite2-ASN.mmdb`, or `limits/rate.yml` will be resolved relative to the YAML file and stored as absolute paths at runtime.

## Global Configuration

The global configuration allows for items like the default status code and the default block message template to be
configured. More options to come.

```yaml
global:
  mode: block
  banning_status_code: 429
  banning_message: '{{request.id}} Request Banned'
  require_trusted_proxies: false
  blocking_escalation:
    - window: 300
      offense: 0
    - window: 3600
      duration: 3600
      offense: 1
    - window: 7200
      offense: 3
      duration: 18000
    - window: 7200
      offense: 3
      duration: 0
```

### Trusted Proxies

`require_trusted_proxies` controls how `Firewall::create()` reacts when `Symfony\Component\HttpFoundation\Request::getTrustedProxies()` is empty:

| Value | Behaviour |
|-------|-----------|
| `false` (default) | Logs a `warning` and continues. Suitable for development or when the application is reachable only directly. |
| `true` | Throws `Kanopi\Firewall\Exception\ConfigurationException` and refuses to start. Recommended for production deployments behind a load balancer / CDN / reverse proxy. |

See the trusted-proxies note in [Basic Implementation](#basic-implementation) for the `Request::setTrustedProxies(...)` call you need to add before `Firewall::create()`.

### Mode

The `mode` setting controls how the firewall responds when a request is matched by a blocking plugin. Defaults to `block` if not specified.

| Mode | Evaluates plugins? | Writes to storage? | Terminates request? |
|------|--------------------|--------------------|---------------------|
| `block` | Yes | Yes | Yes (sends HTTP response and exits) |
| `log` | Yes | No | No (logs a warning and allows the request) |
| `exception` | Yes | Yes | No (throws `FirewallBlockedException`) |
| `disabled` | No | No | No (skips all evaluation) |

- **`block`** — Default production behavior. Blocked requests receive an HTTP error response and the script exits.
- **`log`** — Useful for dry-run/audit deployments. Plugins are evaluated normally, but blocks are only logged (at `warning` level) without stopping the request or recording offenses in storage.
- **`exception`** — Throws a `Kanopi\Firewall\Exception\FirewallBlockedException` instead of calling `exit()`. The exception carries the status code (via `getStatusCode()`) and banning message, allowing host frameworks (Laravel, Symfony, etc.) to catch and handle it with their own error responses.
- **`disabled`** — Bypasses the firewall entirely. No plugins are evaluated and the request is immediately allowed. Useful for maintenance or feature-flag toggling.

### Status Code

The status code of the default message can be defined here. By default, it sets it to 400 but can be set to something
else if it is needed.

### Banning Message

The banning message can be configured and dynamically replaced with placeholders. Examples of placeholders can be found
below.

```
* Replace placeholders in a template string with values taken from a Symfony Request
* and/or an additional context array.
*
* Supported placeholders (case-insensitive):
*   • {{ request.method }}          →  GET / POST / …
*   • {{ request.scheme }}          →  http / https
*   • {{ request.host }}            →  example.com
*   • {{ request.path }}            →  /search
*   • {{ request.ip }}              →  client IP (trusts your Symfony trusted proxies config)
*   • {{ request.header.? }}        →  any HTTP header
*   • {{ request.query.? }}         →  ?q=something
*   • {{ request.post.? }}          →  body fields (application/x-www-form-urlencoded, multipart, JSON parsed by you, …)
*   • {{ request.cookie.? }}        →  cookies
```

### Multiple Offenses Defense

Some storage plugins can track multiple offenses from the same attacker over time. You can control how blocking escalates by using the `blocking_escalation` configuration setting.

Below is an example of how to configure it:

```yaml
global:
  blocking_escalation:
    - window: 300
      offense: 0
    - window: 3600
      duration: 3600
      offense: 1
    - window: 7200
      offense: 3
      duration: 18000
    - window: 7200
      offense: 3
      duration: 0
```

Each escalation rule includes the following:

- `window` – Time period in seconds to look back for offenses (e.g., 300 = 5 minutes).

- `offense` – Number of offenses required during the window to trigger the rule.

- `duration` – How long to ban the client (in seconds).

    - Use `0` for a permanent ban.

    - If duration is not set, the plugin's default ban duration will be used.

This system lets you gradually increase penalties for repeat offenders, starting with temporary bans and escalating to permanent blocks if necessary.

## Storage Configuration

Storage defines how the firewall persists blocked IP addresses across requests.

### Available Storage Classes

#### 1. In-Memory Storage

Non-persistent storage that resets with each request. Useful for testing.

```yaml
storage:
  type: "Kanopi\\Firewall\\Storage\\InMemoryStorage"
```

#### 2. File Storage

Persists blocked IPs to the filesystem.

```yaml
storage:
  type: "Kanopi\\Firewall\\Storage\\FileStorage"
  config:
    storage_file: /var/log/firewall/blocked_ips.data
    offense_file: /var/log/firewall/blocked_ip_offenses.data
```

#### 3. Database Storage

Stores blocked IPs in a SQL database using Doctrine DBAL.

```yaml
storage:
  type: "Kanopi\\Firewall\\Storage\\DatabaseStorage"
  config:
    storage_table: firewall_blocked_ips
    offenses_table: firewall_blocked_ip_offenses
    connection:
      # Option 1: Using DSN (recommended)
      dsn: "mysql://user:password@localhost:3306/database?serverVersion=8.0"
      
      # Option 2: Individual parameters
      # dbname: 'my_database'
      # user: 'db_user'
      # password: 'db_password'
      # host: 'localhost'
      # port: 3306
      # driver: 'pdo_mysql'
```

## Plugin Architecture

Plugins are the core components that evaluate incoming requests. They can be configured in two sections:

- **`bypass`**: Plugins here allow requests to pass through without further evaluation
- **`block`**: Plugins here can block requests based on configured rules

### Common Plugin Configuration

All plugins share these configuration options:

```yaml
"Kanopi\\Firewall\\Plugins\\PluginName":
  enable: true              # Whether the plugin is active
  priority: 0               # Execution order (-100 runs before 100)
  metadata: {}              # Plugin-specific configuration
  config: []                # Rules or conditions for the plugin
```

**YAML Syntax Note**: Class names in YAML configuration must be quoted with double backslashes:
- ✅ Correct: `"Kanopi\\Firewall\\Plugins\\IpAddress"`
- ❌ Wrong: `Kanopi\Firewall\Plugins\IpAddress` (missing quotes and single backslash)
- ❌ Wrong: `\Kanopi\Firewall\Plugins\IpAddress` (leading backslash)

This applies to all `type:` declarations (storage backends, rate limit storage) and plugin keys in `block:` and `bypass:` sections.

### Plugin Priority and Execution Order

Plugins execute in order based on their `priority` value (lower numbers run first):

- **-200 to -100**: Early filters (IP whitelists, trusted networks)
- **-99 to -1**: Security checks (geo-blocking, ASN filtering)
- **0**: Default priority (URL rules, user agent checks)
- **1 to 100**: Post-evaluation (rate limiting, logging)

**Important**: Bypass plugins run before block plugins. If any bypass plugin returns `true`, the request is allowed immediately without evaluating block plugins.

**Example: Layered Security**

```yaml
bypass:
  # Run first - whitelist office IPs
  "Kanopi\\Firewall\\Plugins\\IpAddress":
    enable: true
    priority: -200
    config:
      - 192.168.1.0/24

block:
  # Run early - geographic blocking
  "Kanopi\\Firewall\\Plugins\\GeoLocation":
    enable: true
    priority: -100
    config:
      - "country:CN"

  # Run after geo - vulnerability scoring
  "Kanopi\\Firewall\\Plugins\\VulnerabilityScore":
    enable: true
    priority: -50
    config:
      # ... scoring config ...

  # Run last - rate limiting
  "Kanopi\\Firewall\\Plugins\\RateLimit":
    enable: true
    priority: 100
    metadata:
      # ... rate limit config ...
```

### Loading External Plugin Configuration

Plugins can load rules from external files (local or remote) using the `metadata.config` option. This is useful for managing large rule sets separately:

```yaml
block:
  "Kanopi\\Firewall\\Plugins\\VulnerabilityScore":
    enable: true
    priority: -50
    metadata:
      # Load scoring rules from external file(s)
      config:
        - vulnerability-score-rules.yml
        # Can also load from remote URLs
        - https://cdn.example.com/firewall/vuln-patterns.yml
    # Inline config is merged with loaded files
    config:
      risk_levels:
        critical:
          threshold: 100
          block: true
```

The external files use the same structure as the inline `config` section. Multiple files can be specified and will be merged in order. Both local file paths (relative or absolute) and remote URLs are supported.

## Available Plugins

### IP Address Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\IpAddress`

Evaluates requests based on IP addresses, supporting IPv4, IPv6, CIDR blocks, and IP ranges.

#### Configuration Example

```yaml
# In bypass section - whitelist trusted IPs
bypass:
  "Kanopi\\Firewall\\Plugins\\IpAddress":
    enable: true
    priority: -100  # Run early
    config:
      # Single IPv4 address
      - 192.168.1.1
      # Single IPv6 address
      - ::1
      - 2001:db8::1
      # CIDR notation
      - 10.0.0.0/8
      - 172.16.0.0/12
      # IP range (start-end)
      - 192.168.1.100-192.168.1.200

# In block section - blacklist malicious IPs
block:
  "Kanopi\\Firewall\\Plugins\\IpAddress":
    enable: true
    priority: -100
    config:
      - 192.168.1.50
      - 10.10.10.0/24
```

### GeoLocation Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\GeoLocation`

Evaluates requests based on geographic location using MaxMind GeoIP2 databases.

#### Configuration Example

```yaml
block:
  "Kanopi\\Firewall\\Plugins\\GeoLocation":
    enable: true
    priority: 0
    metadata:
      reader:
        # Option 1: Local database file
        type: reader
        db: /path/to/GeoLite2-City.mmdb
        
        # Option 2: MaxMind web service
        # type: client
        # accountId: 123456
        # licenseKey: your_license_key
        # languages: ['en', 'es']
        # options: []
    config:
      # Block specific countries
      - "country:CN"
      - "country:RU"
      - "country.isoCode:KP"
      
      # Block entire continents
      - "continent:AS"
      - "continent.code:AF"
      
      # Block specific cities
      - "city:Moscow"
      - "city.name@contains:Beijing"
      
      # Complex location rules
      - variable: location.timeZone
        operator: equals
        value: "Asia/Shanghai"
```

#### Available Variables

- `country` - Returns country ISO code (e.g., "US")
- `country.isoCode` - Country ISO code
- `country.name` - Full country name
- `continent` - Returns continent code (e.g., "NA")
- `continent.code` - Continent code
- `continent.name` - Full continent name
- `city` - Returns city name
- `city.name` - City name
- `location.latitude` - Latitude coordinate
- `location.longitude` - Longitude coordinate
- `location.timeZone` - Time zone
- `postal` - Returns postal code
- `postal.code` - Postal/ZIP code

### URL Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\Url`

Evaluates requests based on URL components and request parameters.

#### Configuration Example

```yaml
block:
  "Kanopi\\Firewall\\Plugins\\Url":
    enable: true
    priority: 0
    config:
      # Block all POST requests
      - "method:POST"
      
      # Block specific paths
      - "path:/wp-admin"
      - "path@starts_with:/admin"
      - "path@contains:phpmyadmin"
      - "path@regex:/\.(sql|bak|old)$/i"
      
      # Block based on host
      - "host:malicious.example.com"
      - "host@ends_with:.suspicious.com"
      
      # Block based on query parameters
      - "query.cmd@exists"
      - "query.action:delete"
      
      # Block based on POST data
      - "post.username:admin"
      - "post.action@in:drop,truncate,delete"
      
      # Block based on headers
      - "header.user-agent@contains:bot"
      - "header.x-forwarded-for@exists"
      
      # Complex URL rules
      - type: AND
        rules:
          - "method:POST"
          - "path@starts_with:/api"
          - "!header.authorization@exists"
```

#### Available Variables

- `method` - HTTP method (GET, POST, PUT, DELETE, etc.)
- `host` - Hostname from the request
- `path` - URI path (e.g., /admin/users)
- `scheme` - URL scheme (http or https)
- `port` - Port number
- `query.*` - Query parameters (e.g., query.page, query.id)
- `post.*` - POST body parameters
- `header.*` - HTTP headers (e.g., header.user-agent)
- `cookie.*` - Cookie values

### User Agent Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\UserAgent`

Analyzes user agent strings to identify bots, devices, browsers, and operating systems.

#### Configuration Example

```yaml
block:
  "Kanopi\\Firewall\\Plugins\\UserAgent":
    enable: true
    priority: 0
    config:
      # Block all bots
      - "bot:true"
      
      # Block specific device types
      - "device.type:desktop"
      - "device.type@in:smartphone,tablet"
      
      # Block specific browsers
      - "client.name:Internet Explorer"
      - "client.type:browser"
      - "client.version@less_than:10"
      
      # Block specific operating systems
      - "os.name:Windows XP"
      - "os.short_name:WIN"
      - "os.version@less_than:10"
      
      # Block specific brands or models
      - "brand:Huawei"
      - "model@contains:Galaxy"
      
      # Complex user agent rules
      - type: AND
        rules:
          - "bot:false"
          - "client.name:Chrome"
          - "client.version@less_than:80"
```

#### Available Variables

- `bot` - Whether the user agent is a bot ("true" or "false")
- `device.type` - Device type (desktop, smartphone, tablet, etc.)
- `client.name` - Browser or client name
- `client.type` - Client type (browser, mobile app, etc.)
- `client.version` - Client version number
- `os.name` - Operating system name
- `os.short_name` - OS short name (WIN, MAC, LIN, etc.)
- `os.version` - OS version number
- `brand` - Device brand (Apple, Samsung, etc.)
- `model` - Device model

### ASN Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\Asn`

Evaluates requests based on Autonomous System Numbers (ASN) using MaxMind's GeoIP2 ASN database.

#### Configuration Example

```yaml
block:
  "Kanopi\\Firewall\\Plugins\\Asn":
    enable: true
    priority: 0
    metadata:
      reader:
        type: reader
        db: /path/to/GeoLite2-ASN.mmdb
    config:
      # Block specific ASN numbers
      - "asn:13335"  # Cloudflare
      - "asn:15169"  # Google
      
      # Block by organization name
      - "asn_org:CLOUDFLARENET"
      - "asn_org@contains:AMAZON"
      - "asn_org@starts_with:DIGITAL"
```

#### Available Variables

- `asn` - Autonomous System Number
- `asn_org` - Organization name associated with the ASN

### Rate Limit Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\RateLimit`

Implements rate limiting to prevent abuse and DDoS attacks.

#### Configuration Example

```yaml
block:
  "Kanopi\\Firewall\\Plugins\\RateLimit":
    enable: true
    priority: 100  # Run after other plugins
    metadata:
      # Default settings for all paths
      default_rate: 60        # Requests allowed
      default_sample: 60      # Time window in seconds
      default_expiration_time: 300  # Block duration in seconds
      
      # Storage backend for rate limit data
      storage:
        # Option 1: Redis (recommended for production)
        type: "Kanopi\\Firewall\\RateLimitStorage\\RedisRateLimitStorage"
        config:
          redis:
            host: localhost
            port: 6379
            # Authentication options:
            # auth: "password"
            # auth: ["password"]
            # auth: ["username", "password"]
        
        # Option 2: File storage
        # type: "Kanopi\\Firewall\\RateLimitStorage\\FileRateLimitStorage"
        # config:
        #   file: /var/log/firewall/ratelimit.data
        
        # Option 3: Database storage
        # type: "Kanopi\\Firewall\\RateLimitStorage\\DatabaseRateLimitStorage"
        # config:
        #   storage-table: firewall_ratelimit
        #   connection:
        #     dsn: "mysql://user:pass@localhost/db"
        
        # Option 4: In-memory (testing only)
        # type: "Kanopi\\Firewall\\RateLimitStorage\\InMemoryRateLimitStorage"
    
    config:
      # Strict rate limit for homepage
      - path: "/"
        rate: 10
        sample: 60
      
      # API endpoints with higher limits
      - path: "/api/*"
        rate: 100
        sample: 60
      
      # Admin area with moderate limits
      - path: "/admin/*"
        rate: 30
        sample: 60
      
      # Login endpoint with strict limits
      - path: "/login"
        rate: 5
        sample: 300  # 5 attempts per 5 minutes
      
      # Use regex for complex patterns
      - path: "/\.(php|asp|aspx)$/i"
        rate: 1
        sample: 3600  # Block direct script access
```

#### Path Patterns

- Exact match: `/login`
- Wildcard: `/api/*` (matches /api/users, /api/posts/123, etc.)
- Regex: `/^\/api\/v[0-9]+\//` (matches /api/v1/, /api/v2/, etc.)

### Vulnerability Score Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\VulnerabilityScore`

Evaluates requests based on a comprehensive scoring system that combines multiple risk factors to determine if a request should be blocked. This plugin provides fine-grained control over security policies by assigning scores to various request characteristics and blocking based on cumulative risk levels.

#### Key Features

- **Multi-Factor Scoring**: Evaluates HTTP methods, geographic origin, ASN, patterns, and user agents
- **Configurable Risk Levels**: Define custom thresholds with different blocking behaviors
- **Pattern Detection**: Built-in detection for SQL injection, XSS, command injection, and custom patterns
- **Geographic Intelligence**: Optional integration with GeoIP databases for country and ASN scoring
- **Dynamic Response**: Different status codes and expiration times based on risk level

#### Configuration Example

```yaml
block:
  "Kanopi\\Firewall\\Plugins\\VulnerabilityScore":
    enable: true
    priority: -50  # Run after basic filters but before rate limiting
    metadata:
      # Default response settings
      default_expiration_time: 3600
      status_code: 403
      
      # Optional: GeoIP database for country scoring
      country_reader:
        type: reader
        db: /path/to/GeoLite2-Country.mmdb
      
      # Optional: ASN database for network scoring
      asn_reader:
        type: reader
        db: /path/to/GeoLite2-ASN.mmdb
      
      # Load scoring rules from external file
      config:
        - vulnerability-score-rules.yml
    
    config:
      scoring:
        # HTTP Method Scoring
        methods:
          GET: 0          # Safe read operations
          HEAD: 0
          OPTIONS: 1      # CORS probing
          POST: 10        # Write operations
          PUT: 15         # Full replacements
          PATCH: 15       # Partial updates
          DELETE: 20      # Destructive operations
          TRACE: 50       # Security risk
          CONNECT: 50     # Proxy tunneling
        
        # Country-based Scoring
        countries:
          # Low risk countries
          US: 1
          CA: 1
          GB: 1
          DE: 1
          
          # Medium risk countries
          BR: 10
          IN: 10
          
          # High risk countries
          CN: 30
          RU: 30
          KP: 50
          IR: 40
        
        # ASN (Network) Scoring
        asn:
          # Trusted networks
          "15169": 1      # Google
          "13335": 1      # Cloudflare
          "16509": 1      # Amazon AWS
          
          # Suspicious networks
          "4134": 30      # Chinanet
          "45102": 25     # Alibaba Cloud
        
        # ASN Organization Pattern Matching
        asn_patterns:
          "vpn": 20
          "proxy": 20
          "hosting": 15
          "datacenter": 10
          "residential": 5
        
        # Malicious Pattern Detection
        patterns:
          # SQL Injection
          - pattern: "/(union.*select|select.*from|drop.*table)/i"
            score: 40
            type: regex
            locations: ["uri", "query_string", "body"]
          
          # XSS Attacks
          - pattern: "/<script[^>]*>.*?<\/script>/i"
            score: 35
            type: regex
            locations: ["uri", "query_string", "body"]
          
          - pattern: "javascript:"
            score: 30
            type: contains
            locations: ["uri", "query_string", "body"]
          
          # Command Injection
          - pattern: "/(;|\||&&|`|\$\()/i"
            score: 25
            type: regex
            locations: ["uri", "query_string"]
          
          # Path Traversal
          - pattern: "/(\.\.[\/\\]){2,}/i"
            score: 30
            type: regex
            locations: ["uri", "query_string"]
          
          # Sensitive Files
          - pattern: ".git"
            score: 20
            type: contains
            locations: ["uri"]
          
          - pattern: ".env"
            score: 25
            type: contains
            locations: ["uri"]
          
          # Admin Access
          - pattern: "admin"
            score: 10
            type: contains
            locations: ["uri"]
        
        # User Agent Scoring
        user_agents:
          # Known attack tools
          - pattern: "sqlmap"
            score: 50
            type: contains
          
          - pattern: "nikto"
            score: 45
            type: contains
          
          - pattern: "nmap"
            score: 40
            type: contains
          
          # Suspicious agents
          - pattern: "python-requests"
            score: 15
            type: contains
          
          - pattern: "curl"
            score: 10
            type: contains
          
          # Empty user agent
          - pattern: "^$"
            score: 20
            type: regex
      
      # Risk Level Configuration
      risk_levels:
        low:
          threshold: 0
          block: false      # Monitor only
          
        medium:
          threshold: 25
          block: false      # Still monitoring
          
        high:
          threshold: 50
          block: true
          status_code: 403
          expiration_time: 3600    # 1 hour
          
        critical:
          threshold: 75
          block: true
          status_code: 403
          expiration_time: 86400   # 24 hours
          
        extreme:
          threshold: 100
          block: true
          status_code: 403
          expiration_time: 604800  # 7 days
```

#### Scoring Components

##### 1. Method Scoring
Assigns scores based on HTTP methods, with higher scores for potentially dangerous operations.

##### 2. Country Scoring
Uses GeoIP database to identify request origin and assign scores based on geographic risk assessment.

##### 3. ASN Scoring
Evaluates the Autonomous System Number of the request origin, identifying datacenter, VPN, or residential connections.

##### 4. Pattern Detection
Searches for malicious patterns in various parts of the request:
- **Locations**: `uri`, `query_string`, `body`, `headers`
- **Types**: `regex`, `contains`, `exact`
- **Patterns**: SQL injection, XSS, command injection, path traversal, etc.

##### 5. User Agent Analysis
Identifies and scores suspicious or malicious user agents, including security tools and bots.

#### Risk Levels

Each risk level can be configured with:
- `threshold`: Minimum score to trigger this level
- `block`: Whether to block requests at this level
- `status_code`: HTTP status code to return when blocking
- `expiration_time`: How long to block the IP address (in seconds)

#### Advanced Usage Examples

##### Example 1: E-commerce Site Protection

```yaml
config:
  scoring:
    methods:
      GET: 0
      POST: 5        # Allow normal form submissions
      DELETE: 50     # High risk for e-commerce
    
    patterns:
      # Credit card testing
      - pattern: "/4[0-9]{12}(?:[0-9]{3})?/"
        score: 60
        type: regex
        locations: ["body", "query_string"]
      
      # Price manipulation attempts
      - pattern: "price="
        score: 30
        type: contains
        locations: ["query_string", "body"]
      
      # Admin panel access
      - pattern: "/admin|/backend|/dashboard/i"
        score: 20
        type: regex
        locations: ["uri"]
    
    user_agents:
      # Block automated scanners
      - pattern: "bot|crawler|spider"
        score: 15
        type: regex
  
  risk_levels:
    high:
      threshold: 40
      block: true
      status_code: 403
      expiration_time: 7200
```

##### Example 2: API Protection

```yaml
config:
  scoring:
    methods:
      GET: 0
      POST: 5
      PUT: 10
      DELETE: 30
    
    patterns:
      # GraphQL introspection
      - pattern: "__schema"
        score: 40
        type: contains
        locations: ["body", "query_string"]
      
      # Mass assignment attempts
      - pattern: "/(role|admin|permission)=/i"
        score: 35
        type: regex
        locations: ["body"]
    
    user_agents:
      # Require proper user agents for API access
      - pattern: "^$"
        score: 50  # No user agent = suspicious
        type: regex
  
  risk_levels:
    medium:
      threshold: 30
      block: true
      status_code: 429  # Too Many Requests
      expiration_time: 300
```

##### Example 3: Geographic Restrictions with Exceptions

```yaml
config:
  scoring:
    countries:
      # Blocked regions
      CN: 50
      RU: 50
      KP: 100
      
      # Allowed regions
      US: 0
      CA: 0
      GB: 0
    
    # But allow known good ASNs from blocked countries
    asn:
      "45102": -40  # Alibaba Cloud (reduces China score)
      "13335": -40  # Cloudflare (reduces any country score)
    
  risk_levels:
    high:
      threshold: 40
      block: true
```

#### Integration with Other Plugins

The VulnerabilityScore plugin works well with other firewall plugins:

```yaml
# Use IP whitelist to bypass scoring
bypass:
  "Kanopi\\Firewall\\Plugins\\IpAddress":
    enable: true
    priority: -200
    config:
      - 192.168.1.0/24  # Internal network

# Apply vulnerability scoring
block:
  "Kanopi\\Firewall\\Plugins\\VulnerabilityScore":
    enable: true
    priority: -50
    config: # ... scoring configuration ...
  
  # Then apply rate limiting to scored requests
  "Kanopi\\Firewall\\Plugins\\RateLimit":
    enable: true
    priority: 100
    config:
      - path: "/*"
        rate: 60
        sample: 60
```

#### Performance Considerations

- The plugin evaluates all scoring factors for each request
- Pattern matching can be CPU intensive with many patterns
- Consider using Redis or database storage for better performance at scale
- Place the plugin after basic filters (like IP blocking) for efficiency

#### Debugging and Monitoring

The plugin logs detailed information about scoring decisions:

```yaml
logger:
  - class: Monolog\Handler\StreamHandler
    args:
      - /var/log/firewall/vulnerability-scores.log
      - Monolog\Level::Debug
    formatter:
      class: Monolog\Formatter\JsonFormatter
```

Log entries include:
- Total score calculated
- Individual component scores
- Risk level determined
- Blocking decision

### CRS (OWASP Core Rule Set) Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\Crs`

Evaluates each request against the [OWASP Core Rule Set](https://coreruleset.org/) — the same ruleset that powers ModSecurity, Coraza, and most commercial WAFs. Detects SQL injection, XSS, LFI, RFI, RCE, PHP / Java injection, session fixation, protocol-level attacks, and known scanner traffic. Backed by the [`kanopi/crs-engine`](https://packagist.org/packages/kanopi/crs-engine) composer package, which parses CRS source files into a runtime-optimised cache and refreshes weekly from upstream.

#### Key Features

- **Real CRS rules**: Parses the upstream `REQUEST-*.conf` files directly — no hand-translation, no divergence from CRS behavior.
- **Paranoia levels (1-4)**: Trade detection coverage against false-positive rate the same way CRS deployments tune ModSecurity.
- **Per-rule / per-category disable**: Silence known false positives without touching upstream rule files.
- **Monitor vs block modes**: Roll the plugin out in monitor mode first; the firewall logs what would have been blocked without rejecting traffic.
- **In-process rule cache**: ~3-4 ms per request once warm (FPM worker steady state). Zero extension dependencies — no APCu / OPcache preload required.
- **Auto-refreshed rules**: The `crs-engine` package CI fetches new CRS releases weekly and opens a reviewable PR; `composer update` pulls the latest curated bump.

#### Configuration Example

```yaml
block:
  "Kanopi\\Firewall\\Plugins\\Crs":
    enable: true
    # CRS work is non-trivial — run cheap IP / UA / ASN filters first.
    priority: 50
    config:
      # Paranoia level 1-4. 1 is the recommended starting point.
      paranoia: 1
      # block (default) or monitor (log without blocking)
      mode: block
      # HTTP status returned for blocked requests
      block_status: 403
      # How long the firewall remembers the offending IP (seconds)
      block_duration: 3600
      # Known false-positives — disable by rule ID
      disabled_rules: [942130]
      # Or by category. Available categories:
      #   sqli, xss, lfi, rfi, rce, php, java, session_fixation,
      #   protocol_attack, protocol_enforcement, method_enforcement,
      #   scanner, multipart, generic, response_leak_sql,
      #   response_leak_java, response_leak_php, response_leak_iis,
      #   web_shell, correlation
      disabled_categories: []
      # Override anomaly-score thresholds
      anomaly_thresholds:
        critical: 5
        error: 4
        warning: 3
        notice: 2
      # Custom rule cache location — defaults to vendor/kanopi/crs-engine/rules
      # rules_path: /etc/firewall/crs-rules
```

#### Coverage

Currently the plugin handles request-side evaluation: every CRS rule in `REQUEST-*.conf` runs against the incoming request. Response-side rules (RESPONSE-* files — SQL error / stack-trace / PHP warning leakage detection) are tracked under issue #69 and will land as a follow-up.

The four CRS rules that rely on `libinjection` (`@detectSQLi` / `@detectXSS` — rules 941100, 941180, 942100, 942500) are parsed but not evaluated; the engine logs them as `parser warnings` in `vendor/kanopi/crs-engine/rules/manifest.json`. CRS's regex-based SQLi/XSS rules in the same files run normally and provide the bulk of the detection.

#### What gets logged

Blocked requests log at `info` level with full context:
- `rule_id` — the CRS rule that fired the block
- `total_score` — accumulated anomaly score
- `scores` — per-category breakdown (sqli, xss, lfi, etc.)
- `matched_rule` — the rule's human-readable message
- `matched_data` — the substring of the request that matched

Non-blocking matches (monitor mode, or rules whose action is `pass`) log at `debug` level.

## Conditional Logic

The firewall supports three formats for defining conditions:

### 1. Simple Format

Quick and readable syntax for common conditions:

```yaml
# Basic equality
- "variable:value"

# With operator
- "variable@operator:value"

# Negation
- "!variable:value"
- "!variable@operator:value"

# Numeric comparisons
- "rate > 100"
- "client.version <= 10"

# Array matching
- "tags@contains:spam,malware#all"  # Must contain all
- "tags@contains:bot,crawler#any"   # Must contain at least one
```

#### Supported Operators

- `equals` (default)
- `not_equals`
- `contains`
- `starts_with`
- `ends_with`
- `regex`
- `in`
- `greater_than` (>)
- `less_than` (<)
- `greater_than_or_equal` (>=)
- `less_than_or_equal` (<=)
- `exists`

### 2. Complex Format

Detailed configuration with full control:

```yaml
- variable: method
  operator: in
  value: [GET, POST]
  negate: false
  case_sensitive: true
  matches: any  # For array values: any, all, none, some
```

### 3. Grouped Format

Combine multiple conditions with logical operators:

```yaml
- type: AND
  rules:
    - "method:POST"
    - "path@starts_with:/api"
    - type: OR
      rules:
        - "header.authorization@exists"
        - "query.api_key@exists"
```

## Logging Configuration

The firewall uses [Monolog](https://github.com/Seldaek/monolog) for flexible logging, so any Monolog handler can be wired up through the `logger` key. Each entry under `logger` is a separate handler — combine as many as you need (file + Slack + email is a common pattern).

Each handler entry accepts:

- `class` — fully qualified handler class name (must implement `Monolog\Handler\HandlerInterface`).
- `args` — positional constructor arguments, in order.
- `formatter` *(optional)* — `class` + `args` for a `Monolog\Formatter\FormatterInterface` implementation, applied to that handler.

Log levels are passed as strings like `Monolog\Level::Info` (Debug, Info, Notice, Warning, Error, Critical, Alert, Emergency). Relative log file paths (e.g., `args[0]` for `StreamHandler`) are resolved **relative to the YAML file** that declares them.

> **Heads up:** several Monolog handlers require additional PHP extensions or third-party packages. Slack/IFTTT/Pushover/Telegram need `ext-curl`; `SendGridHandler` and `SymfonyMailerHandler` may require `composer require` of the relevant transport package. See the [Monolog handler docs](https://seldaek.github.io/monolog/doc/02-handlers-formatters-processors.html) for each handler's prerequisites.

### File logging

Write every event to a flat file:

```yaml
logger:
  - class: Monolog\Handler\StreamHandler
    args:
      - /var/log/firewall/firewall.log
      - Monolog\Level::Info
    formatter:
      class: Monolog\Formatter\LineFormatter
      args:
        - "[%datetime%] [%level_name%] [%context.plugin%] %message% %context% %extra%\n"
        - "Y-m-d H:i:s"
```

### Rotating file logging

Rotate logs daily and keep the last seven days. Useful when StreamHandler files grow unbounded:

```yaml
logger:
  - class: Monolog\Handler\RotatingFileHandler
    args:
      - /var/log/firewall/firewall.log
      - 7                          # maxFiles to keep (0 = unlimited)
      - Monolog\Level::Info
```

### JSON-structured logging

Emit one JSON object per line — easy to ingest into Loki, ELK, Datadog, etc:

```yaml
logger:
  - class: Monolog\Handler\StreamHandler
    args:
      - /var/log/firewall/firewall.ndjson
      - Monolog\Level::Info
    formatter:
      class: Monolog\Formatter\JsonFormatter
```

### Syslog

Forward events to the host's syslog (handy on managed/cloud platforms that scrape syslog automatically):

```yaml
logger:
  - class: Monolog\Handler\SyslogHandler
    args:
      - firewall                   # ident / tag
      - user                       # facility — see below
      - Monolog\Level::Warning
```

> `SyslogHandler` accepts a facility *name* (string) such as `user`, `daemon`, `mail`, `auth`, `local0`–`local7`. The PHP `LOG_*` constants are integers that YAML cannot reference; passing the literal string `LOG_USER` triggers `UnexpectedValueException`. Stick to the lowercase names above.

### PHP error log

Pipe firewall events into the configured PHP `error_log` — useful in shared hosting or when you don't control filesystem paths:

```yaml
logger:
  - class: Monolog\Handler\ErrorLogHandler
    args:
      - 0                          # 0 = operating system, 4 = SAPI
      - Monolog\Level::Warning
```

### Email alerts

Send an email when something critical happens. `NativeMailerHandler` uses PHP's `mail()` — no extra package required:

```yaml
logger:
  - class: Monolog\Handler\NativeMailerHandler
    args:
      - security@example.com       # to (string or list of recipients)
      - "Firewall Alert"           # subject
      - noreply@example.com        # from
      - Monolog\Level::Critical
```

For higher-volume alerting via SendGrid (requires `ext-curl`):

```yaml
logger:
  - class: Monolog\Handler\SendGridHandler
    args:
      - apikey                     # SendGrid API user (use "apikey" for API key auth)
      - "${SENDGRID_API_KEY}"      # API key
      - noreply@example.com        # from
      - security@example.com       # to (string or list)
      - "Firewall Alert"           # subject
      - Monolog\Level::Critical
```

### Slack alerts

Post directly to a Slack channel through an [Incoming Webhook](https://api.slack.com/messaging/webhooks). Requires `ext-curl`:

```yaml
logger:
  - class: Monolog\Handler\SlackWebhookHandler
    args:
      - "${SLACK_WEBHOOK_URL}"     # webhook URL
      - "#security-alerts"         # channel override (or null)
      - "Firewall"                 # bot username
      - true                       # useAttachment
      - ":shield:"                 # iconEmoji
      - false                      # useShortAttachment
      - true                       # includeContextAndExtra
      - Monolog\Level::Warning
```

If you prefer the Slack Web API (legacy token-based handler):

```yaml
logger:
  - class: Monolog\Handler\SlackHandler
    args:
      - "${SLACK_BOT_TOKEN}"       # Slack bot token
      - "#security-alerts"         # channel
      - "Firewall"                 # username
      - true                       # useAttachment
      - ":shield:"                 # iconEmoji
      - Monolog\Level::Critical
```

### Pushover (push notifications)

Send mobile push notifications via [Pushover](https://pushover.net/):

```yaml
logger:
  - class: Monolog\Handler\PushoverHandler
    args:
      - "${PUSHOVER_APP_TOKEN}"    # application API token
      - "${PUSHOVER_USER_KEY}"     # user/group key (string or list)
      - "Firewall Alert"           # notification title
      - Monolog\Level::Critical
```

### IFTTT webhooks

Trigger an [IFTTT Maker](https://ifttt.com/maker_webhooks) applet — useful for chaining custom automations (SMS, smart lights, voice assistants, etc.):

```yaml
logger:
  - class: Monolog\Handler\IFTTTHandler
    args:
      - firewall_alert             # event name configured in the IFTTT applet
      - "${IFTTT_MAKER_KEY}"       # Maker webhook key
      - Monolog\Level::Error
```

IFTTT receives three values: `value1` = channel, `value2` = level name, `value3` = message.

### Telegram bot

Send messages to a Telegram channel or chat via a bot token:

```yaml
logger:
  - class: Monolog\Handler\TelegramBotHandler
    args:
      - "${TELEGRAM_BOT_TOKEN}"    # bot token from @BotFather
      - "@my_security_channel"     # chat ID or @channel
      - Monolog\Level::Critical
```

### Per-handler severity thresholds

Each handler entry has its own `level` argument, so you can tune verbosity per destination. The pattern below writes every Info-and-above event to file but only escalates Critical events to email:

```yaml
logger:
  - class: Monolog\Handler\StreamHandler
    args:
      - /var/log/firewall/firewall.log
      - Monolog\Level::Info

  - class: Monolog\Handler\NativeMailerHandler
    args:
      - security@example.com
      - "Firewall Alert"
      - noreply@example.com
      - Monolog\Level::Critical
```

> Handlers that wrap other handlers (e.g. `FingersCrossedHandler`, `BufferHandler`, `FilterHandler`, `GroupHandler`) take a `HandlerInterface` as a constructor argument, which the YAML loader cannot construct recursively. To use those, build the logger programmatically with `Monolog\Logger` and inject it via `LoggingFactory::setLogger()` before calling `Firewall::create()`.

### Combining multiple handlers

You can stack any number of handlers — each entry under `logger` is independent. A common production setup tees everything to a file, surfaces warnings to syslog, and pages humans via Slack/Pushover only on critical events:

```yaml
logger:
  # Everything to file
  - class: Monolog\Handler\RotatingFileHandler
    args:
      - /var/log/firewall/firewall.log
      - 14
      - Monolog\Level::Info

  # Warnings and above to syslog
  - class: Monolog\Handler\SyslogHandler
    args:
      - firewall
      - user
      - Monolog\Level::Warning

  # Critical events ping the on-call channel
  - class: Monolog\Handler\SlackWebhookHandler
    args:
      - "${SLACK_WEBHOOK_URL}"
      - "#security-oncall"
      - "Firewall"
      - true
      - ":rotating_light:"
      - false
      - true
      - Monolog\Level::Critical

  # And buzz a phone if no one acks
  - class: Monolog\Handler\PushoverHandler
    args:
      - "${PUSHOVER_APP_TOKEN}"
      - "${PUSHOVER_USER_KEY}"
      - "Firewall CRITICAL"
      - Monolog\Level::Critical
```

For the full catalogue of available handlers (Telegram, Mandrill, Loggly, Elasticsearch, Sentry via PSR, etc.), see the [Monolog handlers reference](https://seldaek.github.io/monolog/doc/02-handlers-formatters-processors.html).

## Dynamic Configuration Overrides

For dynamic environments (Docker, multi-site installations), you can override YAML configuration with PHP arrays:

```php
<?php
$overrides = [
    // Override storage location
    '[storage][config][file]' => $_ENV['FIREWALL_STORAGE_PATH'] ?? '/tmp/firewall.data',
    
    // Override GeoIP database path
    '[block][\Kanopi\Firewall\Plugins\GeoLocation][metadata][reader][db]' => $_ENV['GEOIP_DB_PATH'],
    
    // Override Redis connection
    '[block][\Kanopi\Firewall\Plugins\RateLimit][metadata][storage][config][redis][host]' => $_ENV['REDIS_HOST'] ?? 'localhost',
    
    // Disable a plugin
    '[block][\Kanopi\Firewall\Plugins\UserAgent][enable]' => false,
];

\Kanopi\Firewall\Firewall::create([__DIR__ . '/config.yml'], $overrides)->evaluate();
```

## Platform Integration

### Drupal

Add to `settings.php` before the container configuration:

```php
// Load composer autoloader if not already loaded
if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require_once __DIR__ . '/../vendor/autoload.php';
}

// Initialize firewall
if (class_exists('\Kanopi\Firewall\Firewall')) {
    $firewall_config = __DIR__ . '/firewall.yml';
    if (file_exists($firewall_config)) {
        \Kanopi\Firewall\Firewall::create([$firewall_config])->evaluate();
    }
}
```

### WordPress

Add to `wp-config.php` after `ABSPATH` is defined but before `wp-settings.php`:

```php
// Firewall integration
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
    
    if (class_exists('\Kanopi\Firewall\Firewall')) {
        $firewall_config = __DIR__ . '/firewall/config.yml';
        if (file_exists($firewall_config)) {
            \Kanopi\Firewall\Firewall::create([$firewall_config])->evaluate();
        }
    }
}
```

### Symfony

Add to `public/index.php` before the kernel boot:

```php
use App\Kernel;
use Kanopi\Firewall\Firewall;

require_once dirname(__DIR__).'/vendor/autoload_runtime.php';

return function (array $context) {
    // Initialize firewall
    if (class_exists(Firewall::class)) {
        $configPath = dirname(__DIR__) . '/config/firewall.yml';
        if (file_exists($configPath)) {
            Firewall::create([$configPath])->evaluate();
        }
    }
    
    return new Kernel($context['APP_ENV'], (bool) $context['APP_DEBUG']);
};
```

### Laravel

Add to `public/index.php` after the autoloader:

```php
require __DIR__.'/../vendor/autoload.php';

// Firewall integration
if (class_exists('\Kanopi\Firewall\Firewall')) {
    $firewall_config = __DIR__ . '/../config/firewall.yml';
    if (file_exists($firewall_config)) {
        \Kanopi\Firewall\Firewall::create([$firewall_config])->evaluate();
    }
}

$app = require_once __DIR__.'/../bootstrap/app.php';
```

## Advanced Examples

### Multi-layered Security Configuration

```yaml
# High-performance storage
storage:
  type: "Kanopi\\Firewall\\Storage\\DatabaseStorage"
  config:
    storage_table: firewall_blocked
    connection:
      dsn: "mysql://firewall:secure@localhost/security"

# Whitelist trusted sources
bypass:
  # Office IPs
  "Kanopi\\Firewall\\Plugins\\IpAddress":
    enable: true
    priority: -200
    config:
      - 203.0.113.0/24  # Office network
      - 198.51.100.50   # VPN endpoint

# Comprehensive blocking rules
block:
  # Geographic restrictions
  "Kanopi\\Firewall\\Plugins\\GeoLocation":
    enable: true
    priority: -100
    metadata:
      reader:
        type: reader
        db: /usr/share/GeoIP/GeoLite2-City.mmdb
    config:
      # Block high-risk countries
      - type: OR
        rules:
          - "country@in:CN,RU,KP,IR"
          - "continent:AF"
  
  # Block suspicious user agents
  "Kanopi\\Firewall\\Plugins\\UserAgent":
    enable: true
    priority: -50
    config:
      # Block all bots except Google and Bing
      - type: AND
        rules:
          - "bot:true"
          - "!client.name@in:Googlebot,Bingbot"
      
      # Block outdated browsers
      - type: OR
        rules:
          - variable: client.name
            operator: equals
            value: "Internet Explorer"
          - type: AND
            rules:
              - "client.name:Chrome"
              - "client.version < 80"
  
  # Vulnerability scoring for comprehensive threat assessment
  "Kanopi\\Firewall\\Plugins\\VulnerabilityScore":
    enable: true
    priority: -25
    metadata:
      country_reader:
        type: reader
        db: /usr/share/GeoIP/GeoLite2-Country.mmdb
      asn_reader:
        type: reader
        db: /usr/share/GeoIP/GeoLite2-ASN.mmdb
    config:
      scoring:
        methods:
          DELETE: 30
          PUT: 20
          POST: 10
        countries:
          CN: 25
          RU: 25
          KP: 50
        patterns:
          - pattern: "/(union.*select|drop.*table)/i"
            score: 50
            type: regex
            locations: ["uri", "query_string", "body"]
          - pattern: "/<script|javascript:/i"
            score: 40
            type: regex
            locations: ["uri", "query_string", "body"]
      risk_levels:
        high:
          threshold: 50
          block: true
          status_code: 403
          expiration_time: 7200
  
  # URL-based protection
  "Kanopi\\Firewall\\Plugins\\Url":
    enable: true
    priority: 0
    config:
      # Protect admin areas
      - type: AND
        rules:
          - "path@starts_with:/admin"
          - "!header.authorization@exists"
      
      # Block vulnerability scanners
      - "path@regex:/(\.git|\.env|\.htaccess|wp-config\.php|phpmyadmin)/i"
      
      # Block SQL injection attempts
      - "query@regex:/(union.*select|select.*from|insert.*into|drop.*table)/i"
  
  # Aggressive rate limiting
  "Kanopi\\Firewall\\Plugins\\RateLimit":
    enable: true
    priority: 100
    metadata:
      default_rate: 120
      default_sample: 60
      storage:
        type: "Kanopi\\Firewall\\RateLimitStorage\\RedisRateLimitStorage"
        config:
          redis:
            host: redis.internal
            port: 6379
            auth: ["default", "redis_password"]
    config:
      # API rate limits by endpoint
      - path: "/api/v1/auth/*"
        rate: 5
        sample: 300
      
      - path: "/api/v1/public/*"
        rate: 100
        sample: 60
      
      - path: "/api/v1/private/*"
        rate: 30
        sample: 60

# Comprehensive logging
logger:
  # General log file
  - class: Monolog\Handler\RotatingFileHandler
    args:
      - /var/log/firewall/firewall.log
      - 7  # Keep 7 days
      - Monolog\Level::Info
    formatter:
      class: Monolog\Formatter\JsonFormatter
  
  # Security alerts
  - class: Monolog\Handler\StreamHandler
    args:
      - /var/log/firewall/security-alerts.log
      - Monolog\Level::Warning
    formatter:
      class: Monolog\Formatter\LineFormatter
      args:
        - "[%datetime%] %level_name%: %message% %context%\n"
```

### Custom Plugin Implementation

Create a custom plugin to implement specific business logic:

```php
<?php

namespace App\Security\Firewall\Plugins;

use Kanopi\Firewall\Plugins\AbstractPluginBase;
use Symfony\Component\HttpFoundation\Request;

class ApiKeyValidator extends AbstractPluginBase
{
    private array $validApiKeys;
    
    public function __construct(array $metadata = [], array $config = [])
    {
        parent::__construct($metadata, $config);
        
        // Load API keys from configuration or database
        $this->validApiKeys = $metadata['api_keys'] ?? [];
    }
    
    public function getName(): string
    {
        return 'API Key Validator';
    }
    
    public function getDescription(): string
    {
        return 'Validates API keys for authenticated endpoints';
    }
    
    public function evaluate(Request $request): bool
    {
        // Only check API endpoints
        if (!str_starts_with($request->getPathInfo(), '/api/')) {
            return false;
        }
        
        // Check for API key in header or query
        $apiKey = $request->headers->get('X-API-Key') 
                  ?? $request->query->get('api_key');
        
        if (!$apiKey) {
            $this->logger?->warning('Missing API key', [
                'ip' => $request->getClientIp(),
                'path' => $request->getPathInfo(),
            ]);
            return true; // Block request
        }
        
        if (!in_array($apiKey, $this->validApiKeys, true)) {
            $this->logger?->warning('Invalid API key', [
                'ip' => $request->getClientIp(),
                'api_key' => substr($apiKey, 0, 8) . '...',
            ]);
            return true; // Block request
        }
        
        return false; // Allow request
    }
    
    public function getStatusCode(): int
    {
        return 401; // Unauthorized
    }
}
```

Register the custom plugin in your configuration:

```yaml
block:
  \App\Security\Firewall\Plugins\ApiKeyValidator:
    enable: true
    priority: -150  # Run before rate limiting
    metadata:
      api_keys:
        - "sk_live_abcd1234567890"
        - "sk_live_efgh0987654321"
```

## Testing

The firewall includes a comprehensive test suite. Run tests with:

```bash
# Run all tests
composer test

# Run with coverage
composer test:coverage

# Run specific test suite
./vendor/bin/phpunit tests/Unit/Plugins/

# Run integration tests
./vendor/bin/phpunit tests/Integration/
```

### Example Test Case

```php
<?php

use PHPUnit\Framework\TestCase;
use Kanopi\Firewall\Firewall;
use Symfony\Component\HttpFoundation\Request;

class FirewallTest extends TestCase
{
    public function testBlocksMaliciousIp(): void
    {
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'config' => ['192.168.1.100']
                ]
            ]
        ];
        
        $firewall = Firewall::create([$config]);
        
        // Create a request from the blocked IP
        $request = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.100'
        ]);
        
        // The firewall should block this request
        $this->expectException(\Exception::class);
        $firewall->evaluate($request);
    }
}
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Clone the repository
2. Install dependencies: `composer install`
3. Run tests: `composer test`
4. Check code style: `composer cs`
5. Run static analysis: `composer stan`

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [https://github.com/kanopi/firewall/wiki](https://github.com/kanopi/firewall/wiki)
- **Issues**: [https://github.com/kanopi/firewall/issues](https://github.com/kanopi/firewall/issues)
- **Discussions**: [https://github.com/kanopi/firewall/discussions](https://github.com/kanopi/firewall/discussions)

## Credits

Lite Firewall is developed and maintained by [Kanopi Studios](https://kanopi.com).

Special thanks to:
- The Symfony team for the excellent HttpFoundation component
- MaxMind for the GeoIP2 databases
- The Monolog team for the flexible logging library
- All our contributors and users