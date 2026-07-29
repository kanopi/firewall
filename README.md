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
  - [Filesystem Processors (opt-in)](#filesystem-processors-opt-in)
- [Global Configuration](#global-configuration)
  - [Multiple Offenses Defense](#multiple-offenses-defense)
- [Storage Configuration](#storage-configuration)
  - [Custom Storage Backends](#custom-storage-backends)
  - [Custom Rate Limit Storage](#custom-rate-limit-storage)
- [Plugin Architecture](#plugin-architecture)
  - [Challenge Response Type](#challenge-response-type)
- [Available Plugins](#available-plugins)
  - [IP Address Plugin](#ip-address-plugin)
  - [GeoLocation Plugin](#geolocation-plugin)
  - [URL Plugin](#url-plugin)
  - [User Agent Plugin](#user-agent-plugin)
  - [ASN Plugin](#asn-plugin)
  - [Rate Limit Plugin](#rate-limit-plugin)
  - [Vulnerability Score Plugin](#vulnerability-score-plugin)
  - [CRS (OWASP Core Rule Set) Plugin](#crs-owasp-core-rule-set-plugin)
  - [AbuseIPDB Plugin](#abuseipdb-plugin)
- [Conditional Logic](#conditional-logic)
- [Logging Configuration](#logging-configuration)
  - [Sensitive Value Redaction](#sensitive-value-redaction)
  - [Injecting Your Own Logger](#injecting-your-own-logger)
- [Dynamic Configuration Overrides](#dynamic-configuration-overrides)
- [Error Handling & Exceptions](#error-handling--exceptions)
- [Platform Integration](#platform-integration)
- [Advanced Examples](#advanced-examples)
- [Testing](#testing)
- [Legacy format (deprecated)](#legacy-format-deprecated)
- [Additional Documentation](#additional-documentation)
- [Contributing](#contributing)

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

    plugins:
        - plugin: "Kanopi\\Firewall\\Plugins\\Url"
          response: block
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

The firewall configuration consists of five main sections:

| Section     | Purpose                                                                    | Required |
|-------------|----------------------------------------------------------------------------|----------|
| `global`    | Defines global configuration settings                                      | No       |
| `storage`   | Defines where blocked IP addresses are persisted                           | Yes      |
| `plugins`   | Ordered list of plugin entries that allow (`response: allow`), challenge (`response: challenge`), or block (`response: block`) traffic | No       |
| `challenge` | Settings for the interstitial flow (provider, HMAC secret, cookie / header names). Required iff any plugin uses `response: challenge`. See [Challenge Response Type](#challenge-response-type). | Conditional |
| `logger`    | Monolog handlers for logging firewall events                               | No       |

> **Legacy formats `bypass:` / `block:`** are still accepted and auto-normalized into `plugins:` entries at load time. See [Legacy format (deprecated)](#legacy-format-deprecated) at the end of this document. New configs should use the `plugins:` array.

## Configuration Loading & Includes

The firewall supports **modular configuration** via a top‑level `configs:` key in any YAML file. Paths listed under `configs:` are loaded and **merged** into the current file.

**Rules & behavior**

- Paths in `configs:` can be:
  - **Relative** (resolved against the directory of the YAML file that declares them)
  - **Absolute**
  - **Remote URLs** (e.g., `https://example.com/firewall-rules.yml`; cached locally with configurable TTL)
  - Use the `{config_dir}` token (expanded to the current YAML's directory)
  - Use the `{presets_dir}` token (expanded to this package's `presets/` directory inside `vendor/`, so you can include a shipped preset without knowing your vendor layout — e.g. `"{presets_dir}/malicious-requests.yml"`)
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

plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\GeoLocation"
    response: block
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

- **Type Processors**: `string`, `int`, `float`, `bool`, `json` (→ array), `base64`, `enum:FQCN` (→ backed enum case, matched by value then by case name)
- **File Operations**: `resolve` (resolves relative paths), plus the opt-in `file` and `require` processors — see [Filesystem Processors](#filesystem-processors-opt-in) below
- **String Operations**: `trim`, `lower`, `upper`, `urlencode`, `urldecode`
- **Array/List Operations**: `csv` (→ list), `query_string` (→ array, preserves duplicate keys), `url` (→ array from `parse_url`), `shuffle` (randomizes an array in place)
- **Special Processors**:
  - `default:value` - Provides fallback value if variable doesn't exist
  - `defined` - Returns boolean indicating if variable exists
  - `const` - Retrieves PHP constant instead of environment variable
  - `key:name` - Extracts a key from an array (chain multiple for nested keys)
  - `raw_key:name` - Like `key:` but does not treat the key name as further processors; use when a key contains a `:`
  - `not` - Logical NOT (negates boolean value)
  - `safe:fallback` - Wraps every processor to its right in a try/catch and returns `fallback` if any of them fail (missing variable, bad JSON, absent key). Useful for optional platform config — see [Pantheon presets](presets/README.md#pantheon-platform-presets).

**Examples**

```yaml
app:
  # Basic type conversions
  env: '%env(string:APP_ENV)%'           # "dev"
  port: '%env(int:APP_PORT)%'            # 8080 (int)
  debug: '%env(bool:APP_DEBUG)%'         # true/false (bool)
  options: '%env(json:APP_JSON)%'        # { key: value } (array)
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

  # Backed enum resolution — resolves to an enum *instance*, so only use it
  # for keys read by your own code (e.g. a custom plugin's metadata).
  tier: '%env(enum:App\Enum\ServiceTier:SERVICE_TIER)%'  # 'gold' or 'Gold' → ServiceTier::Gold

  # Tolerate a missing / malformed variable
  db_name: '%env(safe:fallback_db:json:key:name:DB_SETTINGS)%'    # "fallback_db" on any failure
```

### Filesystem Processors (opt-in)

The `file:` (read a file's contents) and `require:` (include a PHP file and use its return value) processors are **disabled by default**. Because their path comes from an environment variable, enabling them turns any env-var injection into a local file inclusion — or, for `require:`, remote code execution.

Using either one without opting in raises `ConfigurationException` from `TokenSubstitute`. Note where that exception ends up:

- **Calling `TokenSubstitute::substitute()` directly** — the exception propagates to you.
- **A token inside a YAML config** — `Config::loadFile()` catches it and drops that file from the merge, so with the default `require_config: false` the firewall starts with **a config missing those rules** — potentially an empty one that allows every request. The failure is logged at `error` level with the reason. Set [`global.require_config: true`](#requiring-the-config-to-load) to make it a startup failure instead.

Opt in during bootstrap, **before any config is loaded**, and constrain the reads to directories you control:

```php
use Kanopi\Firewall\Utility\TokenSubstitute;

// Allow file: reads, but only from within /etc/firewall/secrets.
TokenSubstitute::enableUnsafeProcessors(['file'], ['/etc/firewall/secrets']);

\Kanopi\Firewall\Firewall::create([__DIR__ . '/firewall.yml'])->evaluate();
```

```yaml
global:
  banning_message: '%env(file:BANNED_TEMPLATE_PATH)%'   # /etc/firewall/secrets/banned.html
```

- **First argument** — processors to enable. Only `file` and `require` are valid; anything else throws `ConfigurationException`.
- **Second argument** — absolute base directories. The resolved `realpath()` of the target must sit under one of them, otherwise loading fails. Passing an empty list disables the prefix check entirely and is **not recommended in production** — do it only if you have vetted every path your environment variables can produce.
- Base directories must already exist; a directory that does not resolve throws `ConfigurationException`.
- `TokenSubstitute::resetUnsafeProcessors()` clears the opt-in again. It exists for test suites, not for request-time use.

Prefer `file:` over `require:` whenever you can — reading a secret is far less dangerous than executing a path an attacker may influence.

**Path resolution for common keys**

Some metadata values are commonly file paths. The loader automatically rewrites **relative** values to **absolute** when they exist on disk, using the **YAML file's directory** as the base. You can target keys with dot‑path patterns and lightweight alternation:

- `*` matches any key at that level
- Alternation per segment: `block|allow`, `{block,allow}`, or `(block|allow)`

**Useful patterns**

```text
logger.*.args.0

# New plugins: array format
plugins.*.metadata.reader.db
plugins.*.metadata.storage.config.file
plugins.*.metadata.config.*

# Legacy block:/bypass: format (still supported)
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
  require_config: false
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

### Requiring the config to load

Config loading is lenient: a config file that is missing, unreadable, or malformed contributes nothing to the merge rather than raising. That is convenient for optional config paths and dangerous everywhere else — a firewall with no plugins allows every request. `require_config` decides which of those you get:

| Value | Behaviour |
|-------|-----------|
| `false` (default) | Every config input that failed to load is logged at `error` level (`Firewall config file failed to load — its rules are NOT active`, with the path and the reason), and the firewall starts with whatever did load. |
| `true` | Throws `Kanopi\Firewall\Exception\ConfigurationException` listing every input that failed, and refuses to start. Recommended for production. |

The exception message carries the underlying reason, so a typo, a permissions problem, a YAML syntax error, a circular `configs:` include, an unresolvable `%env(...)%` token, and a disabled `file:` / `require:` processor are all distinguishable:

```
global.require_config is enabled and 1 config input(s) failed to load:
/var/www/firewall.yml — File does not exist.
```

There is one case the YAML flag cannot cover: when the config file that *would* have carried `require_config: true` is itself the one that failed to load. Set it outside the YAML for that:

```php
// Bootstrap, before Firewall::create().
define('KANOPI_FIREWALL_REQUIRE_CONFIG', true);

// …or as an override, which is read even when no config file parsed.
Firewall::create([__DIR__ . '/firewall.yml'], ['[global][require_config]' => true]);
```

`global.require_config` wins over the constant when both are present, including when it is explicitly `false`.

Plugin-level config files (`metadata.config`) are reported the same way — an unreadable one logs `Plugin config file failed to load — its rules are NOT active` and leaves that plugin with only its inline `config:` entries. `require_config` does not escalate those to a startup failure.

### Mode

The `mode` setting controls how the firewall responds when a request is matched by a blocking plugin. Defaults to `block` if not specified.

| Mode | Evaluates plugins? | Writes to storage? | Terminates request? |
|------|--------------------|--------------------|---------------------|
| `block` | Yes | Yes | Yes (sends HTTP response and exits) |
| `log` | Yes | No | No (logs a warning and allows the request) |
| `exception` | Yes | Yes | No (throws — see [Error Handling & Exceptions](#error-handling--exceptions)) |
| `disabled` | No | No | No (skips all evaluation) |

- **`block`** — Default production behavior. Blocked requests receive an HTTP error response and the script exits.
- **`log`** — Useful for dry-run/audit deployments. Plugins are evaluated normally, but blocks are only logged (at `warning` level) without stopping the request or recording offenses in storage. This includes clients already on the durable storage blocklist: the hit is logged, the ban is neither enforced nor extended, and the request continues.
- **`exception`** — Throws instead of calling `exit()`, allowing host frameworks (Laravel, Symfony, etc.) to catch and render their own responses. A block throws `FirewallBlockedException`, which carries the status code (via `getStatusCode()`) and banning message. The challenge flow throws `ChallengeRequiredException` or `ChallengeSolvedException` instead — see [Error Handling & Exceptions](#error-handling--exceptions) for all of them and what to do with each.
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

### Custom Storage Backends

`storage.type` accepts **any** fully-qualified class name that implements `Kanopi\Firewall\Storage\StorageInterface`, so you can persist blocks anywhere — DynamoDB, Memcached, a platform-specific KV store, your app's ORM. Extend `AbstractStorageBase` and you only have to implement the persistence methods; the base class already provides `getKey()`, `isBlocked()`, and `getStorageData()` (request serialization).

```php
<?php

namespace App\Firewall;

use Kanopi\Firewall\Storage\AbstractStorageBase;

class MemcachedStorage extends AbstractStorageBase
{
    private \Memcached $client;

    public function __construct(array $config = [])
    {
        parent::__construct($config);
        $this->client = new \Memcached();
        $this->client->addServer($config['host'] ?? 'localhost', $config['port'] ?? 11211);
    }

    public function set(string $key, array $value, int $expire = 0): bool
    {
        return $this->client->set($key, $value, $expire);
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $value = $this->client->get($key);

        return $value === false ? $default : $value;
    }

    public function exists(string $key): bool
    {
        return $this->client->get($key) !== false;
    }

    public function delete(string $key): bool
    {
        return $this->client->delete($key);
    }

    public function reset(): bool
    {
        return $this->client->flush();
    }

    public function expire(): bool
    {
        // Memcached expires items itself — nothing to sweep.
        return true;
    }

    public function addToExpire(string $key, int $amount): bool
    {
        return $this->client->touch($key, time() + $amount);
    }

    public function recordOffense(string $key): bool
    {
        $offenses = $this->client->get($key . ':offenses') ?: [];
        $offenses[] = time();

        return $this->client->set($key . ':offenses', $offenses);
    }

    public function countOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX): int
    {
        $offenses = $this->client->get($key . ':offenses') ?: [];

        return count(array_filter($offenses, fn (int $t): bool => $t >= $start && $t <= $end));
    }
}
```

```yaml
storage:
  type: "App\\Firewall\\MemcachedStorage"
  config:
    host: cache.internal
    port: 11211
```

**Contract summary** (see `src/Storage/StorageInterface.php` for full PHPDoc):

| Method | Responsibility |
|---|---|
| `set()` / `get()` / `exists()` / `delete()` | Store, read, test, and remove one block record. `$expire` is an absolute unix timestamp; `0` means never. |
| `reset()` | Drop everything. Used by tests and administrative resets. |
| `expire()` | Sweep records past their expiry. Return `true` for backends that expire on their own. |
| `addToExpire()` | Extend an existing block by `$amount` seconds. |
| `recordOffense()` / `countOffenses()` | Offense history — this is what [Multiple Offenses Defense](#multiple-offenses-defense) escalation reads. A backend that no-ops these cannot escalate bans. |
| `getKey()` | Derive the storage key from the request. `AbstractStorageBase` uses the client IP. |
| `isBlocked()` | Return the block record or `false`. Provided by `AbstractStorageBase`. |
| `getStorageData()` | Build the record written on a block (serialized request + plugin). Provided by `AbstractStorageBase`. |

If `storage.type` is missing, is not loadable, or does not implement `StorageInterface`, the factory falls back to `InMemoryStorage` — which means **blocks will not persist between requests**. It logs `Storage type defaulted to InMemoryStorage` at `info` level with a `reason` of `not_string`, `class_not_found`, or `invalid_interface`. Check for that message first when a custom backend appears to do nothing.

### Custom Rate Limit Storage

`metadata.storage.type` on the Rate Limit plugin works the same way for `Kanopi\Firewall\RateLimitStorage\RateLimitStorageInterface`. The contract is only two methods, and extending `AbstractRateLimitStorage` gives you `$this->config` plus the logging trait:

```php
<?php

namespace App\Firewall;

use Kanopi\Firewall\RateLimitStorage\AbstractRateLimitStorage;

class DynamoRateLimitStorage extends AbstractRateLimitStorage
{
    public function recordRequest(string $key, int $timestamp): void
    {
        // Append $timestamp to the list held for $key.
    }

    public function countRequests(string $key, int $start, int $end): int
    {
        // Count timestamps for $key within the inclusive window.
        return 0;
    }
}
```

An unresolvable rate limit storage type falls back to `InMemoryRateLimitStorage`, so counters reset every request and limits effectively never fire. Look for `Rate limit storage type defaulted to InMemoryRateLimitStorage` at `info` level, which carries the same `reason` field.

This factory also accepts an **already-instantiated** `RateLimitStorageInterface` object and uses it as-is, which is how you inject a backend built by your framework's container. Pass it through [Dynamic Configuration Overrides](#dynamic-configuration-overrides), since YAML cannot carry an object:

```php
Firewall::create([__DIR__ . '/firewall.yml'], [
    '[plugins][0][metadata][storage][type]' => $myRateLimitStorage,
]);
```

## Plugin Architecture

Plugins are the core components that evaluate incoming requests. They are configured as an ordered list under the top-level `plugins:` key. Each entry declares one plugin instance and its `response` mode — either `allow` (let the request through), `block` (reject the request), or `challenge` (require the visitor to solve an interstitial before continuing).

### Common Plugin Configuration

All plugin entries share the same shape:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\PluginName"   # Fully qualified class name
    response: block          # 'allow', 'block', or 'challenge'
    weight: 0                # Execution order within its response group (lower runs first)
    enable: true             # Whether the plugin entry is active
    metadata: {}             # Plugin-specific configuration (DB readers, storage, etc.)
    config: []               # Rules or conditions for the plugin
```

The same class can appear multiple times in the list — each entry becomes its own plugin instance, so you can split rules across instances with different weights or response modes.

**YAML Syntax Note**: The `plugin:` value must be quoted with double backslashes:
- ✅ Correct: `plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"`
- ❌ Wrong: `plugin: Kanopi\Firewall\Plugins\IpAddress` (missing quotes and single backslash)
- ❌ Wrong: `plugin: \Kanopi\Firewall\Plugins\IpAddress` (leading backslash)

This also applies to all `type:` declarations (storage backends, rate limit storage).

### Plugin Execution Order

The firewall evaluates `response: allow` entries first (sorted by `weight`, lower runs first). If any allow plugin matches, the request is permitted immediately and no other plugins run. Otherwise:

1. `response: challenge` entries run next. If one matches and the visitor does **not** already hold a valid pass token, an interstitial is served and the request is paused until the challenge is solved.
2. `response: block` entries run last and the first match rejects the request.

A valid pass token (set by a previously solved challenge) short-circuits the challenge bucket but does **not** suppress block plugins. See [Challenge Response Type](#challenge-response-type) below.

A POST to `challenge.path` (the challenge submission endpoint) skips all three buckets — otherwise an unrelated rule matching the magic path would trap a legitimate visitor in a challenge loop with no way out. The durable storage block list still applies: an IP that already earned a block is rejected before the solution is verified, so it cannot solve its way back out.

Suggested weight ranges:

- **-200 to -100**: Early filters (IP allow-lists, trusted networks)
- **-99 to -1**: Security checks (geo-blocking, ASN filtering)
- **0**: Default (URL rules, user agent checks)
- **1 to 100**: Post-evaluation (rate limiting, logging)

**Example: Layered Security**

```yaml
plugins:
  # Run first - allow trusted office IPs
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -200
    enable: true
    config:
      - 192.168.1.0/24

  # Run early - geographic blocking
  - plugin: "Kanopi\\Firewall\\Plugins\\GeoLocation"
    response: block
    weight: -100
    enable: true
    config:
      - "country:CN"

  # Run after geo - vulnerability scoring
  - plugin: "Kanopi\\Firewall\\Plugins\\VulnerabilityScore"
    response: block
    weight: -50
    enable: true
    config:
      # ... scoring config ...

  # Run last - rate limiting
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 100
    enable: true
    metadata:
      # ... rate limit config ...
```

### Challenge Response Type

`response: challenge` serves an interstitial (a CAPTCHA-style proof-of-effort page) when a plugin matches, instead of rejecting the request outright. A visitor who solves the challenge is issued an HMAC-signed pass token that short-circuits any future `response: challenge` plugin until the token expires.

The pass token is:

- **Signed** with the configured `challenge.secret` (HMAC-SHA256) so it cannot be forged.
- **IP-bound** — the token only verifies for the same client IP that solved the challenge.
- **Audience-bound** — the token carries an `aud` claim and only verifies against the instance that issued it. See [Scoping tokens across instances](#scoping-tokens-across-instances).
- **Delivered two ways** — as an `HttpOnly; Secure; SameSite=Strict` cookie *and* as a value the interstitial JS writes to `localStorage` so SPA callers can attach it to XHRs via a custom header (defaults to `X-Firewall-Challenge`).
- **Expires** after `metadata.default_expiration_time` seconds for the matched plugin (default `3600`).

#### Minimum configuration

```yaml
challenge:
  provider: math                # 'math' is the built-in; or a FQCN that implements ChallengeProviderInterface
  secret: "${FIREWALL_SECRET}"  # REQUIRED. Long random string, ideally from an env var.
  cookie_name: fw_challenge_pass
  header_name: X-Firewall-Challenge
  path: /_firewall/challenge    # The URL the interstitial POSTs to

plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Asn"
    response: challenge
    weight: -10
    enable: true
    metadata:
      default_expiration_time: 3600   # Pass token TTL in seconds
    config:
      - "asn:AS14618"   # Show the challenge to AWS traffic
```

If any plugin uses `response: challenge`, `challenge.secret` is **required**. Startup fails fast with `ConfigurationException` when it is empty — the firewall will not silently fall back to plaintext tokens.

#### Single-use solutions

A stateless provider verifies a solution purely from the posted payload, so the same payload keeps verifying until it expires. For a proof-of-work challenge that quietly defeats the point: an attacker solves one challenge and hands the payload to as many clients as they like, each minting its own IP-bound pass token, and the per-solve cost is amortised to nothing.

Providers can opt out of that by implementing `Kanopi\Firewall\Challenge\SingleUseSolutionInterface`, which hands the firewall an identifier for the solution in the current request. The firewall records it in the configured storage backend and refuses any later submission carrying the same identifier. `altcha` implements this; a solved payload is accepted exactly once.

Two consequences worth knowing:

- **The challenge flow now writes to storage.** Records are small (one per solved challenge) and expire on their own when the underlying challenge would have gone stale. With `InMemoryStorage` they do not survive the process, so use a shared backend if you serve challenges from more than one worker.
- **The check is read-then-write, not atomic.** Two submissions of the same solution arriving in the same instant can both succeed. This shrinks the reuse window from the full challenge lifetime to microseconds, which is the part that matters — the attack being closed is redistribution over seconds or minutes, not winning a race.

`math` deliberately does **not** implement it: its signed state is `answer|expiry`, and with only nine possible answers two visitors served in the same second routinely share one, so treating that value as single-use would reject legitimate solvers.

#### Scoping tokens across instances

A pass token attests "this client solved *a* challenge" — so if two Firewall instances share a `challenge.secret`, they would accept each other's tokens without further scoping. That matters when the challenges differ in strength: a token earned on the trivial `math` challenge could otherwise be replayed against a route protected by `altcha`, and the weakest challenge in your deployment would set the effective security of every route that shares the secret.

Tokens therefore carry an `aud` claim, which defaults to the configured provider name and is covered by the signature. A `math` token will not verify against an `altcha` instance.

If you run **the same provider** in several places with the same secret — say a low-value public route and a sensitive admin area — the default audiences are identical, so set them apart explicitly:

```yaml
challenge:
  provider: altcha
  secret: "${FIREWALL_SECRET}"
  audience: admin-portal   # defaults to the provider name
```

The alternative is to give each instance its own `challenge.secret`, which isolates them just as effectively.

> **Upgrade note.** Pass tokens minted before the `aud` claim existed are rejected, because verification fails closed rather than treating a missing audience as a match. The visible effect is that everyone holding a live pass token is challenged once more after deploying. Tokens are short-lived (default one hour), so this clears on its own.

#### Built-in providers

Two providers ship with the firewall — set `challenge.provider` to either short name:

- **`math`** — asks "What is A + B?" with single-digit operands. Low-friction proof-of-effort, no JS bundle, no external script load. Defeats the laziest bots; trivial for a human.
- **`altcha`** — embeds the [ALTCHA](https://altcha.org/docs/v2/) v2 widget with a pre-computed challenge (no server round-trip to fetch one). The visitor's browser brute-forces `SHA-256(salt + N) == challenge`; the salt embeds an expiry and the challenge is HMAC-signed with `challenge.secret`, so the server stays stateless. Privacy-respecting, and imposes a per-solve CPU cost on bots. Solved challenges are single-use — see [Single-use solutions](#single-use-solutions).

  The widget script is pinned to an exact version and served with a Subresource Integrity digest. To self-host it, or to serve it from a host your CSP already allows, set both options — supplying `widget_src` without `widget_integrity` emits no `integrity` attribute, since a digest that does not match the bytes would block the script entirely:

  ```yaml
  challenge:
    provider: altcha
    provider_options:
      widget_src: /assets/altcha.min.js
      widget_integrity: 'sha384-…'   # openssl dgst -sha384 -binary altcha.min.js | openssl base64 -A
  ```

  The bundle is an ES module, so it is loaded with `<script type="module">`. If you host it yourself, keep that in mind: a classic script tag fails with `Unexpected token 'export'`.

For stronger bot resistance (Turnstile, hCaptcha, reCAPTCHA, etc.), implement `Kanopi\Firewall\Challenge\ChallengeProviderInterface` and set `challenge.provider` to its FQCN.

#### Writing a custom provider

A provider owns both halves of the round-trip: rendering the interstitial, and verifying what comes back. Providers must be **stateless** — embed whatever you need to verify the answer in the interstitial itself (a hidden field, signed with the shared `TokenManager`) rather than storing a per-challenge record. That is what lets the firewall scale horizontally without a shared session store.

```php
<?php

namespace App\Firewall;

use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Challenge\TokenManager;
use Symfony\Component\HttpFoundation\Request;

class TurnstileProvider implements ChallengeProviderInterface
{
    // The factory passes the shared TokenManager to every provider. Use it
    // to sign your own per-challenge state; ignore it if you don't need to.
    public function __construct(private readonly TokenManager $tokenManager)
    {
    }

    public function getName(): string
    {
        return 'turnstile';
    }

    public function renderInterstitial(Request $request, array $context): string
    {
        // $context carries: submit_url, redirect_to, ttl, cookie_name, header_name.
        // Echo redirect_to and ttl back as hidden fields — the Firewall reads
        // them off the POST to size and target the pass token.
        return <<<HTML
        <!DOCTYPE html>
        <html lang="en"><body>
          <form method="post" action="{$context['submit_url']}">
            <div class="cf-turnstile" data-sitekey="YOUR_SITE_KEY"></div>
            <input type="hidden" name="redirect_to" value="{$context['redirect_to']}">
            <input type="hidden" name="ttl" value="{$context['ttl']}">
            <button type="submit">Continue</button>
          </form>
          <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
        </body></html>
        HTML;
    }

    public function verifySolution(Request $request): bool
    {
        $token = (string) $request->request->get('cf-turnstile-response', '');

        // Verify server-side against the provider's siteverify endpoint.
        // Return FALSE on any failure — never throw.
        return $token !== '' && $this->verifyWithCloudflare($token, $request);
    }
}
```

```yaml
challenge:
  provider: "App\\Firewall\\TurnstileProvider"
  secret: "${FIREWALL_SECRET}"
  path: /_firewall/challenge
```

Requirements and gotchas:

- **Escape everything you interpolate.** `redirect_to` originates from the request URI. The built-in `MathChallengeProvider` runs every substitution through `htmlspecialchars()`; do the same.
- **Echo back `redirect_to` and `ttl`** as form fields named exactly that. The Firewall reads them from the POST to decide where to send the visitor and how long to mint the pass token for. Omit them and you get `/` and 3600s.
- **`verifySolution()` must never throw.** It runs on attacker-controlled input; return `false` for anything you don't like.
- **Register via FQCN**, not a short name. `challenge.provider` only resolves `math` as a built-in; everything else must be a loadable class implementing the interface, or `create()` throws `ConfigurationException`.
- **The constructor signature is fixed** — `ChallengeProviderFactory` always calls `new $class($tokenManager)`. Read any further configuration from your own environment or constants.
- Use `$this->tokenManager->sign()` / `verifySignature()` if you need tamper-proof state in the form. You do **not** need to mint the pass token — the Firewall does that once `verifySolution()` returns `true`.

#### How dispatch interacts with allow / block

| Visitor state                          | Result                                       |
|----------------------------------------|----------------------------------------------|
| Matched by an `allow` plugin           | Allowed (challenge skipped).                 |
| Holds a valid pass token + matches `challenge` | Allowed (challenge bucket skipped).  |
| No token, matches a `challenge` plugin | Interstitial served; original URL is remembered for the post-success redirect. |
| Matches a `block` plugin               | Blocked, even if a valid pass token is held. |

### Loading External Plugin Configuration

Plugins can load rules from external files (local or remote) using the `metadata.config` option. This is useful for managing large rule sets separately:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\VulnerabilityScore"
    response: block
    weight: -50
    enable: true
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
plugins:
  # Allow list - trusted IPs bypass further evaluation
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -100   # Run early
    enable: true
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

  # Block list - reject malicious IPs
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: block
    weight: -100
    enable: true
    config:
      - 192.168.1.50
      - 10.10.10.0/24
```

### GeoLocation Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\GeoLocation`

Evaluates requests based on geographic location using MaxMind GeoIP2 databases.

#### Obtaining the databases

The plugin needs a `.mmdb` database. `bin/update_geoip.sh` fetches all three editions the library can use (`GeoLite2-City`, `GeoLite2-Country`, `GeoLite2-ASN` — the last one is for the [ASN Plugin](#asn-plugin)) into a directory you name:

```bash
mkdir -p /var/lib/geoip
bash bin/update_geoip.sh YOUR_MAXMIND_LICENSE_KEY /var/lib/geoip
```

- Both arguments are required and the target directory must already exist.
- The script currently downloads from a public mirror of the GeoLite2 databases, so the license key argument is validated as non-empty but not actually used for the download. Keep passing one — the direct-from-MaxMind path is retained in the script and the argument will be needed again when it is re-enabled.
- MaxMind refreshes GeoLite2 twice weekly. Run this on a schedule (cron, or a build step) rather than once at install; stale geolocation data quietly produces wrong verdicts.

For manual downloads, MaxMind web-service configuration, and Docker volume mounting, see [example/README.md](example/README.md#geoip-database-setup).

#### Configuration Example

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\GeoLocation"
    response: block
    weight: 0
    enable: true
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
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    weight: 0
    enable: true
    config:
      # Block all POST requests
      - "method:POST"

      # Block specific paths
      - "path:/wp-admin"
      - "path@starts_with:/admin"
      - "path@contains:phpmyadmin"
      - 'path@regex:/\.(sql|bak|old)$/i'

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
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\UserAgent"
    response: block
    weight: 0
    enable: true
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
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Asn"
    response: block
    weight: 0
    enable: true
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
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 100   # Run after other plugins
    enable: true
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

        # Option 4: PSR-6 cache pool
        # type: "Kanopi\\Firewall\\RateLimitStorage\\CacheRateLimitStorage"
        # config:
        #   # Class implementing Psr\Cache\CacheItemPoolInterface
        #   adaptor: "Symfony\\Component\\Cache\\Adapter\\FilesystemAdapter"
        #   # Constructor arguments, spread in order
        #   args: ['firewall', 0, '/var/cache/firewall']
        #   ttl: 3600

        # Option 5: In-memory (testing only)
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
      - path: '/\.(php|asp|aspx)$/i'
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
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\VulnerabilityScore"
    response: block
    weight: -50   # Run after basic filters but before rate limiting
    enable: true
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
          - pattern: '/(;|\||&&|`|\$\()/i'
            score: 25
            type: regex
            locations: ["uri", "query_string"]
          
          # Path Traversal
          - pattern: '/(\.\.[\/\\]){2,}/i'
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
plugins:
  # Use IP allow-list to bypass scoring
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -200
    enable: true
    config:
      - 192.168.1.0/24  # Internal network

  # Apply vulnerability scoring
  - plugin: "Kanopi\\Firewall\\Plugins\\VulnerabilityScore"
    response: block
    weight: -50
    enable: true
    config: # ... scoring configuration ...

  # Then apply rate limiting to scored requests
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 100
    enable: true
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

> ### Upgrading from a release built on `crs-engine` 0.1.0
>
> This plugin now requires `crs-engine` ^1.0, which is the first version where the engine actually enforces. In 0.1.0 the detection pipeline was substantially inert — the anomaly-evaluation rules could never fire, `TX:` targets never resolved, and `skipAfter` silently discarded the rest of the ruleset. **Traffic that used to pass will now be rejected**, because previously very little was.
>
> Roll it out with `mode: monitor` first. Let it run over real traffic, group the `contributing_rules` on the debug log lines by rule ID, and build your `disabled_rules` list from what you actually see before you let it block. CRS at paranoia 1 does flag some ordinary editorial content — a support ticket containing `cat /etc/hosts | grep` scores 15 and would be rejected — so on a CMS this step is not optional.

#### Configuration Example

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Crs"
    response: block
    # CRS work is non-trivial — run cheap IP / UA / ASN filters first.
    weight: 50
    enable: true
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
      #   scanner, multipart, generic, response_leak, response_leak_sql,
      #   response_leak_java, response_leak_php, response_leak_iis,
      #   response_leak_ruby, web_shell, correlation, blocking_evaluation
      # Do not disable blocking_evaluation — it is how anomaly scoring
      # rejects anything at all.
      disabled_categories: []
      # Anomaly-score thresholds. There are exactly two — see
      # "Anomaly scores and thresholds" below before reaching for these.
      anomaly_thresholds:
        # Request-side score at or above which the request is rejected.
        inbound: 5
        # Response-side equivalent. Inert until response evaluation lands (#69).
        outbound: 4
      # Custom rule cache location — defaults to vendor/kanopi/crs-engine/rules
      # rules_path: /etc/firewall/crs-rules
```

#### Anomaly scores and thresholds

A matching rule adds points to the request's anomaly score, weighted by the rule's CRS severity — critical contributes 5, error 4, warning 3, notice 2. Those per-severity weights are fixed by CRS and are not configurable through this plugin.

Once the accumulated score reaches the threshold, CRS rule 949110 rejects the request. The two thresholds are:

| Key | Default | Controls |
|---|---|---|
| `inbound` | `5` | Request-side threshold — the score at or above which a request is rejected. |
| `outbound` | `4` | Response-side equivalent. Not reached yet; this plugin does not call `evaluateResponse()` (issue #69). |

At the default of 5, a single critical rule is enough to reject. Raise it to require corroboration from several rules, lower it to reject on weaker evidence:

```php
$payload = ['id' => "1' UNION SELECT 1,2,3--"];   // scores 10: rules 942190 + 942360

(new Crs([], ['anomaly_thresholds' => ['inbound' => 5]]))->evaluate($request);    // true  — rejected
(new Crs([], ['anomaly_thresholds' => ['inbound' => 500]]))->evaluate($request);  // false — allowed
```

The severity-named spellings `critical` (= `inbound`) and `error` (= `outbound`) are still accepted, so config written before the rename keeps working — the plugin translates them, which also keeps `crs-engine`'s deprecation notice out of your logs. Any other key, including the `warning` and `notice` that earlier versions of this document showed, has never had any effect; the plugin logs a warning naming what it ignored rather than accepting it silently. If both spellings of one threshold are present, `inbound` / `outbound` win.

> **A block is attributed to rule 949110, not to the rule that caught the payload.**
> 949110 is the CRS rule that compares the score to the threshold, so it is the `rule_id` on every anomaly-score block. **Never put it in `disabled_rules`** — that switches off anomaly blocking entirely. The rules worth excluding are in `contributing_rules` on the same log line.

To tune a false positive, in rough order of precision:

- **`disabled_rules`** — the precise lever. Take the IDs from `contributing_rules` in the block's log line.
- **`disabled_categories`** — blunter, when a whole class of rules is wrong for your app. Note `blocking_evaluation` is a category: disabling it turns off anomaly blocking, so treat it as off-limits.
- **`anomaly_thresholds.inbound`** — raise it to require more corroboration before rejecting. Affects everything, so prefer the two above when you know which rule is wrong.
- **`paranoia`** — lower it to drop the aggressive rule tiers wholesale.
- **`mode: monitor`** — evaluates and logs but never rejects. The safe setting while you build an exclusion list.

#### Coverage

Currently the plugin handles request-side evaluation: every CRS rule in `REQUEST-*.conf` runs against the incoming request. Response-side rules (RESPONSE-* files — SQL error / stack-trace / PHP warning leakage detection) are tracked under issue #69 and will land as a follow-up.

The four CRS rules that rely on `libinjection` (`@detectSQLi` / `@detectXSS` — rules 941100, 941180, 942100, 942500) are parsed but not evaluated; the engine logs them as `parser warnings` in `vendor/kanopi/crs-engine/rules/manifest.json`. CRS's regex-based SQLi/XSS rules in the same files run normally and provide the bulk of the detection.

#### What gets logged

Blocked requests log at `info` level with full context:
- `rule_id` — the CRS rule that fired the block. For an anomaly-score block this is always **949110**, the rule that compares the score to the threshold — not the rule that caught the payload, and not something to put in `disabled_rules`.
- `contributing_rules` — the rules that actually detected something, in match order. **These are the IDs to feed to `disabled_rules`.**
- `total_score` — accumulated anomaly score
- `scores` — per-category breakdown (sqli, xss, lfi, etc.)
- `matched_rule` — the first matching rule's human-readable message
- `matched_data` — the substring of the request that matched
- `operator_errors` / `truncations` — see below

Non-blocking matches (monitor mode, or a score under the threshold) log at `debug` level with the same `contributing_rules`, which is what makes monitor mode usable for building an exclusion list.

Separately, the plugin logs at `warning` level when `operator_errors` or `truncations` is non-empty — a rule that could not run, or an inspection cap that engaged. Both mean part of the request went unexamined, so a clean verdict is weaker evidence than it looks. This fires even when nothing matched, because that is exactly when a silent gap in coverage is most likely to be believed.

#### Inspecting the verdict programmatically

`evaluate()` returns a plain bool, which is all the firewall needs to make a decision. When you want the full CRS verdict — to surface in an admin UI, forward to a SIEM, or drive your own routing — `Crs::getLastVerdict()` returns the `Kanopi\Crs\CrsVerdict` from the most recent evaluation, or `null` if the plugin has not evaluated anything yet.

The plugin instances the firewall builds internally are not exposed, so use this by driving the plugin directly, alongside (or instead of) the firewall:

```php
use Kanopi\Firewall\Plugins\Crs;
use Symfony\Component\HttpFoundation\Request;

$request = Request::createFromGlobals();

$crs = new Crs(metadata: [], config: [
    'paranoia' => 1,
    'mode' => 'monitor',   // Score and report without blocking.
]);

// evaluate() returns TRUE when the plugin matched — i.e. when CRS would
// block the request. See PluginInterface::evaluate().
$matched = $crs->evaluate($request);

$verdict = $crs->getLastVerdict();
if ($verdict !== null) {
    $siem->send([
        'blocked'       => $verdict->isBlocked(),
        'rule_id'       => $verdict->blockingRuleId,
        'action'        => $verdict->action,
        'total_score'   => $verdict->totalScore,
        'scores'        => $verdict->scores,      // per-category breakdown
        'matched_rules' => $verdict->matchedRules,
    ]);
}
```

This pairs naturally with `mode: monitor`, where the request is allowed through and you want to record what *would* have been blocked in more detail than the log line carries. `getLastVerdict()` returns `null` until `evaluate()` has run at least once on that instance.

### AbuseIPDB Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\AbuseIpdb`

Checks the client IP against [AbuseIPDB](https://www.abuseipdb.com/), which scores an address 0-100 by how confidently it has been reported for abuse. The plugin matches when that score reaches `threshold`, so a known-bad address can be turned away before the expensive rule-matching plugins run.

Requires a free API key from [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api). With no `api_key` the plugin is a no-op that matches nothing, so it is safe to add to a config before the key is provisioned.

#### Configuration Example

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\AbuseIpdb"
    response: block
    # Cheaper than CRS, dearer than a static IP list — sit between them.
    weight: 40
    enable: true
    config:
      # Required. An %env()% token keeps the key out of the config file —
      # see "Environment Variables in YAML" above.
      api_key: "%env(ABUSEIPDB_API_KEY)%"
      # Abuse confidence (0-100) at or above which the plugin matches.
      threshold: 75
      # How long a verdict is reused before asking again (seconds).
      cache_ttl: 86400
      # How long a *failed* lookup is remembered (seconds). See below.
      error_cache_ttl: 300
      # Seconds to wait on the API before giving up and allowing the request.
      timeout: 2.0
      # How far back AbuseIPDB should consider reports.
      max_age_in_days: 30
      # Where verdicts are cached. Defaults to the system temp directory,
      # or KANOPI_FIREWALL_CACHE_DIR when that constant is defined.
      # cache_dir: /var/cache/firewall
      # HTTP status returned for blocked requests
      block_status: 403
      # How long the firewall remembers the offending IP (seconds)
      block_duration: 3600
```

#### Choosing a threshold

AbuseIPDB's confidence score is not a count of reports — it is a weighting of how many distinct reporters, how recently, and how reputable. 75 is the point AbuseIPDB's own guidance treats as strong enough to act on, and it is the default here.

| Threshold | Effect |
|---|---|
| `100` | Only addresses AbuseIPDB is certain about. Very few false positives, catches less. |
| `75` | The default. Corroborated reports from multiple reporters. |
| `50` | More aggressive; starts catching addresses with a thinner report history. |
| `25` and below | Not recommended. At this level the score largely reflects a handful of reports and will turn away real users on recycled residential IPs. |

Addresses AbuseIPDB marks as whitelisted — search-engine crawlers and similar known-good infrastructure — never match, whatever their score.

#### It fails open, deliberately

A lookup that times out, is refused, or runs into a spent quota reports **no match**, logs at `warning` level, and lets evaluation continue to the next plugin. Nothing here blocks a request it could not get an answer for.

That is a deliberate trade. Reputation is corroborating evidence, not the last line of defence, and a third-party outage should not become an outage on your site. If you need an address blocked regardless of whether AbuseIPDB is reachable, put it in the [IP Address plugin](#ip-address-plugin) — that is what a local blocklist is for.

#### Quota and caching

The free tier allows **1,000 checks per day**, which a modest site would exhaust before lunch if every request meant an API call. Two things keep it inside that budget:

- **Verdicts are cached per address** for `cache_ttl`, 24 hours by default. Cost is roughly one call per unique visitor per day; repeat visitors and crawlers are free. Clean results are cached too — that is most of the saving.
- **Private and reserved ranges are never looked up.** A local or intranet deployment spends no quota at all, and `127.0.0.1` in development costs nothing.

Failures are cached as well, for the much shorter `error_cache_ttl` (5 minutes). Without that, a provider outage would make every single request wait out the full `timeout` before failing open — availability preserved on paper while the site crawls. Raise `error_cache_ttl` to be more patient during an outage, lower it to notice recovery sooner.

If a site is large enough that unique visitors alone exceed the quota, put the plugin behind a cheaper filter so it only ever sees traffic that got past the static rules — see [Plugin Execution Order](#plugin-execution-order).

#### What gets logged

A match logs at `info` level with `ip`, `abuse_confidence_score`, `threshold`, `total_reports`, and `country_code`.

A failed lookup logs at `warning` with `error`, `http_status`, and a note that the request was allowed through. Distinct causes are named rather than collapsed into one message — a rejected API key, an exhausted quota, and an unreachable endpoint need different responses from whoever reads the log.

Skips (no API key, a non-routable address, a score under the threshold, a whitelisted address, a still-cached recent failure) log at `debug`.

Cache entries are named by SHA-1 of the address rather than the address itself, so client IPs are not readable from a directory listing.

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

### Sensitive Value Redaction

Conditional rules can match against any part of a request, including headers and cookies. At `debug` level the matched value is logged so you can see *why* a rule fired — which would otherwise write session cookies and API keys into your firewall log verbatim.

To prevent that, matched values for a set of variable names are logged as `[REDACTED]`. **This is on by default**, covering:

```
header.cookie
header.authorization
header.proxy-authorization
header.x-api-key
header.x-auth-token
header.x-csrf-token
header.x-session-token
cookie.*
```

Matching is case-insensitive, and a trailing `.*` makes the entry a prefix wildcard — `cookie.*` covers every individual cookie. Redaction applies to the logged value only; **rule evaluation always sees the real value**, so redacting a variable never changes whether a request is blocked.

Replace the list from PHP, before evaluation:

```php
use Kanopi\Firewall\Logging\LoggingFactory;

// Keep the defaults and add your own headers.
LoggingFactory::setRedactedVariables([
    ...LoggingFactory::getRedactedVariables(),
    'header.x-internal-token',
    'query.access_token',
    'post.password',
]);

\Kanopi\Firewall\Firewall::create([__DIR__ . '/firewall.yml'])->evaluate();
```

`setRedactedVariables()` **replaces** the list rather than appending to it, which is why the example above spreads `getRedactedVariables()` first. Passing an empty array turns redaction off entirely:

```php
// Everything gets logged verbatim. Only do this in local debugging.
LoggingFactory::setRedactedVariables([]);
```

Use the same dot-notation as your conditional rules (`header.*`, `cookie.*`, `query.*`, `post.*`). `LoggingFactory::shouldRedactVariable('header.cookie')` tells you whether a given name currently matches.

**Redaction only covers rule-match logging.** It does not scrub values that reach your log through other paths — the banning message, for instance, interpolates `{{ request.header.? }}` placeholders you write yourself. Don't put a secret-bearing header in a banning message and expect it to be redacted.

### Injecting Your Own Logger

By default the library builds its own Monolog `Logger` on the `firewall` channel from the `logger:` config. There are two ways to send firewall events to logging your application already owns.

**Option 1 — inject your handlers (recommended).** `class` accepts an *instantiated* `Monolog\Handler\HandlerInterface`, not just a class name. Because a YAML scalar cannot carry an object, pass it through [Dynamic Configuration Overrides](#dynamic-configuration-overrides):

```php
\Kanopi\Firewall\Firewall::create(
    [__DIR__ . '/firewall.yml'],
    ['[logger][0][class]' => $myMonologHandler]
)->evaluate();
```

This keeps everything the firewall logs — including the messages emitted *during* `create()` — flowing to your handler. It works whether or not your YAML declares a `logger:` section; index `0` is created if it does not exist. Entries you do declare are preserved, so `[logger][1][class]` adds a second handler alongside the first.

**Option 2 — replace the whole logger after construction.** `LoggingFactory::setLogger()` takes a Monolog `Logger` instance (not any PSR-3 logger):

```php
use Kanopi\Firewall\Logging\LoggingFactory;

$firewall = \Kanopi\Firewall\Firewall::create([__DIR__ . '/firewall.yml']);

// Must come *after* create() — see the note below.
LoggingFactory::setLogger($myMonologLogger);

$firewall->evaluate();
```

> **Ordering matters.** `Firewall::create()` always ends up calling `setLogger()` itself with a logger built from the `logger:` config, so a logger you install *before* `create()` is discarded. Install it after `create()` and before `evaluate()`. Startup messages (config loading, plugin registration, trusted-proxy warnings) are emitted during `create()` and will still go to the YAML-configured logger — which is why Option 1 is the better choice if you need those too.

`LoggingFactory::logger()` returns whichever logger is currently in effect, and `LoggingFactory::logMessage($level, $message, $context)` writes to it — useful from a custom plugin.

## Dynamic Configuration Overrides

For dynamic environments (Docker, multi-site installations), you can override YAML configuration with PHP arrays. Override paths target the **source YAML shape** (before plugin normalization runs), so the right path depends on how your YAML is written.

**Overriding entries written in the `plugins:` array** — the path includes the list index (`0`, `1`, `2`, …) in declaration order:

```php
<?php
$overrides = [
    // Override storage location
    '[storage][config][file]' => $_ENV['FIREWALL_STORAGE_PATH'] ?? '/tmp/firewall.data',

    // Override GeoIP database path on the 2nd plugin entry (index 1)
    '[plugins][1][metadata][reader][db]' => $_ENV['GEOIP_DB_PATH'],

    // Override Redis connection on the 4th plugin entry (index 3)
    '[plugins][3][metadata][storage][config][redis][host]' => $_ENV['REDIS_HOST'] ?? 'localhost',

    // Disable a plugin entry
    '[plugins][2][enable]' => false,
];

\Kanopi\Firewall\Firewall::create([__DIR__ . '/config.yml'], $overrides)->evaluate();
```

**Overriding entries written in the legacy `block:` / `bypass:` format** — paths still address the plugin by class name (legacy format is normalized after overrides are merged, so this continues to work):

```php
<?php
$overrides = [
    '[block][\Kanopi\Firewall\Plugins\GeoLocation][metadata][reader][db]' => $_ENV['GEOIP_DB_PATH'],
    '[block][\Kanopi\Firewall\Plugins\UserAgent][enable]' => false,
];
```

**Sections you have not declared are created for you.** An override writes into `global:`, `storage:`, `logger:`, `bypass:` or `block:` even when your YAML leaves that section out entirely — you do not have to add a placeholder entry first.

**An override that cannot be applied is silently ignored.** This happens when the path has to traverse *through* a value that is not an array:

```yaml
storage: /tmp/firewall.data   # a scalar, not a mapping
```

```php
// Dropped — `[storage]` is a string, so there is no `[config]` to write into.
// No exception, no log entry, and the original scalar is left intact.
'[storage][config][file]' => '/tmp/other.data',
```

Because there is no signal when this happens, assert the value landed if the override matters:

```php
$config = \Kanopi\Firewall\Utility\Config::load([$configPath], $overrides);
if (($config['storage']['config']['file'] ?? null) !== $expectedPath) {
    throw new \RuntimeException('Firewall storage override did not apply.');
}
```

## Error Handling & Exceptions

Every exception the library throws extends `Kanopi\Firewall\Exception\FirewallException`, which extends `\RuntimeException`. Catching that one base class is always safe.

```
\RuntimeException
└── FirewallException
    ├── ConfigurationException     Bad config — thrown from Firewall::create()
    │   └── (no subclasses)
    ├── StorageException           Storage file is unusable
    ├── FirewallBlockedException    ─┐
    ├── ChallengeRequiredException   ├─ only in mode: exception
    └── ChallengeSolvedException    ─┘
```

| Exception | When | What to do |
|---|---|---|
| `ConfigurationException` | During `Firewall::create()`: an empty `challenge.secret` while challenge plugins are configured, a `challenge.provider` that does not resolve to a `ChallengeProviderInterface`, or no trusted proxies when `require_trusted_proxies: true`. | Fail the deploy. This always signals operator error, never attacker input. |
| `StorageException` | A `FileStorage` / `FileRateLimitStorage` path cannot be created, read, or written. | Fix permissions on the storage path. Thrown at construction, so it also surfaces from `create()`. |
| `FirewallBlockedException` | `mode: exception` only — a `block` plugin matched. Carries `getStatusCode()` and the interpolated banning message. | Render your framework's error response with that status code. |
| `ChallengeRequiredException` | `mode: exception` only — a `challenge` plugin matched and the visitor holds no valid pass token, **or** a posted solution was rejected. | Render the interstitial yourself, or return the status your API expects. |
| `ChallengeSolvedException` | `mode: exception` only — a posted solution verified. Carries `getToken()` (the minted pass token) and `getRedirect()` (a sanitized, same-origin target). | Set the pass-token cookie / return the token to the client, then redirect to `getRedirect()`. |

Note that the three request-time exceptions are thrown **only** in `mode: exception`. In the default `block` mode the firewall writes the response and calls `exit()` itself, so there is nothing to catch.

Config *loading* problems are conditional: a missing, unreadable, or malformed config file — including circular `configs:` includes, unresolvable `%env(...)%` tokens, and use of a disabled filesystem processor — is logged at `error` level and produces an empty or partial ruleset, and raises `ConfigurationException` only when [`global.require_config: true`](#requiring-the-config-to-load) is set. See [Fail open or fail closed?](#fail-open-or-fail-closed) for why that matters.

### Handling blocks in a framework

```php
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;

try {
    Firewall::create([__DIR__ . '/firewall.yml'])->evaluate();
} catch (FirewallBlockedException $e) {
    // mode: exception — a plugin blocked the request. Render your own page.
    return new Response($e->getMessage(), $e->getStatusCode());
} catch (ConfigurationException $e) {
    // Startup validation failed. See "Fail open or fail closed?" below.
    $logger->critical('Firewall failed to start: ' . $e->getMessage());

    throw $e;
}
```

#### Fail open or fail closed?

"Fail open" means a broken firewall lets traffic through; "fail closed" means it refuses traffic. Which one you get depends on *how* the firewall broke, and the three cases behave differently:

| What went wrong | Throws? | What happens if you catch it and continue |
|---|---|---|
| A `block` plugin matched a request (`mode: exception`) | `FirewallBlockedException` | The request you were meant to block proceeds. |
| Startup validation failed — empty `challenge.secret`, unresolvable `challenge.provider`, or no trusted proxies with `require_trusted_proxies: true` | `ConfigurationException` | The firewall never started. **Nothing is filtered.** |
| Your config file is missing, unreadable, or malformed, with `require_config: true` | `ConfigurationException` | The firewall never started. **Nothing is filtered.** |
| The same, with `require_config: false` (default) | **Nothing** — logged at `error` | The firewall starts with a partial ruleset, possibly an empty one that allows every request. |

**The last row is the one to design around.** Config loading is lenient by default: `Config::loadFile()` skips files it cannot read and catches YAML, include, and `%env(...)%` resolution errors, so a mistyped path or a broken include yields a firewall with **no plugins**. `Firewall::create()` succeeds and `evaluate()` returns `true` for everything. Each failure is at least logged:

```
firewall.ERROR: Firewall config file failed to load — its rules are NOT active
    {"file":"/var/www/firewall.yml","reason":"File does not exist.","require_config":false}
```

An exception handler alone still will not catch that, because none is thrown. Turn it into a startup failure instead:

```yaml
global:
  require_config: true
```

See [Requiring the config to load](#requiring-the-config-to-load) for the constant and override forms, which cover the case where the file carrying the flag is the one that failed to load. If you would rather assert on the result yourself, `Config::getLoadErrors()` reports what a lenient load dropped:

```php
$configPath = __DIR__ . '/firewall.yml';

\Kanopi\Firewall\Utility\Config::clearLoadErrors();
$config = \Kanopi\Firewall\Utility\Config::load([$configPath]);

if (\Kanopi\Firewall\Utility\Config::getLoadErrors() !== []) {
    throw new \RuntimeException("Firewall config did not load cleanly: {$configPath}");
}

Firewall::create([$configPath])->evaluate();
```

For the cases that *do* throw, pick a policy deliberately:

- **Fail closed** — rethrow, or return a 503. Correct default for anything where serving unfiltered traffic is worse than serving an error: authenticated apps, checkout flows, admin surfaces. A startup misconfiguration is an operator error caught in deploy, not something to paper over at runtime.
- **Fail open** — log at `critical` and continue. Reasonable only for public, low-risk content where availability outweighs filtering, and only if that alert actually pages someone.

Whichever you choose, make it explicit in code. The library does not decide for you: it propagates the exception and leaves the policy to your error handler.

### Handling the challenge flow in a framework

In `mode: exception` you own the HTTP side of the challenge round-trip. `evaluate()` intercepts POSTs to `challenge.path` before any plugin runs, so a single call site handles both directions:

```php
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;

// Same secret as challenge.secret in your YAML.
$provider = new MathChallengeProvider(new TokenManager($_ENV['FIREWALL_SECRET']));

try {
    Firewall::create([__DIR__ . '/firewall.yml'])->evaluate($request);
} catch (ChallengeSolvedException $e) {
    // Visitor answered correctly. Issue the pass token and send them on.
    $response = new RedirectResponse($e->getRedirect());
    $response->headers->setCookie(
        Cookie::create('fw_challenge_pass', $e->getToken())
            ->withHttpOnly(true)
            ->withSecure(true)
            ->withSameSite('strict')
    );

    return $response;
} catch (ChallengeRequiredException $e) {
    // No valid token, or a wrong answer. Serve the interstitial again.
    return new Response($provider->renderInterstitial($request, [
        'submit_url' => '/_firewall/challenge',
        'redirect_to' => $request->getRequestUri(),
        'ttl' => '3600',
        'cookie_name' => 'fw_challenge_pass',
        'header_name' => 'X-Firewall-Challenge',
    ]), 200);
} catch (FirewallBlockedException $e) {
    return new Response($e->getMessage(), $e->getStatusCode());
}
```

`ChallengeRequiredException` deliberately does not distinguish "you need to solve a challenge" from "your answer was wrong" — telling a bot which of the two happened is free information. If your UX needs to show a retry message, key it off the request being a POST to `challenge.path`.

The cookie attributes above mirror what the firewall sets for you in `block` mode (`HttpOnly`, `Secure`, `SameSite=Strict`). Keep them.

## Platform Integration

Each snippet below uses the default `mode: block`, where the firewall sends its own response and exits. If you set `mode: exception`, wrap `evaluate()` as shown in [Error Handling & Exceptions](#error-handling--exceptions).

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

plugins:
  # =====================================================================
  # Trusted sources (response: allow)
  # =====================================================================
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -200
    enable: true
    config:
      - 203.0.113.0/24  # Office network
      - 198.51.100.50   # VPN endpoint

  # =====================================================================
  # Geographic restrictions
  # =====================================================================
  - plugin: "Kanopi\\Firewall\\Plugins\\GeoLocation"
    response: block
    weight: -100
    enable: true
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

  # =====================================================================
  # Suspicious user agents
  # =====================================================================
  - plugin: "Kanopi\\Firewall\\Plugins\\UserAgent"
    response: block
    weight: -50
    enable: true
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

  # =====================================================================
  # Vulnerability scoring for comprehensive threat assessment
  # =====================================================================
  - plugin: "Kanopi\\Firewall\\Plugins\\VulnerabilityScore"
    response: block
    weight: -25
    enable: true
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

  # =====================================================================
  # URL-based protection
  # =====================================================================
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    weight: 0
    enable: true
    config:
      # Protect admin areas
      - type: AND
        rules:
          - "path@starts_with:/admin"
          - "!header.authorization@exists"

      # Block vulnerability scanners
      - 'path@regex:/(\.git|\.env|\.htaccess|wp-config\.php|phpmyadmin)/i'

      # Block SQL injection attempts
      - "query@regex:/(union.*select|select.*from|insert.*into|drop.*table)/i"

  # =====================================================================
  # Aggressive rate limiting
  # =====================================================================
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 100
    enable: true
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
plugins:
  - plugin: "App\\Security\\Firewall\\Plugins\\ApiKeyValidator"
    response: block
    weight: -150   # Run before rate limiting
    enable: true
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

### Static Analysis and Code Style

```bash
composer check          # phpcs + phpstan (level max) + rector --dry-run
composer check:code     # PHP_CodeSniffer against phpcs_ruleset.xml
composer check:security # PHPStan at level max
composer check:rector   # Rector, dry run

composer fix            # php -l + phpcbf + rector, applied
```

### Testing Against Another PHP Version

`bin/test.sh` runs the quality gates inside a throwaway Docker container, which is how you reproduce a CI failure on a PHP version you don't have locally:

```bash
# Defaults to cimg/php:8.2
bash bin/test.sh

# Pick a version, or a different base image
PHP_VERSION=8.3 bash bin/test.sh
PHP_IMAGE=php PHP_VERSION=8.1-cli bash bin/test.sh
```

It copies the working tree into the container, discards `composer.lock` and `vendor/` so dependencies resolve fresh for that PHP version, then runs `check:code`, `check:security`, and `check:rector`. The container is removed afterwards. Note that it does **not** run PHPUnit — use `composer test` locally for that.

### Performance Benchmarks

The repository ships a load-testing harness that measures throughput, latency, memory, and false-positive rate under mixed legitimate/malicious traffic. See [tests/Performance/README.md](tests/Performance/README.md).

```bash
bash tests/Performance/run-local-test.sh
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
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'block',
                    'enable' => true,
                    'config' => ['192.168.1.100'],
                ],
            ],
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

## Legacy format (deprecated)

Earlier versions of this library configured plugins in two separate top-level sections (`bypass:` and `block:`), each keyed by the plugin class name. This format is still accepted — `Kanopi\Firewall\Utility\PluginConfigNormalizer` rewrites it into the `plugins:` array shape at load time — but it will be removed in a future major release. New configs should use the `plugins:` array described above.

**Side-by-side**

| Legacy (deprecated)                             | New (`plugins:` array)               |
|-------------------------------------------------|--------------------------------------|
| `bypass:` section                               | entry with `response: allow`         |
| `block:` section                                | entry with `response: block`         |
| keyed by plugin class                           | `plugin: "..."` field on each entry  |
| `priority:`                                     | `weight:`                            |
| one instance per class per section              | multiple instances per class allowed |
| deep-merges by class across `configs:` includes | appends entries across includes      |

**Same config in both shapes**

```yaml
# Legacy (deprecated)
bypass:
  "Kanopi\\Firewall\\Plugins\\IpAddress":
    priority: -200
    enable: true
    config:
      - 192.168.1.0/24

block:
  "Kanopi\\Firewall\\Plugins\\Url":
    priority: -10
    enable: true
    config:
      - path:/wp-admin
```

```yaml
# New (canonical)
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -200
    enable: true
    config:
      - 192.168.1.0/24

  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    weight: -10
    enable: true
    config:
      - path:/wp-admin
```

You can also mix both formats in the same config during migration — legacy entries are normalized first, then appended to whatever is already in `plugins:`.

## Additional Documentation

This README is the configuration reference. The repository carries several focused guides alongside it:

| Guide | Covers |
|---|---|
| [presets/README.md](presets/README.md) | The shipped presets (malicious requests, malicious URLs, WordPress, rate limiting, Pantheon), how to compose and override them, tuning thresholds, and common false positives. |
| [presets/RATE-LIMITING-REFERENCE.md](presets/RATE-LIMITING-REFERENCE.md) | Every rate limit rule in `rate-limiting.yml`, with the reasoning behind each limit. |
| [example/README.md](example/README.md) | The Docker sandbox: simulating remote IPs with `X-Forwarded-For`, GeoIP database setup, and worked blocking examples. |
| [example/demo/README.md](example/demo/README.md) | A runnable demo app (`composer demo`), including a scripted walkthrough of the challenge flow and repeat-offender escalation. |
| [tests/Performance/README.md](tests/Performance/README.md) | The load-testing harness: traffic profiles, success criteria, reports, and CI integration. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, branch and commit conventions, testing requirements, and the PR checklist. |

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