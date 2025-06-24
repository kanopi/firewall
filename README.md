# Simple Firewall

**Simple Firewall** is a powerful, extensible request-evaluation library for PHP-based systems. It provides comprehensive protection by analyzing HTTP requests and applying configurable rules to either allow or block access based on IP addresses, geolocation, user agents, URLs, ASN (Autonomous System Numbers), and rate limits. The library is designed to work seamlessly with popular frameworks like Drupal, WordPress, Symfony, or any standalone PHP application.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration Overview](#configuration-overview)
- [Storage Configuration](#storage-configuration)
- [Plugin Architecture](#plugin-architecture)
- [Available Plugins](#available-plugins)
  - [IP Address Plugin](#ip-address-plugin)
  - [GeoLocation Plugin](#geolocation-plugin)
  - [URL Plugin](#url-plugin)
  - [User Agent Plugin](#user-agent-plugin)
  - [ASN Plugin](#asn-plugin)
  - [Rate Limit Plugin](#rate-limit-plugin)
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
- **Rate Limiting**: Built-in rate limiting with configurable storage backends
- **GeoIP Integration**: Full support for MaxMind GeoIP2 databases (both local and web service)
- **Advanced Conditional Logic**: Support for simple, complex, and grouped conditional rules
- **PSR-3 Compatible Logging**: Integration with Monolog for flexible logging
- **Framework Agnostic**: Works with any PHP application or framework

## Requirements

- PHP 8.0 or higher
- Composer
- Optional: MaxMind GeoIP2 databases for geolocation features
- Optional: Redis for distributed rate limiting

## Installation

Install via Composer:

```bash
composer require kanopi/firewall
```

For geolocation features, also install:

```bash
composer require geoip2/geoip2
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

### Minimal Configuration Example

Create a `config/firewall.yml` file:

```yaml
# Storage configuration - where blocked IPs are stored
storage:
  type: \Kanopi\Firewall\Storage\FileStorage
  config:
    file: /var/log/firewall/blocked.data

# Block malicious IPs
block:
  \Kanopi\Firewall\Plugins\IpAddress:
    enable: true
    config:
      - 192.168.1.100
      - 10.0.0.0/24

# Optional: Configure logging
logger:
  - class: Monolog\Handler\StreamHandler
    args:
      - /var/log/firewall/firewall.log
      - Monolog\Level::Info
```

## Configuration Overview

The firewall configuration consists of four main sections:

| Section   | Purpose                                                  | Required |
|-----------|----------------------------------------------------------|----------|
| `storage` | Defines where blocked IP addresses are persisted         | Yes      |
| `bypass`  | Plugins that allow trusted traffic through               | No       |
| `block`   | Plugins that deny harmful or suspicious traffic          | No       |
| `logger`  | Monolog handlers for logging firewall events             | No       |

## Storage Configuration

Storage defines how the firewall persists blocked IP addresses across requests.

### Available Storage Classes

#### 1. In-Memory Storage

Non-persistent storage that resets with each request. Useful for testing.

```yaml
storage:
  type: \Kanopi\Firewall\Storage\InMemoryStorage
```

#### 2. File Storage

Persists blocked IPs to the filesystem.

```yaml
storage:
  type: \Kanopi\Firewall\Storage\FileStorage
  config:
    file: /var/log/firewall/blocked_ips.data
```

#### 3. Database Storage

Stores blocked IPs in a SQL database using Doctrine DBAL.

```yaml
storage:
  type: \Kanopi\Firewall\Storage\DatabaseStorage
  config:
    storage-table: firewall_blocked_ips
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
PluginNamespace:
  enable: true              # Whether the plugin is active
  priority: 0              # Execution order (-100 runs before 100)
  metadata: {}             # Plugin-specific configuration
  config: []               # Rules or conditions for the plugin
```

## Available Plugins

### IP Address Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\IpAddress`

Evaluates requests based on IP addresses, supporting IPv4, IPv6, CIDR blocks, and IP ranges.

#### Configuration Example

```yaml
# In bypass section - whitelist trusted IPs
bypass:
  \Kanopi\Firewall\Plugins\IpAddress:
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
  \Kanopi\Firewall\Plugins\IpAddress:
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
  \Kanopi\Firewall\Plugins\GeoLocation:
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
  \Kanopi\Firewall\Plugins\Url:
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
  \Kanopi\Firewall\Plugins\UserAgent:
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
  \Kanopi\Firewall\Plugins\Asn:
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
  \Kanopi\Firewall\Plugins\RateLimit:
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
        type: \Kanopi\Firewall\RateLimitStorage\RedisRateLimitStorage
        config:
          redis:
            host: localhost
            port: 6379
            # Authentication options:
            # auth: "password"
            # auth: ["password"]
            # auth: ["username", "password"]
        
        # Option 2: File storage
        # type: \Kanopi\Firewall\RateLimitStorage\FileRateLimitStorage
        # config:
        #   file: /var/log/firewall/ratelimit.data
        
        # Option 3: Database storage
        # type: \Kanopi\Firewall\RateLimitStorage\DatabaseRateLimitStorage
        # config:
        #   storage-table: firewall_ratelimit
        #   connection:
        #     dsn: "mysql://user:pass@localhost/db"
        
        # Option 4: In-memory (testing only)
        # type: \Kanopi\Firewall\RateLimitStorage\InMemoryRateLimitStorage
    
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

The firewall uses Monolog for flexible logging. Multiple handlers can be configured:

```yaml
logger:
  # File logging
  - class: Monolog\Handler\StreamHandler
    args:
      - /var/log/firewall/firewall.log
      - Monolog\Level::Info
    formatter:
      class: Monolog\Formatter\LineFormatter
      args:
        - "[%datetime%] [%level_name%] [%context.plugin%] %message% %context% %extra%\n"
        - "Y-m-d H:i:s"
  
  # Syslog
  - class: Monolog\Handler\SyslogHandler
    args:
      - firewall
      - LOG_USER
      - Monolog\Level::Warning
  
  # Email alerts for critical events
  - class: Monolog\Handler\NativeMailerHandler
    args:
      - security@example.com
      - "Firewall Alert"
      - noreply@example.com
      - Monolog\Level::Critical
```

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
  type: \Kanopi\Firewall\Storage\DatabaseStorage
  config:
    storage-table: firewall_blocked
    connection:
      dsn: "mysql://firewall:secure@localhost/security"

# Whitelist trusted sources
bypass:
  # Office IPs
  \Kanopi\Firewall\Plugins\IpAddress:
    enable: true
    priority: -200
    config:
      - 203.0.113.0/24  # Office network
      - 198.51.100.50   # VPN endpoint

# Comprehensive blocking rules
block:
  # Geographic restrictions
  \Kanopi\Firewall\Plugins\GeoLocation:
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
  \Kanopi\Firewall\Plugins\UserAgent:
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
  
  # URL-based protection
  \Kanopi\Firewall\Plugins\Url:
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
  \Kanopi\Firewall\Plugins\RateLimit:
    enable: true
    priority: 100
    metadata:
      default_rate: 120
      default_sample: 60
      storage:
        type: \Kanopi\Firewall\RateLimitStorage\RedisRateLimitStorage
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

Simple Firewall is developed and maintained by [Kanopi Studios](https://kanopi.com).

Special thanks to:
- The Symfony team for the excellent HttpFoundation component
- MaxMind for the GeoIP2 databases
- The Monolog team for the flexible logging library
- All our contributors and users