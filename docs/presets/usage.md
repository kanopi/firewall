# Using Presets

## Quick Start with Malicious Request Detection

For comprehensive protection, start with the `malicious-requests.yml` preset:

```yaml
# firewall-config.yml
configs:
  - presets/malicious-requests.yml

storage:
  type: Kanopi\Firewall\Storage\FileStorage
  config:
    file: /tmp/firewall-blocked.data
```

This provides immediate protection without requiring GeoIP databases. For enhanced detection with geographic scoring, see [Enabling GeoIP Scoring](#enabling-geoip-scoring) below.

## Quick Start with Rate Limiting

For rate limiting protection, start with the `rate-limiting.yml` preset:

```yaml
# firewall-config.yml
configs:
  - presets/rate-limiting.yml

# Rate limiting requires storage - configure Redis (recommended)
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 0
    enable: true
    metadata:
      storage:
        type: "Kanopi\\Firewall\\RateLimitStorage\\RedisRateLimitStorage"
        config:
          redis:
            host: redis
            port: 6379
```

See [Rate Limiting Storage Options](#rate-limiting-storage-options) for other storage backends.

## Referencing Presets From `vendor/`

Every example here writes `presets/…`, which assumes your config sits next to a `presets/` directory. When the library is installed as a dependency the presets live under `vendor/kanopi/firewall/presets/`. Use the `{presets_dir}` token so you don't have to hardcode that path:

```yaml
# firewall-config.yml — works regardless of where vendor/ is
configs:
  - "{presets_dir}/malicious-requests.yml"
  - "{presets_dir}/wordpress.yml"
```

`{presets_dir}` expands to this package's own `presets/` directory. `{config_dir}` is also available and expands to the directory of the YAML file doing the including — useful for your own rule files.

## Include in Main Configuration

```yaml
# firewall-config.yml
configs:
  - presets/malicious-urls.yml

storage:
  type: Kanopi\Firewall\Storage\FileStorage
  config:
    file: /tmp/firewall-blocked.data
```

## Combine Multiple Presets

```yaml
configs:
  - presets/malicious-urls.yml
  - example/config.wordpress-simple.yml
  - custom/my-rules.yml
```

## Override or Add Bypass Rules

```yaml
configs:
  - presets/malicious-urls.yml

# Allow specific files that would otherwise be blocked
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: allow
    weight: -200
    enable: true
    config:
      # Allow custom API endpoint
      - path:/api.php
      # Allow custom admin file
      - path:/admin.php
      # Allow specific IP to access setup
      - type: AND
        rules:
          - path@starts_with:/setup
          - header.x-forwarded-for:203.0.113.100
```

## Enabling GeoIP Scoring

To enable country and ASN-based scoring in `malicious-requests.yml`:

1. **Download GeoIP databases** (see [example/README.md](../guides/geoip-setup.md))

2. **Create an override config** to enable GeoIP:

```yaml
# firewall-config.yml
configs:
  - presets/malicious-requests.yml

# Override to enable GeoIP
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\VulnerabilityScore"
    response: block
    weight: -75
    enable: true
    metadata:
      country_reader:
        type: reader
        db: /usr/local/share/GeoIP/GeoLite2-Country.mmdb
      asn_reader:
        type: reader
        db: /usr/local/share/GeoIP/GeoLite2-ASN.mmdb
    config:
      scoring:
        # Uncomment the countries and asn sections in the preset
        # or define your own scoring here
        countries:
          US: 0
          CN: 15
          RU: 15
          XX: 25  # Unknown
        asn:
          "13335": 0   # Cloudflare
          "4134": 20   # Chinanet
```

## Customizing Risk Thresholds

Adjust blocking sensitivity by modifying risk level thresholds:

```yaml
configs:
  - presets/malicious-requests.yml

plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\VulnerabilityScore"
    response: block
    weight: -75
    enable: true
    config:
      risk_levels:
        # More aggressive: Lower thresholds
        high:
          threshold: 30      # Block at 30 points (default: 40)
          block: true
          expiration_time: 7200  # 2 hour ban

        # More lenient: Higher thresholds
        high:
          threshold: 50      # Block at 50 points (default: 40)
          block: true
          expiration_time: 1800  # 30 minute ban
```

## Layered Security Approach

For maximum protection, combine multiple presets:

```yaml
configs:
  - presets/malicious-requests.yml    # Advanced scoring
  - presets/malicious-urls.yml        # URL pattern blocking
  - presets/rate-limiting.yml         # Rate limiting
  - presets/wordpress.yml             # WordPress-specific rules

storage:
  type: Kanopi\Firewall\Storage\DatabaseStorage
  config:
    type: mysql
    host: localhost
    database: firewall
    username: firewall_user
    password: secure_password
```

## Rate Limiting Storage Options

The rate limiting preset requires persistent storage. Choose based on your infrastructure:

### Redis (Recommended for Production)

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 0
    enable: true
    metadata:
      storage:
        type: "Kanopi\\Firewall\\RateLimitStorage\\RedisRateLimitStorage"
        config:
          redis:
            host: localhost
            port: 6379
            # Optional authentication
            auth: "password"
            # Or for Redis 6+ ACL:
            # auth: ["username", "password"]
```

**Benefits**: Fast, distributed, scales horizontally, automatic expiration

### Database Storage

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 0
    enable: true
    metadata:
      storage:
        type: "Kanopi\\Firewall\\RateLimitStorage\\DatabaseRateLimitStorage"
        config:
          storage-table: firewall_ratelimit
          connection:
            dsn: "pdo-mysql://user:pass@localhost:3306/db"
            # Or use connection details:
            # dbname: firewall
            # user: firewall_user
            # password: secure_password
            # host: localhost
            # driver: pdo_mysql
```

**Benefits**: Uses existing database infrastructure, persistent across restarts

### File Storage (Simple Deployments)

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 0
    enable: true
    metadata:
      storage:
        type: "Kanopi\\Firewall\\RateLimitStorage\\FileRateLimitStorage"
        config:
          file: /var/lib/firewall/ratelimit.data
```

**Benefits**: No external dependencies, easy setup
**Limitations**: Single server only, slower than Redis

### PSR-6 Cache

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 0
    enable: true
    metadata:
      storage:
        type: "Kanopi\\Firewall\\RateLimitStorage\\CacheRateLimitStorage"
        config:
          # A class implementing Psr\Cache\CacheItemPoolInterface.
          adaptor: "Symfony\\Component\\Cache\\Adapter\\FilesystemAdapter"
          # Constructor arguments, spread in declaration order.
          args: ['firewall', 0, '/var/cache/firewall']
          # Per-key lifetime in seconds (default 3600).
          ttl: 3600
```

**Benefits**: Integrates with existing cache infrastructure

Any PSR-6 pool works — `RedisAdapter`, `MemcachedAdapter`, `ApcuAdapter`, or your framework's own pool. To hand over an **already-constructed** pool (for example your framework's `cache.app` service) pass it through the overrides argument instead of YAML, since a YAML scalar cannot carry an object. The index (`0` here) is the plugin's position in your `plugins:` list:

```php
Firewall::create([__DIR__ . '/firewall.yml'], [
    '[plugins][0][metadata][storage][config][adaptor]' => $myCachePool,
]);
```

See [Dynamic Configuration Overrides](../configuration/overrides.md) for the full path syntax.

**Note**: if `adaptor` is missing or cannot be resolved to a PSR-6 pool, the backend logs a warning and silently records nothing — rate limits will never trigger. Check for `Cache rate limit storage failed to initialize` in your logs.

## Customizing Rate Limits

Override specific endpoints while keeping preset defaults:

```yaml
configs:
  - presets/rate-limiting.yml

plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 0
    enable: true
    config:
      # More strict login limits
      - path: /login
        rate: 3
        sample: 600  # 3 attempts per 10 minutes

      # Higher API limits for paid tier
      - path: /api/premium/*
        rate: 500
        sample: 60

      # Custom endpoint
      - path: /my-custom-endpoint
        rate: 50
        sample: 60
```
