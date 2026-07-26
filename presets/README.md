# Firewall Presets

This directory contains pre-configured firewall rule sets (presets) that can be included in your main configuration to block common attack patterns and malicious requests.

## Available Presets

### `malicious-requests.yml` (Recommended)

**Advanced vulnerability scoring system** that detects and blocks malicious requests based on multiple risk factors. This is the most comprehensive preset and provides protection against:

- **SQL Injection**: All major variants including union-based, time-based, and error-based attacks
- **Cross-Site Scripting (XSS)**: Script tags, event handlers, protocol handlers, and HTML injection
- **Command Injection**: Shell operators, system commands, and code execution patterns
- **Path Traversal**: Directory traversal, sensitive file access, and null byte injection
- **Remote Code Execution (RCE)**: PHP execution, obfuscated code, and eval patterns
- **Web Shells**: Detection of common backdoor files and signatures
- **File Upload Exploits**: Dangerous file extensions and upload bypass attempts
- **XXE Injection**: XML external entity attacks
- **SSRF Attacks**: Server-side request forgery attempts
- **Template Injection**: Detection of template engine exploitation
- **Attack Tools**: Automated scanners (SQLMap, Nikto, Nmap, etc.)
- **Geographic Patterns**: Optional country/ASN-based scoring (requires GeoIP)

**Features**:
- Multi-factor risk scoring system
- Configurable thresholds (low, medium, high, critical, extreme)
- Progressive ban durations (1 hour to 7 days)
- 50+ attack pattern signatures
- Support for GeoIP-based country and ASN scoring

**Requirements**: None (GeoIP optional for enhanced detection)

### `rate-limiting.yml`

**Production-ready rate limiting** configuration to protect against abuse and resource exhaustion:

- **Authentication Protection**: Brute force prevention for login, password reset, and registration
- **API Rate Limits**: Graduated limits for public, authenticated, and admin API endpoints
- **WordPress Specific**: XML-RPC, wp-admin, wp-cron, and AJAX endpoint protection
- **Form Protection**: Contact forms, comments, search, and upload limits
- **Static Assets**: Relaxed limits for CSS, JS, and images
- **Webhooks**: Optimized limits for payment processors and integrations
- **Health Checks**: High limits for monitoring endpoints
- **Smart Defaults**: 60 requests/minute for general traffic

**Storage Options**:
- Redis (recommended for production/distributed)
- Database (MySQL/PostgreSQL)
- File (single server)
- PSR-6 Cache (Symfony, etc.)

**Rate Limits Include**:
- Login: 5 attempts per 5 minutes
- Password Reset: 3 attempts per 10 minutes
- API: 100 requests per minute
- Homepage: 120 requests per minute
- XML-RPC: 10 requests per minute
- Static Assets: 500 requests per minute

**Requirements**: Redis, Database, or File storage configured

📖 **[RATE-LIMITING-REFERENCE.md](RATE-LIMITING-REFERENCE.md)** documents every rule in this preset — the exact limit and window for each path, why it was chosen, storage backend comparisons, customization recipes, and a troubleshooting guide for limits that fire too early or never fire.

### `wordpress.yml`

WordPress-specific blocking rules including:

- **Admin & Login**: `/wp-admin/*`, `/wp-login.php`
- **XML-RPC**: `/xmlrpc.php` (DDoS target)
- **Core Files**: Direct access to WordPress system files
- **Sensitive Files**: `wp-config.php`, logs, backups
- **Uploads**: PHP execution in uploads directory
- **Security**: Version control files, debug logs, attack patterns

**Note**: REST API (`/wp-json/`) is commented out by default.

### `malicious-urls.yml`

Blocks common malicious PHP files, attack patterns, and suspicious URLs including:

- **Environment Files**: `.env`, `wp-config.php`, configuration files
- **Malicious PHP Files**: Known backdoor and shell file names (alfa.php, c99.php, etc.)
- **Generic Attack Files**: Common exploit file names at root level
- **WordPress Paths**: Comprehensive WordPress endpoint blocking
- **Shell/Backdoor Patterns**: Known webshell file names and patterns
- **Code Execution**: Query and POST parameter injection attempts
- **Suspicious Extensions**: `.exe`, `.bat`, `.cmd`, `.sh` files

**Note**: `.well-known` directory is NOT blocked by default (required for SSL cert validation).

### Pantheon Platform Presets

Two presets wire the firewall into [Pantheon](https://pantheon.io)'s environment rather than adding rules. Both read Pantheon's `PRESSFLOW_SETTINGS` / filesystem conventions, so they are no-ops (or wrong) anywhere else.

#### `storage-pantheon.yml`

Points blocked-client storage at the site's own MySQL database, pulling credentials out of the JSON in `$_SERVER['PRESSFLOW_SETTINGS']`:

```yaml
configs:
  - presets/storage-pantheon.yml
```

Every value uses the `safe:` env processor with a fallback, so a missing or malformed `PRESSFLOW_SETTINGS` degrades to placeholder values instead of throwing during bootstrap. See [Environment Variables in YAML](../README.md#environment-variables-in-yaml) for the processor syntax.

Tables are created automatically on first connection, using the `DatabaseStorage` defaults `firewall_storage` and `firewall_offenses` (this preset does not override the names — add `storage_table` / `offenses_table` under `config` if you need different ones). Database storage is the right choice on Pantheon because it is shared across application containers, unlike file storage on the ephemeral local filesystem.

#### `logging-pantheon.yml`

Writes firewall events to `/files/private/firewall.log`, which is inside Pantheon's persistent, non-web-accessible files directory:

```yaml
configs:
  - presets/logging-pantheon.yml
```

Logs at `INFO` and above. Read it with `terminus drush <site>.<env> -- ...` or over SFTP.

> **Note**: this preset still uses the legacy top-level `logger:` key. That key remains supported, but see [Logging Configuration](../README.md#logging-configuration) for the current handler options if you are writing your own.

### Composed Preset

#### `config.yml`

A convenience bundle that pulls in the two URL-pattern presets together:

```yaml
configs:
  - presets/config.yml    # == malicious-urls.yml + wordpress.yml
```

Use it when you want both rule sets and no rate limiting or vulnerability scoring. For anything more selective, include the individual presets so the composition is visible in your own config.

## Example Configurations

Three fully-commented example configs show complete, deployable setups. They are meant to be **copied into your project and edited**, not included via `configs:` — each one already declares its own storage and overrides.

| File | Shows |
|---|---|
| `example-usage.yml` | Composing multiple presets (`wordpress.yml` + `malicious-urls.yml`) with custom allow rules and additional plugins. |
| `example-malicious-requests-usage.yml` | Deploying `malicious-requests.yml` in production: storage, logging, and threshold overrides. |
| `example-rate-limiting-usage.yml` | Several rate limiting deployment scenarios side by side — Redis, database, and file storage, plus per-path limit overrides. |

```bash
cp presets/example-malicious-requests-usage.yml config/firewall.yml
# edit paths and credentials, then:
#   Firewall::create(['config/firewall.yml'])->evaluate();
```

Because each example is a menu of alternatives rather than one runnable config, read the comments before using one — several blocks are mutually exclusive and expect you to delete the ones you don't want.

## Configuration Format

The firewall uses a canonical `plugins:` array format. Each entry in the array configures one plugin and supports the following keys:

- `plugin` — Fully-qualified plugin class name (string, double-quoted with escaped backslashes, e.g. `"Kanopi\\Firewall\\Plugins\\Url"`).
- `response` — One of:
  - `allow` — bypass / whitelist behavior.
  - `block` — deny / blacklist behavior.
  - `challenge` — serve a CAPTCHA-style interstitial; on success the visitor receives an HMAC-signed pass token (cookie + custom header) valid for `metadata.default_expiration_time` seconds. Requires a top-level `challenge:` section with a non-empty `secret`. See the main [README → Challenge Response Type](../README.md#challenge-response-type) for the full contract.
- `weight` — Integer execution order. Lower weights run first (e.g. `-200` before `-10` before `0`).
- `enable` — `true`/`false` toggle for the entry.
- `metadata` — Plugin-specific metadata (e.g. storage backends, GeoIP readers, external config file references).
- `config` — Plugin-specific rule list or scalar configuration.

Example skeleton:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -200
    enable: true
    config:
      - 203.0.113.100/32

  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    weight: -10
    enable: true
    config:
      - path:/blocked-path
```

### Preset composition and merging

When a preset is pulled in through `configs:`, the loader **appends** each included file's `plugins:` entries onto a single combined list — it does not class-key-merge entries. This means:

- Two files can each declare an entry for `Kanopi\Firewall\Plugins\Url` and both will be kept as separate entries with their own `response`, `weight`, `enable`, and `config`. They are not folded into one.
- Order of `configs:` includes does not collapse duplicates; instead, all entries land in the combined list and are then partitioned by `response` and sorted by `weight` at runtime.
- To override an entry from a preset, add another `plugins:` entry in your main config with a lower `weight` so it runs first, or disable an unwanted plugin upstream by republishing it with `enable: false`.

This is a meaningful behavior difference from the legacy `block:`/`bypass:` format (which keyed entries by class name and deep-merged). See the **Legacy format (deprecated)** section at the bottom of this document.

## Usage

### Quick Start with Malicious Request Detection

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

### Quick Start with Rate Limiting

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

### Referencing Presets From `vendor/`

Every example here writes `presets/…`, which assumes your config sits next to a `presets/` directory. When the library is installed as a dependency the presets live under `vendor/kanopi/firewall/presets/`. Use the `{presets_dir}` token so you don't have to hardcode that path:

```yaml
# firewall-config.yml — works regardless of where vendor/ is
configs:
  - "{presets_dir}/malicious-requests.yml"
  - "{presets_dir}/wordpress.yml"
```

`{presets_dir}` expands to this package's own `presets/` directory. `{config_dir}` is also available and expands to the directory of the YAML file doing the including — useful for your own rule files.

### Include in Main Configuration

```yaml
# firewall-config.yml
configs:
  - presets/malicious-urls.yml

storage:
  type: Kanopi\Firewall\Storage\FileStorage
  config:
    file: /tmp/firewall-blocked.data
```

### Combine Multiple Presets

```yaml
configs:
  - presets/malicious-urls.yml
  - example/config.wordpress-simple.yml
  - custom/my-rules.yml
```

### Override or Add Bypass Rules

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

### Enabling GeoIP Scoring

To enable country and ASN-based scoring in `malicious-requests.yml`:

1. **Download GeoIP databases** (see [example/README.md](../example/README.md#geoip-database-setup))

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

### Customizing Risk Thresholds

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

### Layered Security Approach

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

### Rate Limiting Storage Options

The rate limiting preset requires persistent storage. Choose based on your infrastructure:

#### Redis (Recommended for Production)

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

#### Database Storage

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

#### File Storage (Simple Deployments)

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

#### PSR-6 Cache

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

See [Dynamic Configuration Overrides](../README.md#dynamic-configuration-overrides) for the full path syntax.

**Note**: if `adaptor` is missing or cannot be resolved to a PSR-6 pool, the backend logs a warning and silently records nothing — rate limits will never trigger. Check for `Cache rate limit storage failed to initialize` in your logs.

### Customizing Rate Limits

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

## Understanding Regex Patterns

### Regex Delimiter Requirement

**IMPORTANT**: All regex patterns MUST include delimiters. The firewall validates regex patterns and will reject patterns without proper delimiters.

**Valid patterns:**
```yaml
- path@regex:#^/test\.php$#        # Using # delimiter
- path@regex:/test\.php$/          # Using / delimiter
- path@regex:@test\.php$@          # Using @ delimiter
- path@regex:~test\.php$~          # Using ~ delimiter
```

**Invalid patterns (will be rejected):**
```yaml
- path@regex:^/test\.php$          # Missing delimiters - INVALID
- path@regex:test\.php             # Missing delimiters - INVALID
```

### Choosing Delimiters

Choose a delimiter that doesn't appear in your pattern to avoid excessive escaping:
- Use `#` for paths with slashes: `#^/test/#`
- Use `/` for simple patterns: `/test/`
- Use `@` if pattern contains `/` and `#`: `@test@`

## Understanding the Generic PHP Block

The `malicious-urls.yml` preset includes this powerful catch-all rule:

```yaml
- path@regex:#(?<!index)\.php(\?.*)?$#
```

This blocks **any PHP file except index.php**. This is useful for:
- Preventing execution of uploaded malicious PHP files
- Blocking common backdoor file names
- Stopping unknown exploits

### When to Use This Rule

**Use when:**
- Running a CMS (WordPress, Drupal) where all requests go through index.php
- You have a front-controller pattern (Laravel, Symfony)
- Maximum security is required

**Don't use when:**
- You have legitimate PHP files at root level (contact.php, api.php)
- Your application doesn't use a front-controller pattern
- You need to access various PHP files directly

### Adapting the Generic PHP Block

If you need to allow specific PHP files, add an `allow` entry to your `plugins:` array:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: allow
    weight: -200
    enable: true
    config:
      - path:/contact.php
      - path:/api.php
      - path:/webhook.php
      - path@regex:#^/api/.*\.php$#  # Allow all files in /api/ directory
```

Or modify the preset to exclude specific patterns:

```yaml
# Allow PHP files in /api/ and /public/ directories
- type: AND
  rules:
    - path@regex:(?<!index)\.php(\?.*)?$
    - path@not_contains:/api/
    - path@not_contains:/public/
```

## Testing Your Configuration

### Testing malicious-requests.yml (Vulnerability Scoring)

Test various attack patterns to verify scoring and blocking:

```bash
# Test SQL Injection (should score 40+ and block)
curl "http://localhost:8080/?id=1' UNION SELECT * FROM users--"
curl "http://localhost:8080/?search=admin' OR '1'='1"

# Test XSS (should score 35+ and block)
curl "http://localhost:8080/?name=<script>alert(1)</script>"
curl "http://localhost:8080/?redirect=javascript:alert(1)"

# Test Command Injection (should score 35+ and block)
curl "http://localhost:8080/?cmd=ls;cat /etc/passwd"
curl "http://localhost:8080/?file=test|whoami"

# Test Path Traversal (should score 30+ and block)
curl "http://localhost:8080/../../../etc/passwd"
curl "http://localhost:8080/?file=../../wp-config.php"

# Test Web Shell Detection (should score 50+ and block)
curl "http://localhost:8080/c99.php"
curl "http://localhost:8080/shell.php"

# Test with attack tools user agent (should score 50+ and block)
curl -A "sqlmap/1.0" http://localhost:8080/
curl -A "Nikto/2.1.5" http://localhost:8080/

# Test legitimate requests (should allow)
curl http://localhost:8080/
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://localhost:8080/
```

### Testing malicious-urls.yml

```bash
# Should be blocked (403)
curl -I https://yoursite.com/alfa.php
curl -I https://yoursite.com/shell.php
curl -I https://yoursite.com/wp-config.php
curl -I https://yoursite.com/.env

# Should work (200)
curl -I https://yoursite.com/
curl -I https://yoursite.com/index.php
```

### Testing wordpress.yml

```bash
# Should be blocked (403)
curl -I https://yoursite.com/test.php
curl -I https://yoursite.com/random.php

# Should work if explicitly allowed (response: allow entry)
curl -I https://yoursite.com/contact.php
```

### Testing rate-limiting.yml

Test rate limiting by making rapid requests:

```bash
# Test homepage rate limit (120 requests per minute)
# Make 125 requests rapidly - last 5 should return 429
for i in {1..125}; do
  curl -I http://localhost:8080/ 2>&1 | grep "HTTP/"
  sleep 0.1
done

# Test login rate limit (5 attempts per 5 minutes)
# Make 6 requests - 6th should return 429
for i in {1..6}; do
  curl -I http://localhost:8080/login
  echo "Request $i"
done

# Test API rate limit (100 per minute)
for i in {1..105}; do
  curl -I http://localhost:8080/api/endpoint 2>&1 | grep "HTTP/"
done

# Test with different IPs using X-Forwarded-For
# Each IP gets its own rate limit
curl -H "X-Forwarded-For: 1.2.3.4" http://localhost:8080/login
curl -H "X-Forwarded-For: 5.6.7.8" http://localhost:8080/login

# Verify rate limiting is working
# Look for 429 status code
curl -I http://localhost:8080/login | grep "429 Too Many Requests"

# Wait for rate limit window to expire, then try again
sleep 300  # Wait 5 minutes for login rate limit to reset
curl -I http://localhost:8080/login  # Should work again
```

### Monitor Logs and Scoring

```bash
# Check what's being blocked
tail -f /var/log/firewall/blocked-requests.log

# Look for false positives
grep "403" /var/log/nginx/access.log | grep -v "alfa.php\|shell.php"

# For VulnerabilityScore plugin, enable debug logging to see scores:
# Add to your config:
# logging:
#   level: debug
#   handlers:
#     - type: stream
#       path: /var/log/firewall-debug.log
#
# Then watch scores in real-time:
tail -f /var/log/firewall-debug.log | grep "Total vulnerability score"
```

## Common False Positives

### Legitimate PHP Files Blocked

**Problem**: Your application has legitimate PHP files that are blocked.

**Solution**: Add an `allow` entry for those specific files:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: allow
    weight: -200
    enable: true
    config:
      - path:/my-file.php
```

### WordPress Plugin/Theme Files Blocked

**Problem**: WordPress plugins or themes have PHP files that are being blocked.

**Solution**: The preset already allows `/wp-content/plugins/` and `/wp-content/themes/`. If you're still having issues:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: allow
    weight: -200
    enable: true
    config:
      - path@starts_with:/wp-content/plugins/
      - path@starts_with:/wp-content/themes/
```

### API Endpoints Blocked

**Problem**: Your REST API endpoints are being blocked.

**Solution**: Add specific `allow` entries for API routes:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: allow
    weight: -200
    enable: true
    config:
      - path@starts_with:/api/
      - path@starts_with:/wp-json/
```

## Creating Custom Presets

You can create your own presets by following the same structure:

```yaml
# presets/my-custom-rules.yml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: allow
    weight: -200
    enable: true
    config:
      - path:/my-allowed-path

  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    weight: -100
    enable: true
    config:
      - path:/my-blocked-path
      - path@contains:/sensitive
```

Then include it in your main config:

```yaml
configs:
  - presets/my-custom-rules.yml
```

Both entries will be appended to the combined `plugins:` list at load time. The `allow` entry runs first (lower `weight`) so trusted paths are short-circuited before the block rules execute.

## Security Recommendations

1. **Start Conservative**: Begin with `config.wordpress-simple.yml` before adding `malicious-urls.yml`
2. **Test Thoroughly**: Always test in staging before production
3. **Monitor Logs**: Watch for false positives in the first week
4. **Keep Updated**: Review and update presets as new threats emerge
5. **Layer Security**: Use these presets alongside other security measures (WAF, SSL, etc.)

## Performance Impact

- **Minimal**: URL pattern matching is very fast
- **Regex Rules**: Slightly slower than simple string matching, but still negligible
- **Rule Count**: Having 100+ rules has minimal performance impact
- **Plugin Weight**: URL plugin runs early (`weight: -100`) to block bad requests quickly

## Contributing

To contribute new presets or improvements:

1. Create a new preset file in this directory
2. Document the use case and rules clearly
3. Include usage examples
4. Test thoroughly
5. Submit a pull request

## Support

For questions or issues:

- Check the main [configuration reference](../README.md)
- Review the [rate limiting reference](RATE-LIMITING-REFERENCE.md)
- Review [example configurations](../example/README.md)
- Open an issue on GitHub

## Legacy format (deprecated)

Older configurations used top-level `bypass:` and `block:` sections keyed by plugin class. That shape is still accepted, but it is normalized at load time by `Kanopi\Firewall\Utility\PluginConfigNormalizer` into the canonical `plugins:` array, and **it will be removed in a future major version**. New configs should use the `plugins:` array directly.

Mini side-by-side:

Legacy (deprecated):

```yaml
bypass:
  Kanopi\Firewall\Plugins\IpAddress:
    priority: -200
    enable: true
    config:
      - 203.0.113.100

block:
  Kanopi\Firewall\Plugins\Url:
    priority: -10
    enable: true
    config:
      - path:/foo
```

Canonical (new):

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -200
    enable: true
    config:
      - 203.0.113.100

  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    weight: -10
    enable: true
    config:
      - path:/foo
```

Mapping:

- `bypass:` → `response: allow`
- `block:` → `response: block`
- `priority:` → `weight:`
- Class-keyed map → flat list of entries with `plugin:` set to the (double-quoted, escaped) class name

Note that the legacy format keyed entries by class name, so a class could appear at most once per file. The canonical format allows multiple entries for the same plugin class, and entries from preset includes are appended (not class-merged) into a single combined list.
