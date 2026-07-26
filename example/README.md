# Firewall Example Setup

This directory contains a working example of the Kanopi Firewall library running in a local Docker environment. Use this to test configurations, experiment with plugins, and understand how the firewall works.

## Table of Contents

- [Docker Setup](#docker-setup)
- [Testing with Remote IPs (X-FORWARDED-FOR)](#testing-with-remote-ips-x-forwarded-for)
- [GeoIP Database Setup](#geoip-database-setup)
- [Configuration Files](#configuration-files)
- [Testing Examples](#testing-examples)

## Docker Setup

### Prerequisites

- Docker and Docker Compose installed
- PHP 8.1+ (for running Composer locally)
- Composer installed

### Starting the Environment

```bash
# From the project root directory
composer server:start
```

This starts the following services:
- **nginx** on http://localhost:8080 (serves files from `example/` directory)
- **php-fpm** (PHP 8.2 with Xdebug)
- **mariadb** on port 3306 (for database storage testing)
- **postgres** on port 5432 (for database storage testing)
- **redis** on port 6370 (for rate limiting testing)

### Stopping the Environment

```bash
composer server:stop
```

### Destroying the Environment

To remove all containers and volumes:

```bash
composer server:destroy
```

### Accessing the Application

Once started, visit http://localhost:8080 in your browser. The `example/index.php` file will:
1. Load the firewall with your configuration
2. Evaluate the current request
3. Display "BLOCKED" if blocked, or show the `$_SERVER` array if allowed

## Testing with Remote IPs (X-FORWARDED-FOR)

The `example/index.php` file is pre-configured to trust the `X-FORWARDED-FOR` header when testing from behind a proxy.

### Using curl to Simulate Remote IPs

```bash
# Test with a specific IP address
curl -H "X-Forwarded-For: 192.168.1.100" http://localhost:8080

# Test with a blocked IP (if configured)
curl -H "X-Forwarded-For: 10.0.0.1" http://localhost:8080

# Test with multiple IPs (proxy chain)
curl -H "X-Forwarded-For: 203.0.113.1, 198.51.100.1" http://localhost:8080

# Test with a foreign country IP (requires GeoIP)
curl -H "X-Forwarded-For: 8.8.8.8" http://localhost:8080
```

### How It Works

The example `index.php` configures Symfony's Request component to trust the proxy:

```php
if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    \Symfony\Component\HttpFoundation\Request::setTrustedProxies(
        [$_SERVER['REMOTE_ADDR']],
        \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_FOR
    );
}
```

This tells the firewall to use the IP from `X-Forwarded-For` instead of the direct connection IP (which would be your local Docker network IP).

### Testing IP-Based Blocking

Create or modify `example/config.yml`.

**New Format (Recommended):**

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: block
    weight: 0
    enable: true
    config:
      - '192.168.1.0/24'      # Block entire subnet
      - '10.0.0.1'            # Block specific IP
      - '8.8.8.0-8.8.8.255'   # Block IP range
```

**Legacy Format:**

```yaml
block:
  Kanopi\Firewall\Plugins\IpAddress:
    priority: 0
    config:
      - '192.168.1.0/24'      # Block entire subnet
      - '10.0.0.1'            # Block specific IP
      - '8.8.8.0-8.8.8.255'   # Block IP range
```

Then test:

```bash
# Should be blocked (matches 192.168.1.0/24)
curl -H "X-Forwarded-For: 192.168.1.50" http://localhost:8080

# Should be allowed
curl -H "X-Forwarded-For: 172.16.0.1" http://localhost:8080
```

## GeoIP Database Setup

The GeoLocation and ASN plugins require MaxMind GeoIP2 databases. You have two options:

### Quickest path: `bin/update_geoip.sh`

The repository ships a helper that downloads all three databases (`GeoLite2-City`, `GeoLite2-Country`, `GeoLite2-ASN`) into a directory you name:

```bash
mkdir -p example/geo
bash bin/update_geoip.sh YOUR_MAXMIND_LICENSE_KEY example/geo
```

Both arguments are required and the target directory must already exist. The script currently pulls from a public GeoLite2 mirror, so the license key is checked for non-emptiness but not used for the download itself — pass any non-empty value if you don't have one yet. Because GeoLite2 is refreshed twice weekly, re-run this periodically rather than once.

The manual options below give you more control (specific editions, MaxMind's official endpoint, or the web service instead of local files).

### Option 1: Download Free GeoLite2 Databases (Recommended for Testing)

1. **Sign up for a free MaxMind account**:
   - Visit https://www.maxmind.com/en/geolite2/signup
   - Create a free account

2. **Generate a license key**:
   - Log into your account
   - Navigate to "My Account" → "Manage License Keys"
   - Generate a new license key
   - Save the key (you'll need it for downloads)

3. **Download the databases**:

   Using `geoipupdate` (recommended):
   ```bash
   # Install geoipupdate
   # macOS:
   brew install geoipupdate

   # Ubuntu/Debian:
   sudo apt install geoipupdate

   # Configure geoipupdate
   # Edit /usr/local/etc/GeoIP.conf (or /etc/GeoIP.conf on Linux)
   AccountID YOUR_ACCOUNT_ID
   LicenseKey YOUR_LICENSE_KEY
   EditionIDs GeoLite2-Country GeoLite2-City GeoLite2-ASN
   DatabaseDirectory /usr/local/share/GeoIP

   # Run update
   geoipupdate
   ```

   OR download manually:
   ```bash
   # Download from MaxMind website after logging in
   # Extract to a local directory, e.g.:
   mkdir -p /usr/local/share/GeoIP
   # Extract .mmdb files to that directory
   ```

4. **Configure the firewall to use the databases**:

   In your `config.yml`:

   **New Format (Recommended):**
   ```yaml
   plugins:
     - plugin: "Kanopi\\Firewall\\Plugins\\GeoLocation"
       response: block
       weight: 0
       enable: true
       metadata:
         reader:
           type: reader
           db: /usr/local/share/GeoIP/GeoLite2-City.mmdb
       config:
         - country:CN    # Block China
         - country:RU    # Block Russia
         - '!country:US' # Block everything except US

     - plugin: "Kanopi\\Firewall\\Plugins\\Asn"
       response: block
       weight: 0
       enable: true
       metadata:
         reader:
           type: reader
           db: /usr/local/share/GeoIP/GeoLite2-ASN.mmdb
       config:
         - asn:AS15169        # Block Google's ASN
         - asn_org@contains:amazon  # Block Amazon ASNs
   ```

   **Legacy Format:**
   ```yaml
   block:
     Kanopi\Firewall\Plugins\GeoLocation:
       priority: 0
       enable: true
       metadata:
         reader:
           type: reader
           db: /usr/local/share/GeoIP/GeoLite2-City.mmdb
       config:
         - country:CN    # Block China
         - country:RU    # Block Russia
         - '!country:US' # Block everything except US

     Kanopi\Firewall\Plugins\Asn:
       priority: 0
       enable: true
       metadata:
         reader:
           type: reader
           db: /usr/local/share/GeoIP/GeoLite2-ASN.mmdb
       config:
         - asn:AS15169        # Block Google's ASN
         - asn_org@contains:amazon  # Block Amazon ASNs
   ```

### Option 2: Use MaxMind Web Service (Paid)

If you have a MaxMind subscription, you can use their web service instead of local databases:

```yaml
block:
  Kanopi\Firewall\Plugins\GeoLocation:
    priority: 0
    enable: true
    metadata:
      reader:
        type: client
        accountId: YOUR_ACCOUNT_ID
        licenseKey: YOUR_LICENSE_KEY
        language: ['en']
    config:
      - country:CN
```

### Docker Volume Mounting (Optional)

To use GeoIP databases inside Docker, mount them as a volume in `docker-compose.yml`:

```yaml
services:
  php:
    volumes:
      - .:/var/www/html
      - /usr/local/share/GeoIP:/usr/local/share/GeoIP:ro
```

### Testing GeoLocation

```bash
# Test with a US IP (Google DNS)
curl -H "X-Forwarded-For: 8.8.8.8" http://localhost:8080

# Test with a Chinese IP
curl -H "X-Forwarded-For: 123.125.114.144" http://localhost:8080

# Test with a Russian IP
curl -H "X-Forwarded-For: 77.88.55.60" http://localhost:8080
```

### GeoIP Database Paths

Common database locations:
- **macOS (Homebrew)**: `/usr/local/share/GeoIP/`
- **Linux**: `/usr/share/GeoIP/` or `/var/lib/GeoIP/`
- **Docker**: Mount wherever convenient, e.g., `/geoip/`

Required database files:
- **GeoLocation plugin**: `GeoLite2-City.mmdb` or `GeoLite2-Country.mmdb`
- **ASN plugin**: `GeoLite2-ASN.mmdb`

## Configuration Files

This directory contains several example configurations:

- **config.yml** - Main configuration file (gitignored, create your own)
- **config.notes.yml** - Comprehensive documentation of all plugins and options
- **config.ip.yml** - Simple IP blocking example
- **config.vulnerability-score.yml** - Advanced multi-factor risk scoring example
- **test-vulnerability-score.php** - Test script for vulnerability scoring

### Supporting Files

- **index.php** - Front controller for the sandbox. Loads `config.yml`, calls `Firewall::create(...)->evaluate()`, and prints either `BLOCKED` or the `$_SERVER` array.
- **.ht.router.php** - Router script for PHP's built-in web server, used instead of nginx for a dependency-free run. It serves existing files as-is and routes everything else to `index.php`, working around [PHP bug #61286](https://bugs.php.net/bug.php?id=61286). It refuses to run outside the `cli-server` SAPI, so it is inert if it ever gets served by a real web server.

  ```bash
  # From the example/ directory — an alternative to the Docker setup above
  php -S localhost:8888 .ht.router.php
  ```

  For a richer, purpose-built demo (including the challenge flow and repeat-offender escalation) use [example/demo/](demo/README.md) and `composer demo` instead.

## Testing Examples

### Example 1: Block Specific User Agents

```yaml
block:
  Kanopi\Firewall\Plugins\UserAgent:
    priority: 0
    config:
      - 'device.type:Bot'
      - 'browser.name:Chrome'
      - 'browser.family@regex:/bot|crawler|spider/i'
```

Test:
```bash
curl -A "Mozilla/5.0 (compatible; Googlebot/2.1)" http://localhost:8080
curl -A "Mozilla/5.0 Chrome/120.0" http://localhost:8080
```

### Example 2: Block WordPress Login Attempts

```yaml
block:
  Kanopi\Firewall\Plugins\Url:
    priority: 0
    config:
      - path:/wp-login.php
      - path:/wp-admin/
      - 'path@regex:#/wp-.*\.php$#'
```

Test:
```bash
curl http://localhost:8080/wp-login.php
curl http://localhost:8080/wp-admin/
curl http://localhost:8080/wp-config.php
```

### Example 3: Rate Limiting

```yaml
block:
  Kanopi\Firewall\Plugins\RateLimit:
    priority: 100
    metadata:
      storage:
        type: redis
        config:
          host: redis
          port: 6379
    config:
      - limit: 10
        window: 60
        key: 'ip'  # Per IP address
```

Test:
```bash
# Make 11 requests quickly
for i in {1..11}; do
  curl http://localhost:8080
done
# The 11th request should be blocked
```

### Example 4: Bypass Trusted IPs

**New Format (Recommended):**

```yaml
plugins:
  # Allow trusted IPs first (lower weight = runs first)
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -100
    enable: true
    config:
      - '127.0.0.1'
      - '192.168.0.0/16'

  # Then apply blocking rules
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: block
    weight: 0
    enable: true
    config:
      - '10.0.0.0/8'
```

**Legacy Format:**

```yaml
bypass:
  Kanopi\Firewall\Plugins\IpAddress:
    priority: -100  # Execute before block rules
    config:
      - '127.0.0.1'
      - '192.168.0.0/16'

block:
  # ... other blocking rules ...
```

## Important: Regex Pattern Delimiters

When using regex patterns in your configurations, **always include delimiters**. The firewall validates regex patterns and will reject patterns without proper delimiters.

**Valid regex patterns:**
```yaml
block:
  Kanopi\Firewall\Plugins\Url:
    config:
      - path@regex:#^/admin/#         # Using # delimiter
      - path@regex:/\.php$/           # Using / delimiter
      - path@regex:@^/api/@           # Using @ delimiter
      - path@regex:~/test~            # Using ~ delimiter
      - path@regex:/test/i            # With case-insensitive modifier
```

**Invalid patterns (will fail):**
```yaml
- path@regex:^/admin/               # Missing delimiters - INVALID
- path@regex:\.php$                 # Missing delimiters - INVALID
```

**Choosing the right delimiter:**
- Use `#` when pattern contains `/`: `#^/path/#` (no need to escape slashes)
- Use `/` for simple patterns: `/test/`
- Use `@` or `~` if both `/` and `#` appear in pattern

**Error handling:**
If you see warnings about regex delimiters, check that:
1. Your pattern starts and ends with the same delimiter character
2. The delimiter is not alphanumeric (can't use letters or numbers)
3. The pattern is at least 3 characters long (e.g., `/a/` is valid, `/a` is not)

## Troubleshooting

### Request shows REMOTE_ADDR instead of X-Forwarded-For IP

Make sure you're sending the header correctly:
```bash
curl -H "X-Forwarded-For: 1.2.3.4" http://localhost:8080
```

### GeoIP plugin not working

1. Verify database file exists and is readable
2. Check the path in your config matches the actual file location
3. Ensure the database is mounted correctly in Docker (if using Docker)
4. Check logs for GeoIP-related errors

### Changes not taking effect

1. The firewall reads config files on every request (no caching)
2. Check for YAML syntax errors
3. Verify the config file path in `index.php`
4. Check nginx error logs: `docker-compose logs nginx`

### Performance testing

The example `index.php` adds custom headers showing execution time and memory:
```bash
curl -I http://localhost:8080
# Look for:
# time: 0.0123
# memory: 2097152
```

## Additional Resources

- [Main README](../README.md) - Full configuration reference
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Development guide
- [config.notes.yml](config.notes.yml) - Complete plugin reference
- [Presets](../presets/README.md) - Ready-made rule sets you can include instead of writing your own
- [Demo app](demo/README.md) - Runnable demo covering the challenge flow and repeat-offender escalation
- [Performance suite](../tests/Performance/README.md) - Load testing harness
- [MaxMind GeoIP2 Documentation](https://maxmind.github.io/GeoIP2-php/)
