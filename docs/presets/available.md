# Available Presets

## `malicious-requests.yml` (Recommended)

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

## `rate-limiting.yml`

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

📖 **[RATE-LIMITING-REFERENCE.md](../reference/rate-limiting.md)** documents every rule in this preset — the exact limit and window for each path, why it was chosen, storage backend comparisons, customization recipes, and a troubleshooting guide for limits that fire too early or never fire.

## `wordpress.yml`

WordPress-specific blocking rules including:

- **Admin & Login**: `/wp-admin/*`, `/wp-login.php`
- **XML-RPC**: `/xmlrpc.php` (DDoS target)
- **Core Files**: Direct access to WordPress system files
- **Sensitive Files**: `wp-config.php`, logs, backups
- **Uploads**: PHP execution in uploads directory
- **Security**: Version control files, debug logs, attack patterns

**Note**: REST API (`/wp-json/`) is commented out by default.

## `malicious-urls.yml`

Blocks common malicious PHP files, attack patterns, and suspicious URLs including:

- **Environment Files**: `.env`, `wp-config.php`, configuration files
- **Malicious PHP Files**: Known backdoor and shell file names (alfa.php, c99.php, etc.)
- **Generic Attack Files**: Common exploit file names at root level
- **WordPress Paths**: Comprehensive WordPress endpoint blocking
- **Shell/Backdoor Patterns**: Known webshell file names and patterns
- **Code Execution**: Query and POST parameter injection attempts
- **Suspicious Extensions**: `.exe`, `.bat`, `.cmd`, `.sh` files

**Note**: `.well-known` directory is NOT blocked by default (required for SSL cert validation).

## Pantheon Platform Presets

Two presets wire the firewall into [Pantheon](https://pantheon.io)'s environment rather than adding rules. Both read Pantheon's `PRESSFLOW_SETTINGS` / filesystem conventions, so they are no-ops (or wrong) anywhere else.

### `storage-pantheon.yml`

Points blocked-client storage at the site's own MySQL database, pulling credentials out of the JSON in `$_SERVER['PRESSFLOW_SETTINGS']`:

```yaml
configs:
  - presets/storage-pantheon.yml
```

Every value uses the `safe:` env processor with a fallback, so a missing or malformed `PRESSFLOW_SETTINGS` degrades to placeholder values instead of throwing during bootstrap. See [Environment Variables in YAML](../configuration/environment-variables.md) for the processor syntax.

Tables are created automatically on first connection, using the `DatabaseStorage` defaults `firewall_storage` and `firewall_offenses` (this preset does not override the names — add `storage_table` / `offenses_table` under `config` if you need different ones). Database storage is the right choice on Pantheon because it is shared across application containers, unlike file storage on the ephemeral local filesystem.

### `logging-pantheon.yml`

Writes firewall events to `/files/private/firewall.log`, which is inside Pantheon's persistent, non-web-accessible files directory:

```yaml
configs:
  - presets/logging-pantheon.yml
```

Logs at `INFO` and above. Read it with `terminus drush <site>.<env> -- ...` or over SFTP.

> **Note**: this preset still uses the legacy top-level `logger:` key. That key remains supported, but see [Logging Configuration](../configuration/logging.md) for the current handler options if you are writing your own.

## Composed Preset

### `config.yml`

A convenience bundle that pulls in the two URL-pattern presets together:

```yaml
configs:
  - presets/config.yml    # == malicious-urls.yml + wordpress.yml
```

Use it when you want both rule sets and no rate limiting or vulnerability scoring. For anything more selective, include the individual presets so the composition is visible in your own config.
