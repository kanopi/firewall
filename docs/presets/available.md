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

## `drupal.yml`

Drupal hardening that is safe on any site, Drupal 7 through 11:

- **Version disclosure**: `/CHANGELOG.txt`, `/core/*.txt`, `/README.md`, `/web.config` — the files that tell a scanner exactly which core version to target
- **Installer and recovery routes**: `/core/install.php`, `/core/update.php`, `/core/authorize.php`, `/core/rebuild.php`, and the unprefixed Drupal 7 forms
- **Settings and services**: `settings.php`, `settings.local.php`, `services.yml` across single-site and multisite — served as *text*, credentials included, whenever PHP stops executing
- **PHP under the files directory**: the upload-then-request path, covering `.php`, `.phtml`, `.phar`, `.inc` and numbered variants
- **Private files**: `/sites/*/files/private/`, reachable only when the docroot is misconfigured — and when it is, everything Drupal thought was private is public
- **Configuration export**: `/config/sync/`, a full inventory of enabled modules and their settings
- **Build artefacts**: `composer.json`, `composer.lock`, `package.json`, `/vendor/`, `/.git/`, `.env`, `.ddev/` — a leaked lock file is a shopping list of known CVEs
- **Development routes**: `/devel`, `/admin/config/development`, core test directories, `phpunit.xml`

**Deliberately not blocked**: `/core/misc/*` and `/core/assets/*` (core serves its CSS and
JavaScript from there), uploaded media under `/sites/*/files/`, public user profiles at
`/user/<id>`, and `/.well-known/` for certificate renewal.

**Does not touch `/admin` or `/user/login`** — that is [`drupal-admin.yml`](#drupal-adminyml).

## `drupal-admin.yml`

Drupal's administrative and authentication surface:

- **Admin interface**: `/admin` and everything under it, including
  `/admin/reports/status`, which discloses the version and module list
- **Authentication**: `/user/login`, `/user/register`, `/user/password`, `/user/reset/*`,
  and their language-prefixed forms (`/es/user/login`)
- **Content authoring**: `/node/add`, `/node/*/edit`, `/node/*/delete`

!!! danger "This preset locks people out. That is what it is for."
    Including it without an allow rule above it means **nobody can log in**, editors
    included. Pair it with an `IpAddress` allow entry at a lower weight:

    ```yaml
    configs:
      - "{presets_dir}/drupal.yml"
      - "{presets_dir}/drupal-admin.yml"

    plugins:
      - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
        response: allow
        weight: -200          # ahead of the preset's blocks
        enable: true
        config:
          - 203.0.113.0/24    # office
          - 198.51.100.7      # VPN egress
    ```

    Or change `response: block` to `response: challenge` in your own copy, so an
    interstitial replaces the refusal. That needs a
    [`challenge:` section](../plugins/challenges.md) configured.

**Blocks `/user` but not `/user/<id>`** — public profiles keep working, which is why the
authentication routes are named individually rather than blocking the `/user` prefix.
## AI Crawler Presets

Three presets, two lists, and one decision to make twice — because "AI crawler" covers two
populations with very different costs.

**Training and dataset crawlers** fetch pages to build corpora. Blocking them costs you
nothing in traffic. **Answer engines** fetch a page because a user just asked a question
about it, then cite it — several of them send referral traffic and put your pages in front
of people actively looking for what you publish.

The lists live as data beside the presets (`presets/lists/*.txt`) and are read through
[rule sources](../configuration/sources.md), so they can be reviewed as lists, consumed by
anything else that wants them, and updated without waiting on a release.

### `ai-crawlers.yml`

Blocks training and dataset collection: `GPTBot`, `ClaudeBot`, `CCBot`, `Google-Extended`,
`Applebot-Extended`, `Bytespider`, `Amazonbot`, `Meta-ExternalAgent`, `Diffbot` and others.
The safer half of the question — start here.

### `ai-crawlers-challenge.yml`

The same list, served an interstitial instead of a refusal. Friction rather than a hard no.

!!! warning "Requires a configured `challenge:` section"
    `response: challenge` needs `challenge.secret` and a provider, and the firewall refuses
    to start without them. See [Challenge Responses](../plugins/challenges.md). Use
    `ai-crawlers.yml` if you have not set that up.

### `ai-answer-engines.yml`

Blocks `PerplexityBot`, `ChatGPT-User`, `OAI-SearchBot`, `Claude-User`, `YouBot`,
`DuckAssistBot` and similar.

!!! danger "This one has a traffic cost"
    Blocking answer engines is a business decision, not a security one. Measure before you
    make it — run in log mode for a week and look at what they are actually doing:

    ```yaml
    global:
      mode: log
    ```

    `mode: log` is **global**. It stops every other rule from enforcing too, so do it
    deliberately on staging or during a quiet window rather than leaving it on. There is no
    log-only *preset*, precisely because a file you include alongside your other rules
    should not be able to switch enforcement off for all of them.

### What these cannot do

User-agent matching is a courtesy, not a control. Anything that wants to ignore it changes
its UA string and never appears again. These presets stop well-behaved crawlers that
identify themselves honestly; they do not stop scraping. Pair them with `robots.txt`, which
several of these do honour.

### Do not confuse these with search indexing

`Google-Extended` is training; **`Googlebot` is search indexing**, and blocking it
deindexes the site. Likewise `Applebot-Extended` versus `Applebot`, which powers Siri and
Spotlight. Neither preset touches the search crawlers, and there are tests asserting that.

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
