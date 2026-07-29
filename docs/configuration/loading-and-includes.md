# Configuration Loading & Includes

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
