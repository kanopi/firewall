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
  - Lists (numeric arrays) are **replaced as a whole** by later files — with one
    exception: a root-level `plugins:` list **appends**, so several included files can
    each contribute plugin entries
- Safety: circular includes are prevented and excessive include depth is rejected.

**Remote Configuration Files**

Configuration files can be loaded from remote URLs, which is useful for centralized management across multiple servers:

```yaml
configs:
  - "https://cdn.example.com/firewall/base-rules.yml"
  - "https://cdn.example.com/firewall/ip-blocklist.yml"
```

!!! note "`configs:` is for configuration documents, not rule lists"
    Because lists are replaced rather than appended, a remote *rule list* included this
    way overwrites your local one instead of adding to it — and does so quietly. Pulling
    a list of addresses, user agents, or paths is what
    [Rule Sources](sources.md) are for: they append, declare their own format, and carry
    their own TTL and failure policy. Keep `configs:` for whole configuration documents.

Remote files are cached locally to improve performance and reduce external dependencies. You can control caching behavior using PHP constants:

```php
<?php
// Define before initializing the firewall
define('KANOPI_FIREWALL_CACHE_DIR', '/var/cache/firewall');  // Default: /tmp/cache
define('KANOPI_FIREWALL_CACHE_TTL', 7200);                   // Default: 3600 (1 hour)
define('KANOPI_FIREWALL_CACHE_TIMEOUT', 10.0);               // Default: 5.0 seconds
define('KANOPI_FIREWALL_CACHE_MAX_STALE', 86400);            // Default: unbounded

\Kanopi\Firewall\Firewall::create([__DIR__ . '/config.yml'])->evaluate();
```

### When the fetch fails

A remote include that cannot be fetched **falls back to its cached copy, even after the
TTL has expired**, and reports the fallback as a warning rather than an error:

```
firewall.WARNING: Firewall config loaded in a degraded state
    {"file":"https://cdn.example.com/firewall/base-rules.yml",
     "reason":"Remote config could not be fetched; served a cached copy 7412s old.
               The rules are active, but they are not necessarily current."}
```

The alternative — discarding a copy that worked an hour ago because a CDN returned a 503 —
drops the whole ruleset over a momentary failure. For a `response: block` include that
fails open. For a `response: allow` include at negative weight it fails *closed*, and
starts blocking the monitoring and deploy traffic the include existed to admit.

Three things follow from this being a warning rather than an error:

- It does **not** trip [`global.require_config`](global.md#requiring-the-config-to-load).
  The config loaded; it is just older than you asked for. A transient DNS blip should not
  refuse to start a site that has perfectly usable rules on disk.
- The cache file's timestamp is **not** refreshed. Restamping would reset the TTL and hide
  the age, so an upstream that has been dead for a month would look healthy.
- Read it yourself with `Config::getLoadWarnings()`, alongside `getLoadErrors()`.

With no cached copy to fall back to, the fetch failure stays an error and the include
contributes nothing.

`KANOPI_FIREWALL_CACHE_MAX_STALE` bounds how far past the TTL a copy may be served. Past
that age the fallback becomes a hard failure and is reported as an error. It is unbounded
by default, on the grounds that stale rules beat no rules — set it when you would rather
be told loudly that an upstream has gone away.

### When a file parses to something that is not configuration

YAML folds a newline-delimited list into a single scalar, so a file like this **parses
successfully** and yields no configuration at all:

```
216.144.248.16/28
69.162.124.224/28
```

That is reported rather than passed over in silence:

```
firewall.ERROR: Firewall config file failed to load — its rules are NOT active
    {"file":"/srv/app/config/ips.txt",
     "reason":"Parsed as a single string, not a configuration mapping. A newline-delimited
               list folds into one YAML scalar — if this is a rule list, load it through a
               plugin source (metadata.sources) rather than as configuration."}
```

An **empty** file is still silent: a file with nothing in it, only comments, or an explicit
`~` is legitimately no configuration, not a mistake. A YAML **sequence** still loads
normally, since plugin rule files are sequences.

A bad *include* costs only that include. The file that included it still loads, so one
stray `.txt` caught by a `configs:` glob does not take the ruleset with it.

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
