# Environment Variables in YAML

You can reference OS environment variables inside YAML using Symfony‑style tokens: `%env(NAME)%`.

- When a YAML scalar is **exactly** a single token (e.g., `port: '%env(int:APP_PORT)%'`), the value is returned as a **native type** based on the processor (int, float, bool, array, or string).
- When a token appears **inside a larger string**, it is interpolated as text.
- Remember to **quote** tokens in YAML (e.g., `' %env(...)% '`) because `%` is a reserved indicator in YAML.

## Variable Resolution with `$_SERVER` Fallback

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
  - `safe:fallback` - Wraps every processor to its right in a try/catch and returns `fallback` if any of them fail (missing variable, bad JSON, absent key). Useful for optional platform config — see [Pantheon presets](../presets/available.md#pantheon-platform-presets).

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

## Filesystem Processors (opt-in)

The `file:` (read a file's contents) and `require:` (include a PHP file and use its return value) processors are **disabled by default**. Because their path comes from an environment variable, enabling them turns any env-var injection into a local file inclusion — or, for `require:`, remote code execution.

Using either one without opting in raises `ConfigurationException` from `TokenSubstitute`. Note where that exception ends up:

- **Calling `TokenSubstitute::substitute()` directly** — the exception propagates to you.
- **A token inside a YAML config** — `Config::loadFile()` catches it and drops that file from the merge, so with the default `require_config: false` the firewall starts with **a config missing those rules** — potentially an empty one that allows every request. The failure is logged at `error` level with the reason. Set [`global.require_config: true`](global.md#requiring-the-config-to-load) to make it a startup failure instead.

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
