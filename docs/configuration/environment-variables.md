# Environment Variables in YAML

You can reference OS environment variables inside YAML using Symfony‑style tokens: `%env(NAME)%`.

- When a YAML scalar is **exactly** a single token (e.g., `port: '%env(int:APP_PORT)%'`), the value is returned as a **native type** based on the processor (int, float, bool, array, or string).
- When a token appears **inside a larger string**, it is interpolated as text.
- Remember to **quote** tokens in YAML (e.g., `' %env(...)% '`) because `%` is a reserved indicator in YAML.

## `${VAR}` Is Not Supported

`%env(NAME)%` is the **only** substitution syntax this library implements. The shell-style form `${NAME}` is the more intuitive guess, but nothing resolves it — the value is loaded as the literal string `${NAME}`:

```yaml
# WRONG — loaded as the literal string "${FIREWALL_CHALLENGE_SECRET}"
challenge:
  secret: '${FIREWALL_CHALLENGE_SECRET}'

# Correct
challenge:
  secret: '%env(FIREWALL_CHALLENGE_SECRET)%'
```

This matters most for secrets, because the failure is not always loud. A rejected API key surfaces quickly as an error from the remote service, but a signing key set to the literal `${FIREWALL_CHALLENGE_SECRET}` keeps working — using a value that is identical across every deployment that copy-pasted it, which anyone can then use to forge a valid token.

If you see `${...}` in a config example, it is either a mistake or it belongs to a different tool. Docker Compose, shell scripts, and CI configuration substitute `${VAR}` themselves before this library ever sees the file; inside a firewall YAML config, it is always wrong.

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

The `file:` (read a file's contents) and `require:` (include a PHP file and use its return value) processors are **disabled by default**. Their path *typically* comes from an environment variable, and where it does, enabling them turns any env-var injection into a local file inclusion — or, for `require:`, remote code execution.

The path does not have to come from a variable — see [Reading from a known path](#reading-from-a-known-path) below, which is the lower-risk form when you already know where the file is.

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

### Reading from a known path

When you already know the path, use `%file(...)%` rather than an environment variable:

```yaml
challenge:
  secret: '%file(/etc/firewall/hmac.key)%'

global:
  banning_message: '%file(/etc/firewall/banned.html)%'
```

The token content is the whole path, so unlike the `file:` processor there is **no colon limitation** — `%file(/tmp/sec:rets/key.txt)%` works. There is also no environment variable involved, so nothing in the environment can redirect the read.

The same opt-in and base-directory allowlist apply:

```php
TokenSubstitute::enableUnsafeProcessors(['file'], ['/etc/firewall']);
```

A literal path in a config file is only as trustworthy as that file, so this form is lower risk than the env-var one — but it is held to the same controls so there is a single mental model, and the allowlist still limits the blast radius if a config file is ever compromised.

Contents come back **verbatim**, newline included, exactly as `file:` returns them. A key file written by an editor usually ends with `\n`, and an HMAC secret carrying a stray newline fails in a way that is annoying to diagnose — if that matters, read it through a [configuration override](overrides.md#reading-a-value-from-a-file) where you can `trim()` it.

`%file(...)%` interpolates inside a larger string and resolves inside nested arrays, like `%env(...)%`.

!!! note "The older workaround, and why to move off it"

    Before this token existed, the only way to use a literal path was to chain `default:` into `file:`:

    ```yaml
    secret: '%env(file:default:/etc/firewall/hmac.key:UNUSED)%'
    ```

    It still works, and you will meet it in existing configs, but it carries two hazards that `%file(...)%` does not.

    **`UNUSED` must never be defined by anything.** Define it — a platform injecting variables, a `.env` file, a colleague reusing the name — and the path silently becomes that value. Nothing in the config file signals the dependency. This is where the base-directory allowlist earns its keep: with `enableUnsafeProcessors(['file'], ['/etc/firewall'])` in place, a hijacked variable pointing at `/etc/passwd` fails loudly rather than being read:

    ```
    ConfigurationException: Path for file processor escapes the configured allowlist: /etc/passwd
    ```

    Never pass an empty allowlist when using that form.

    **A colon truncates the path.** Tokens are split on `:`, so `%env(file:default:/tmp/sec:rets/key.txt:UNUSED)%` resolves the path as `/tmp/sec`. This is the same limitation `raw_key:` exists to work around for keys; there is no equivalent escape for paths.

Prefer `file:` over `require:` whenever you can — reading a secret is far less dangerous than executing a path an attacker may influence.

**Path resolution for common keys**

Some metadata values are commonly file paths. The loader automatically rewrites **relative** values to **absolute**, using the **YAML file's directory** as the base. Keys naming a file the firewall *reads* — a GeoIP database, a plugin config file — are rewritten only when the target exists, so a wrong path is reported by whatever tried to read it rather than silently relocated. Keys naming a file the firewall *writes* — `storage.config.storage_file`, `storage.config.offense_file`, `…storage.config.file`, and log files — are rewritten whether or not they exist, since on a first run they do not. You can target keys with dot‑path patterns and lightweight alternation:

- `*` matches any key at that level
- Alternation per segment: `block|allow`, `{block,allow}`, or `(block|allow)`

**Useful patterns**

```text
# New plugins: array format
plugins.*.metadata.reader.db
plugins.*.metadata.storage.config.file
plugins.*.metadata.config.*

# Legacy block:/bypass: format (still supported)
(block|allow).Kanopi\Firewall\Plugins\GeoLocation.metadata.reader.db
(block|allow).Kanopi\Firewall\Plugins\Asn.metadata.reader.db
(block|allow).Kanopi\Firewall\Plugins\RateLimit.metadata.storage.config.file
```

With these patterns, paths like `geo/GeoLite2-ASN.mmdb` or `limits/rate.yml` will be resolved relative to the YAML file and stored as absolute paths at runtime.

Log file paths are handled separately, without a pattern: `args.0` is a path for `StreamHandler` and `RotatingFileHandler` but an ident string or an address for other handlers, so the loader resolves it based on the handler class instead. See [Logging](logging.md).

## `%config(...)%` — reusing a value from elsewhere in the config

`%env()%` and `%file()%` reach outside the configuration. `%config()%` reaches *inside* it:
the value is whatever sits at a dot-path in the merged configuration.

The case it exists for is a database connection declared once and used in several places:

```yaml
storage:
  type: "Kanopi\\Firewall\\Storage\\DatabaseStorage"
  config:
    connection:
      driver: pdo_mysql
      host: "%env(DB_HOST)%"
      dbname: "%env(DB_NAME)%"
      user: "%env(DB_USER)%"
      password: "%env(DB_PASSWORD)%"

logger:
  - class: "Kanopi\\Firewall\\Logging\\Handler\\DatabaseHandler"
    args:
      - table: firewall_log
        connection: "%config(storage.config.connection)%"

plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    metadata:
      storage:
        type: "Kanopi\\Firewall\\RateLimitStorage\\DatabaseRateLimitStorage"
        config:
          connection: "%config(storage.config.connection)%"
```

One declaration; three consumers. Change the host in one place.

### Prefer a YAML anchor within a single file

If everything is in one file, a plain YAML anchor does the same job with no library
involvement, and is the better answer:

```yaml
storage:
  config:
    connection: &db
      driver: pdo_mysql
      host: "%env(DB_HOST)%"

logger:
  - class: "Kanopi\\Firewall\\Logging\\Handler\\DatabaseHandler"
    args:
      - table: firewall_log
        connection: *db
```

An anchor cannot cross a file boundary — each file is parsed on its own — so it is no help
once `storage:` and `logger:` live in different [included files](loading-and-includes.md).
That is what `%config()%` is for.

### Rules

- **Paths are literal**, matched segment by segment: `storage.config.connection`. List
  indexes are segments too: `logger.0.args.0.table`. There are no wildcards — a reference
  names one thing, and `*` resolving to "the first of several" would be a trap rather than
  a convenience.
- **A value that is exactly one token keeps its type.** That is what lets a reference stand
  in for an array like a connection block.
- **A token inside a larger string is interpolated**, so the target must be a scalar:
  `"mysql://%config(storage.config.connection.host)%:3306"`. Pointing at an array there is
  reported rather than guessed at.
- **References may chain** — a reference to a reference resolves through. A cycle is
  reported instead of recursing.

### When it does not resolve

The token is left in place as written, and a warning is logged (`Firewall config loaded in
a degraded state`). Leaving the literal is deliberate: whatever reads the value then fails
in its own terms, rather than the value looking like something that was never configured at
all.

```
Reference "storage.config.connection" points at nothing in the merged configuration.
```

### Ordering

`%env()%` and `%file()%` are resolved per file while it is parsed. `%config()%` is resolved
once, after every file has been merged **and after any
[runtime overrides](overrides.md)** — so a referenced value already has its environment
tokens filled in, an override can write a reference, and a reference sees values an
override replaced.

> A reference copies whatever is at the path, including secrets. That is no more exposure
> than writing the value twice, but note that a remote config included over HTTP can use
> one — as it already can use `%env()%`. Only include remote configuration you control.
