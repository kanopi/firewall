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
  - **An included file overrides the file that includes it.** Includes are merged over the
    including file's own settings, so where both set the same key, the include wins —
    whether the include is listed before or after the setting in the file. To override
    something an include sets, put your value in a file listed *after* it in `configs:`.
    A file you share for others to include should therefore only add entries under names
    of its own, never set a value the including file is likely to set
  - Lists (numeric arrays) are **replaced as a whole** by later files — with one
    exception: a root-level `plugins:` list **appends**, so several included files can
    each contribute plugin entries
  - **An empty list clears one.** `lockdown_allow: []` in an included file replaces the
    list it overrides with nothing, as any other list would. (Until #474 was fixed, an empty list
    was ignored, and the earlier list stayed in force.) Over a map, `[]` changes nothing:
    YAML can't tell `[]` from `{}`, and an empty map adds no keys. An empty root-level
    `plugins:` appends nothing
- **Separate configs merge the same way.** Several configs passed to
  `Firewall::create([$base, $site])` combine like includes, with each later one over the
  ones before it: maps merge, a list replaces a list, `[]` clears one, root `plugins:`
  appends, and a legacy rule's `config:` appends. Two things differ from includes: a later
  config's `priority` and `enable: false` on a legacy rule win, so a later config can still
  switch a rule off. (Until #481 was fixed, separate configs appended every list, so a
  second config added to `trusted_proxies` rather than replacing it, and couldn't clear
  `lockdown_allow`.)
- Safety: circular includes are prevented and excessive include depth is rejected.

**Remote Configuration Files**

Configuration files can be loaded from remote URLs, which is useful for centralized management across multiple servers:

```yaml
configs:
  - "https://cdn.example.com/firewall/base-rules.yml"
  - "https://cdn.example.com/firewall/ip-blocklist.yml"
```

!!! note "`configs:` is for configuration documents, not rule lists"
    An included document's top-level `plugins:` list **appends** to yours — the two rules
    both run, each keeping its own `config:`. Every *other* list is **replaced wholesale**,
    including the `config:` inside a rule and anything under `storage:`.

    So a remote file that re-declares one of your rules to extend its address list does not
    extend it. It gives you a second rule alongside the first, which the
    [linter warns about](../how-to/diagnosing.md) as a duplicate name — and if instead the
    include lands on the same key by another route, your list is overwritten rather than
    added to, quietly.

    Pulling a list of addresses, user agents, or paths is what [Rule Sources](sources.md)
    are for: they append into one rule, declare their own format, and carry their own TTL
    and failure policy. Keep `configs:` for whole configuration documents.

!!! warning "A `configs:` entry naming a file that does not exist empties the document"
    A missing include is a load failure, not a skipped line: `Config::load()` records the
    error and returns nothing, so *every* rule in the configuration stops being configured.

    That matters most when adding an include for a file you are about to create. Write the
    file first — [`firewall-rule init`](../how-to/managing-rules.md) does exactly that, in
    that order — and add the `configs:` line afterwards.

    `global.require_config: true` turns the failure into a startup exception instead, which
    is the loud version of the same thing and generally what you want in production.

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

## The compiled configuration cache

Parsing and merging the configuration costs about **2.2 ms** on the shipped presets, and it
produces the same answer on every request. So the merged result is cached as PHP, keyed on
the files it was built from, and a hit costs about **0.058 ms**.

Nothing needs configuring. It lives in `KANOPI_FIREWALL_CACHE_DIR/compiled` when that
constant is defined, and in a `kanopi-firewall-config` directory inside the system temp
directory otherwise.

### Keeping it in a cache pool, or off disk entirely

Writing PHP files is the right default when the cache directory is local. It is the wrong
one where the only persistent writable directory is a **network filesystem** — writing an
entry and sweeping the directory there can cost more than the parse it saves — or where an
integration keeps runtime caches in its application's own backend.

A host can hand over any PSR-6 pool before the firewall loads its configuration:

```php
use Kanopi\Firewall\Cache\NoObjectsMarshaller;
use Kanopi\Firewall\Utility\Config;
use Symfony\Component\Cache\Adapter\RedisAdapter;

Config::setConfigCachePool(new RedisAdapter($redis, 'firewall', 0, new NoObjectsMarshaller()));

\Kanopi\Firewall\Firewall::create([__DIR__ . '/config.yml'])->evaluate();
```

With a pool set, entries are read and written through it and nothing is written to disk.
They are validated exactly as file entries are — every file fingerprint and the environment
— and expire `KANOPI_FIREWALL_CACHE_MAX_AGE` after they were written, which stands in for the
sweep. A pool that throws costs a parse, never the load. A pool that is slow or unreachable
is another matter: every load then waits out a read timeout and a write timeout, so keep the
client's timeouts short. The setting is process-wide and
lasts until it is replaced; `Config::setConfigCachePool(null)` goes back to files.

A configuration containing an object is still not cached, so only arrays and scalars ever
reach the pool. Reading them back is the pool's job, though, and Symfony's default marshaller
will unserialise any object it finds there. Give the pool `NoObjectsMarshaller`, as above, so a
store something else can write to cannot hand the firewall an object.

A process with no pool to offer (CLI, cron) still writes files. To stop that on a host that
should never have cache files written:

```php
define('KANOPI_FIREWALL_CONFIG_FILE_CACHE', false);  // Default: files are written
```

Any value PHP's `FILTER_VALIDATE_BOOL` reads as false turns the file cache off, so `'0'`,
`'off'` or `''` from an environment variable work too. That includes `getenv()` returning
`false` for an unset variable: `define('KANOPI_FIREWALL_CONFIG_FILE_CACHE', getenv('X'))`
switches the cache off when `X` is not set.

The configuration is then parsed on every load that has no pool. The constant only covers
this cache: cached copies of remote includes and rule sources are unaffected, and a pool, if
one is set, is still used.

### What invalidates an entry

Each file is fingerprinted by a **hash of its content**. An entry is discarded when any file
it was built from changes, is deleted, or becomes unreadable.

Content rather than modification time, because a rewrite inside the same second that keeps
the byte count identical is invisible to an mtime — and an application that compiles its
settings into a YAML file does exactly that. The consequence was a firewall enforcing the
previous configuration while reporting itself perfectly healthy. It also means a deploy that
rewrites identical files *keeps* the cache rather than discarding it.

The **environment** is fingerprinted too, because `%env()%` is resolved during the parse:
change a variable a configuration reads and its entry is discarded. Values that belong to
one request are left out of that fingerprint, or no web request would ever hit the cache:
headers (`HTTP_*`), `REQUEST_*`, `REMOTE_*`, `QUERY_STRING`, `SERVER_NAME`, `SERVER_PORT`,
`SERVER_PROTOCOL`, `HTTPS`, `SSL_*`, `GEOIP_*` and the like.

An entry is also discarded when a release changes how a load is merged, so after the
upgrade that fixed #481 every configuration is parsed once more, rather than being served
as the previous merge left it.

Three things are never cached:

- a configuration containing an object, which cannot be written as PHP source without
  `serialize()`, deliberately not used anywhere this library writes and reads back;
- a load that reported an error or a warning, which would otherwise freeze a degraded
  result in place;
- a load whose `%env()%` read one of those request-scoped values, such as
  `%env(SERVER_NAME)%` or `%env(HTTP_HOST)%` in a `configs:` path that picks rules per site.
  The fingerprint can't see such a value change, so a cached entry would serve the first
  request's value to every later one. That configuration is parsed on each request, and
  everything else stays cached.

### Old entries are removed

An entry is keyed on the paths it was built from, so a deployment using **dated release
directories** produces a new key on every deploy and orphans the previous entry. Nothing
read those orphans again, and until 2.23.0 nothing deleted them either.

Entries older than **30 days** are now swept whenever a new one is written — which is
exactly when an orphan is created, and never on a request that hit the cache.

```php
define('KANOPI_FIREWALL_CACHE_MAX_AGE', 7 * 86400);  // Default: 30 days. 0 disables sweeping.
```

The age is time since the entry was **written**, not since it was last read. So a
configuration that never changes has its entry swept eventually and reparsed once — which is
deliberate: tracking "time since read" means touching the file on every cache hit, measured
at 0.0143 ms against a 0.058 ms warm load. A quarter again on every request the firewall
serves, to avoid one 2.2 ms reparse a month.

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
