# User Agent Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\UserAgent`

Analyzes user agent strings to identify bots, devices, browsers, and operating systems.

## Configuration Example

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\UserAgent"
    response: block
    weight: 0
    enable: true
    config:
      # Block all bots
      - "bot:true"

      # Block specific device types
      - "device.type:desktop"
      - "device.type@in:smartphone,tablet"

      # Block specific browsers
      - "client.name:Internet Explorer"
      - "client.type:browser"
      - "client.version@less_than:10"

      # Block specific operating systems
      - "os.name:Windows XP"
      - "os.short_name:WIN"
      - "os.version@less_than:10"

      # Block specific brands or models
      - "brand:Huawei"
      - "model@contains:Galaxy"

      # Complex user agent rules
      - type: AND
        rules:
          - "bot:false"
          - "client.name:Chrome"
          - "client.version@less_than:80"
```

## Caching

The plugin's detection is backed by `matomo/device-detector`, which compiles a 1.7&nbsp;MB corpus of regex files on the first parse in each PHP process. That costs **110–637&nbsp;ms** depending on the user agent — ordinary mobile browsers are among the worst cases, because brand and model detection walks the largest part of the corpus. Once warm it is roughly 4&nbsp;ms.

Under PHP-FPM every worker pays that on its first request, and again after each `pm.max_requests` recycle. The plugin therefore caches the compiled corpus **by default**:

```
618 ms   first request (populating the cache)
 23 ms   every subsequent process
618 ms   with caching disabled, every time
```

No configuration is needed. The cache is written to `KANOPI_FIREWALL_CACHE_DIR` when that constant is defined, otherwise to a `kanopi-firewall-device-detector` directory inside the system temp directory — the same convention the [AbuseIPDB plugin](abuseipdb.md) uses for its verdict cache.

### Pointing it somewhere else

```yaml
- plugin: "Kanopi\\Firewall\\Plugins\\UserAgent"
  response: block
  enable: true
  metadata:
    cache:
      dir: /var/cache/firewall
  config:
    - "bot:true"
```

### Using a different backend

Any PSR-6 pool works. The shape matches the one [rate limiting](rate-limit.md) already accepts, so there is a single convention to learn:

```yaml
    metadata:
      cache:
        adaptor: "Symfony\\Component\\Cache\\Adapter\\ApcuAdapter"
        args: ['device-detector', 0]
```

An already-constructed pool can be injected through [configuration overrides](../configuration/overrides.md), since YAML cannot carry an object:

```php
Firewall::create([__DIR__ . '/firewall.yml'], [
    '[plugins][0][metadata][cache][adaptor]' => $myCachePool,
]);
```

### Turning it off

```yaml
    metadata:
      cache: false
```

Detection is unchanged either way — only the speed differs.

!!! note "Upgrades invalidate the cache automatically"

    `device-detector` keys its cache entries by its own version, so a `composer update` that bumps the package produces new keys and the stale entries simply age out. There is nothing to clear by hand.

A cache that cannot be created never stops the plugin working: the failure is logged at `warning` and detection continues uncached. An optimisation should not be able to take a site down.

### Only what your rules need

Detection runs in four phases — bot, OS, client, then device (brand and model). Since the rules are known up front, the plugin stops at the deepest phase they actually read:

| Deepest variable in your rules | Phases run | Typical per-request cost |
|---|---|---|
| `bot` | bot | ~0.5&nbsp;ms |
| `os.*` | bot, OS | ~0.9&nbsp;ms |
| `client.*` | bot, OS, client | ~2.8&nbsp;ms |
| `device.type`, `brand`, `model` | all four | ~8.4&nbsp;ms |

A config that only asks `bot:true` therefore costs a fraction of one that inspects `brand`. Nothing needs configuring — the depth is derived from your rules.

Two properties are deliberate:

- **Phases are cumulative, not individually selectable.** Device detection reads the OS and client results to infer a type — Android plus a browser becomes `smartphone`. Running it without them would produce a *wrong* device type, not just a faster one.
- **Bot detection always runs.** Detection stops early once a bot is identified, so a bot never reaches client or device parsing. Skipping it would let bots through to phases they do not reach today, changing what `client.*` rules match.

An unrecognised variable or rule shape falls back to running every phase, so the worst case is a lost optimisation rather than a rule that quietly stops matching.

## Available Variables

- `bot` - Whether the user agent is a bot ("true" or "false")
- `device.type` - Device type (desktop, smartphone, tablet, etc.)
- `client.name` - Browser or client name
- `client.type` - Client type (browser, mobile app, etc.)
- `client.version` - Client version number
- `os.name` - Operating system name
- `os.short_name` - OS short name (WIN, MAC, LIN, etc.)
- `os.version` - OS version number
- `brand` - Device brand (Apple, Samsung, etc.)
- `model` - Device model
