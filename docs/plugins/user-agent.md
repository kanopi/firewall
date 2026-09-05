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

## Catching automated traffic

`bot:true` is backed by `matomo/device-detector`'s curated bot database, which has a blind spot — it does **not** classify a good deal of the tooling a firewall exists to stop.

`automated:true` is the union of that database and a broader crawler list, and catches them:

| | `bot:true` | `automated:true` |
|---|---|---|
| sqlmap, nikto | — | **matched** |
| curl, python-requests, Go-http-client | — | **matched** |
| masscan, nmap, zgrab, wpscan, nuclei, dirbuster | matched | matched |
| Googlebot, bingbot, AhrefsBot, GPTBot | matched | matched |
| real browsers | — | — |

If you wrote `bot:true` expecting scanners to be stopped, **sqlmap is getting through today**. One line changes that:

```yaml
- plugin: "Kanopi\\Firewall\\Plugins\\UserAgent"
  response: block
  enable: true
  config:
    - "automated:true"
```

It is an ordinary rule variable, so it composes like any other:

```yaml
config:
  # Anything automated except your own monitoring.
  - type: AND
    rules:
      - "automated:true"
      - "!client.name@contains:StatusCake"
```

### Why not just widen `bot:`

The broader list deliberately counts generic HTTP client libraries as automated. That is usually what a firewall wants — but if a partner integration, a mobile app, or your own monitoring runs on `python-requests` or `Go-http-client`, `automated:true` **will block traffic that `bot:true` let through**.

Redefining `bot:true` would apply that to rules people wrote long ago and have not touched. As a separate variable it is one line to opt into, and one line to leave alone. `bot:` keeps exactly the meaning it always had.

### `bot.name` and the other sub-keys

`bot.name`, `bot.category` and `bot.producer` come from the curated database only. An agent that solely the wider list recognises will satisfy `automated:true` while exposing no name to match on — the wider list yields a matched pattern, not an identity.

### Interaction with `client.*` rules

Worth knowing if you use `client.name@contains:sqlmap`: it keeps working alongside `automated:true`. Detection stops as soon as an agent is identified as a bot, and a stopped parse exposes no client at all — so the wider list is deliberately kept out of that decision. Folding it in would have silently broken exactly that rule.


## Choosing the bot detection source

`bot:` is answered by device-detector's curated database by default. That is the historical
behaviour and it stays the default, because widening what an existing blocking rule matches
is not something a minor release should do quietly.

When you want the wider list behind `bot:` itself, say so:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\UserAgent"
    response: block
    enable: true
    metadata:
      bot_detector: both      # device-detector | crawler-detect | both
    config:
      - "bot:true"
```

| `bot_detector` | `bot:true` matches |
|---|---|
| `device-detector` *(default)* | The curated bot database — crawlers and the scanners it knows |
| `crawler-detect` | The wider crawler list — adds sqlmap, nikto, curl, python-requests, Go-http-client |
| `both` | Either signal |

!!! warning "The wider list counts HTTP client libraries as bots"
    `curl`, `python-requests` and `Go-http-client` are on it. A partner integration or a
    mobile app built on one of those would start being blocked by a rule that previously
    let it through. That is the trade-off, and it is why the default is the narrow source.

`automated:` is unaffected — it is always the union of both sources, whatever
`bot_detector` says, because that is the question it exists to answer.

### The notice you may see

A plugin configured with `bot:` and no `automated:`, and no explicit `bot_detector`, logs
this once when it is constructed:

```
firewall.NOTICE: bot: does not match sqlmap, nikto, curl, python-requests or Go-http-client —
                 automated: does. Add "automated:true" alongside it, or set
                 metadata.bot_detector to choose a source explicitly and silence this.
```

It is not an error and nothing is broken. It exists because the gap is otherwise invisible:
the rule is valid, it fires, it simply does not know about half the tooling. Setting
`bot_detector` explicitly — to any value, including the default — counts as having made the
choice, and silences it.

### What `bot.name` gives you under each source

device-detector's database carries a name, category and producer. The crawler list carries
only the substring it matched. So under `crawler-detect` or `both`, a bot the curated
database knows still reports all three fields, and one only the crawler list knows reports
`bot.name` as the matched string with no category or producer. That is better than the
field going empty, but do not expect `bot.category` to be populated for everything
`bot:true` now matches.

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

!!! warning "Check the log if you suspect the cache is not working"

    Constructing a cache proves nothing — a filesystem pool is created quite happily against an unwritable directory and only fails later, on each write. The plugin therefore writes and reads back a probe value before trusting a cache, and logs this when it cannot:

    ```
    User Agent regex cache is not writable - every request will re-parse the detection corpus
    ```

    That message means roughly **600 ms per request instead of ~20 ms**. Point `metadata.cache.dir` at a writable directory, define `KANOPI_FIREWALL_CACHE_DIR`, or set `metadata.cache: false` if you want to accept the cost deliberately and stop the warning.

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
