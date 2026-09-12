# Configuration Keys

Every key the code reads, in one place. This page answers *"what was that key called
again"* — press ++cmd+f++ and search it.

For what a setting means and why you would change it, follow the link in the last column.
Nothing here explains anything; that is deliberate.

!!! warning "The single most common mistake"

    `FileStorage` reads **`storage_file`**. `FileRateLimitStorage` reads **`file`**. They
    are different keys for the same idea, and getting it wrong does not error — the backend
    falls back to a hashed filename in the system temp directory, so the firewall appears to
    work while keeping its block list somewhere you did not choose and may lose on reboot.

## Top level

| Key | Type | What it holds |
|---|---|---|
| `configs` | list | Other files to merge in — paths, globs, URLs, `{config_dir}` / `{presets_dir}` tokens. [Loading & Includes](../configuration/loading-and-includes.md) |
| `global` | map | Site-wide behaviour. Table below |
| `storage` | map | Where blocks are persisted. Table below |
| `logger` | list | Monolog handlers. [Logging](../configuration/logging.md) |
| `challenge` | map | Challenge flow settings. Table below |
| `plugins` | list | The rules. Table below |

!!! danger "A `configs:` entry naming a file that does not exist empties the whole document"

    A missing include is a load failure, not a skipped line — every rule stops being
    configured. `global.require_config: true` turns that into a startup exception instead.

## `global:`

| Key | Type | Default | | |
|---|---|---|---|---|
| `mode` | string | `block` | `block`, `log`, `exception`, `disabled`, `lockdown` | [Mode](../configuration/global.md#mode) |
| `panic_file` | string | *unset* | A file that overrides `mode` when it exists | [Panic Switch](../configuration/global.md#panic-switch) |
| `banning_status_code` | int | `400` | Status sent when a rule blocks | [Status Code](../configuration/global.md#status-code) |
| `banning_message` | string | built-in | Body template; `{{request.id}}` is substituted | [Banning Message](../configuration/global.md#banning-message) |
| `repeat_offender_status` | int | `0` | Status for a client already on the block list | [Global](../configuration/global.md) |
| `add_to_expire` | int | `3600` | Seconds added to a ban on each repeat hit | [Global](../configuration/global.md) |
| `blocking_escalation` | list | `[]` | Window/offense/duration rules that lengthen bans | [Multiple Offenses](../configuration/global.md#multiple-offenses-defense) |
| `behind_proxy` | bool | *unset* | Assert whether a proxy sits in front | [Trusted Proxies](../configuration/global.md#trusted-proxies) |
| `require_trusted_proxies` | bool | `false` | Refuse to start without `setTrustedProxies()` | [Trusted Proxies](../configuration/global.md#trusted-proxies) |
| `require_config` | bool | `false` | Refuse to start if any config input failed to load | [Loading](../configuration/loading-and-includes.md) |
| `lockdown` | bool | `false` | Refuse everyone but `lockdown_allow` | [Lockdown](../configuration/global.md#lockdown) |
| `lockdown_allow` | list | *(empty)* | Addresses and CIDRs still served. Empty serves nobody | [Lockdown](../configuration/global.md#lockdown) |
| `lockdown_status` | int | `503` | | [Lockdown](../configuration/global.md#lockdown) |
| `lockdown_retry_after` | int | `300` | Seconds in `Retry-After`; `0` omits it | [Lockdown](../configuration/global.md#lockdown) |
| `lockdown_message` | string | built-in | Supports `{{request.id}}` | [Lockdown](../configuration/global.md#lockdown) |
| `stale_source_error_after` | int | `0` *(off)* | Seconds before an unrefreshed source is an error | [Stale Rule Sources](../configuration/global.md#stale-rule-sources) |

## `storage:`

| Key | Type | |
|---|---|---|
| `type` | class | `FileStorage`, `DatabaseStorage`, `RedisStorage`, `InMemoryStorage` |
| `config` | map | Backend-specific, below |

| Backend | `config` keys | |
|---|---|---|
| `FileStorage` | **`storage_file`**, `offense_file` | Paths; relative resolves against the YAML file |
| `DatabaseStorage` | `connection`, `storage_table`, `offenses_table`, `schema_check_probability` | [Storage](../configuration/storage.md) |
| `RedisStorage` | `redis`, `instance` | Requires `ext-redis` |
| `InMemoryStorage` | — | Per-process; nothing survives the request |

Rate-limit counters are stored separately, under the RateLimit plugin's own metadata:

| Backend | `config` keys |
|---|---|
| `FileRateLimitStorage` | **`file`** |
| `DatabaseRateLimitStorage` | `connection`, `schema_check_probability` |
| `RedisRateLimitStorage` | `redis`, `instance`, `ttl` |
| `CacheRateLimitStorage` | `adaptor`, `args`, `ttl` |
| `InMemoryRateLimitStorage` | — |

## `challenge:`

| Key | Type | Default | | |
|---|---|---|---|---|
| `provider` | string | *required* | `math`, `altcha`, `turnstile`, `recaptcha`, or a FQCN | [Challenges](../plugins/challenges.md) |
| `secret` | string | *required* | HMAC key for pass tokens. Startup fails if empty | [Challenges](../plugins/challenges.md) |
| `path` | string | `/_firewall/challenge` | Where the interstitial POSTs | [Add a Challenge](../how-to/add-a-challenge.md) |
| `cookie_name` | string | `''` | Pass-token cookie; empty disables cookie delivery | [Challenges](../plugins/challenges.md) |
| `header_name` | string | `''` | Header an SPA can send the token in | [Challenges](../plugins/challenges.md) |
| `audience` | string | provider name | `aud` claim, to scope tokens between instances | [Scoping tokens](../plugins/challenges.md#scoping-tokens-across-instances) |
| `provider_options` | map | `[]` | Per-provider settings, keyed by provider name | [Challenges](../plugins/challenges.md) |

## `plugins:` — one entry

| Key | Type | Default | |
|---|---|---|---|
| `plugin` | class | *required* | The rule class |
| `response` | string | `block` | `allow`, `block`, `challenge`, `record`, `redirect`, `mark` — decides the bucket, and [buckets beat weights](evaluation-order.md) |
| `weight` | int | `0` | Order **within** its bucket; lower runs first |
| `enable` | bool | `true` | |
| `metadata` | map | `[]` | How the rule behaves. Below |
| `config` | list | `[]` | The rule's own entries — addresses, paths, patterns |

## `metadata:` — common to every plugin

| Key | Type | Default | | |
|---|---|---|---|---|
| `name` | string | class name | What the log calls it. Name every rule | [Plugins](../plugins/index.md) |
| `mode` | string | *enforce* | `log` observes this one rule without enforcing it | [Observe mode](../configuration/global.md#observing-one-rule-while-the-rest-enforce) |
| `status_code` | int | `banning_status_code` | Per-rule override | [Status Code](../configuration/global.md#status-code) |
| `default_expiration_time` | int | `3600` | Ban length, or pass-token TTL on a challenge rule | [Global](../configuration/global.md) |
| `record` | bool | `true` | `false` refuses without writing to the block list. On a `redirect` rule the default is `false` and `true` opts in | [Evaluation Order](evaluation-order.md#refusing-and-recording-are-separate) |
| `mark_as` | string | the rule's name | The signal `response: mark` raises, so several rules can raise one |
| `mark_header` | string | — | Also set this header on the request when marking |
| `redirect_to` | string | — | Required by `response: redirect`. Never built from the request, so it cannot become an open redirect |
| `redirect_status` | int | `302` | `301`, `302`, `307` or `308` |
| `sources` | list | `[]` | Pull this rule's entries from elsewhere | [Rule Sources](../configuration/sources.md) |
| `challenge_provider` | string | `challenge.provider` | Per-rule provider override | [Per-plugin providers](../plugins/challenges.md#per-plugin-providers) |
| `config` | list | — | Legacy alias for the entry's `config:` | [Legacy format](legacy-format.md) |

Identity-verifying plugins (User Agent, and any implementing
`IdentityVerificationInterface`) add `verify`, `verify_cache`, `verify_ttl`,
`verify_negative_ttl`, `verify_suffixes`, `verify_claim_wait_ms` and
`verify_slow_threshold_ms` — see [User Agent](../plugins/user-agent.md).

Every `sources:` option is its own table in [Rule Sources](../configuration/sources.md#every-option).

## PHP constants

Set before `Firewall::create()`. These exist because they must be readable before any YAML
is parsed.

| Constant | Default | |
|---|---|---|
| `KANOPI_FIREWALL_CACHE_DIR` | system temp | Where compiled config and source caches are written |
| `KANOPI_FIREWALL_CACHE_TTL` | `3600` | Default rule-source TTL, when a source names none |
| `KANOPI_FIREWALL_CACHE_MAX_AGE` | 30 days | Compiled-config entries older than this are swept; `0` disables |
| `KANOPI_FIREWALL_CACHE_MAX_STALE` | — | How long a stale cached source may still be served |
| `KANOPI_FIREWALL_CACHE_TIMEOUT` | — | Fetch timeout for remote sources |
| `KANOPI_FIREWALL_REQUIRE_CONFIG` | `false` | Same as `global.require_config` |
| `KANOPI_FIREWALL_SOURCES_OFFLINE` | `false` | Never fetch on the request path | 

[Environment Variables](../configuration/environment-variables.md) covers `%env(...)%`
substitution, which works in any value above.
