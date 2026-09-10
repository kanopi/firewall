# Global Configuration

The global configuration allows for items like the default status code and the default block message template to be
configured. More options to come.

```yaml
global:
  mode: block
  banning_status_code: 429
  banning_message: '{{request.id}} Request Banned'
  behind_proxy: false
  require_trusted_proxies: false
  require_config: false
  # panic_file: /var/run/firewall/panic   # no default — see Panic Switch below
  stale_source_error_after: 604800
  blocking_escalation:
    - window: 300
      offense: 0
    - window: 3600
      duration: 3600
      offense: 1
    - window: 7200
      offense: 3
      duration: 18000
    - window: 7200
      offense: 3
      duration: 0
```

## Trusted Proxies

Every plugin reads `$request->getClientIp()`, and Symfony only honours proxy headers (`X-Forwarded-For`, `Forwarded`, …) once you have called `Request::setTrustedProxies(...)`. If the application sits behind a proxy and you have not, a client can spoof its source IP and walk past IP allowlists and per-IP rate limits.

The library cannot detect whether a proxy is actually in front of it, so two settings cover the two separate questions.

### `behind_proxy` — asserting the deployment fact

| Value | Behaviour |
|-------|-----------|
| unset (default) | The posture is unknown. Logs a `warning` when trusted proxies are empty, on every request, because the question is unresolved. |
| `false` | Asserted: nothing sits in front of this deployment. The check is skipped silently — there is no proxy to spoof a forwarding header through. |
| `true` | Asserted: there *is* a proxy. Empty trusted proxies is then a definite misconfiguration rather than an open question, so it is logged at `error` instead of `warning`. |

`behind_proxy: false` is the supported way to silence the warning on a site with nothing in front of it:

```yaml
global:
  behind_proxy: false
```

A value that is not interpretable as a boolean — including `behind_proxy:` with nothing after it, or an `%env()%` token that resolves to an empty string — is treated as *unknown* rather than as `false`, and still warns. Silencing a security warning because a key was left half-written is the wrong direction to fail in.

### `require_trusted_proxies` — how loud the unresolved cases are

| Value | Behaviour |
|-------|-----------|
| `false` (default) | Log only, at the level `behind_proxy` selects above. |
| `true` | Throws `Kanopi\Firewall\Exception\ConfigurationException` and refuses to start. Recommended for production deployments behind a load balancer / CDN / reverse proxy. |

`behind_proxy: false` wins over `require_trusted_proxies: true`. An explicit assertion that there is no proxy makes the requirement moot, and throwing anyway would leave an operator who told the truth about their deployment with no way to start.

The two combine to cover the realistic postures:

```yaml
# No proxy. Silent.
global:
  behind_proxy: false

# Behind a CDN, and a missing setTrustedProxies() should fail the deploy.
global:
  behind_proxy: true
  require_trusted_proxies: true
```

See the trusted-proxies note in [Basic Implementation](../getting-started/quick-start.md#basic-implementation) for the `Request::setTrustedProxies(...)` call you need to add before `Firewall::create()`.

## Requiring the config to load

Config loading is lenient: a config file that is missing, unreadable, or malformed contributes nothing to the merge rather than raising. That is convenient for optional config paths and dangerous everywhere else — a firewall with no plugins allows every request. `require_config` decides which of those you get:

| Value | Behaviour |
|-------|-----------|
| `false` (default) | Every config input that failed to load is logged at `error` level (`Firewall config file failed to load — its rules are NOT active`, with the path and the reason), and the firewall starts with whatever did load. |
| `true` | Throws `Kanopi\Firewall\Exception\ConfigurationException` listing every input that failed, and refuses to start. Recommended for production. |

The exception message carries the underlying reason, so a typo, a permissions problem, a YAML syntax error, a circular `configs:` include, an unresolvable `%env(...)%` token, and a disabled `file:` / `require:` processor are all distinguishable:

```
global.require_config is enabled and 1 config input(s) failed to load:
/var/www/firewall.yml — File does not exist.
```

There is one case the YAML flag cannot cover: when the config file that *would* have carried `require_config: true` is itself the one that failed to load. Set it outside the YAML for that:

```php
// Bootstrap, before Firewall::create().
define('KANOPI_FIREWALL_REQUIRE_CONFIG', true);

// …or as an override, which is read even when no config file parsed.
Firewall::create([__DIR__ . '/firewall.yml'], ['[global][require_config]' => true]);
```

`global.require_config` wins over the constant when both are present, including when it is explicitly `false`.

Plugin-level config files (`metadata.config`) are reported the same way — an unreadable one logs `Plugin config file failed to load — its rules are NOT active` and leaves that plugin with only its inline `config:` entries. `require_config` does not escalate those to a startup failure.

## Mode

The `mode` setting controls how the firewall responds when a request is matched by a blocking plugin. Defaults to `block` if not specified.

| Mode | Evaluates plugins? | Writes to storage? | Terminates request? |
|------|--------------------|--------------------|---------------------|
| `block` | Yes | Yes | Yes (sends HTTP response and exits) |
| `log` | Yes | No | No (logs a warning and allows the request) |
| `exception` | Yes | Yes | No (throws — see [Error Handling & Exceptions](../guides/error-handling.md)) |
| `disabled` | No | No | No (skips all evaluation) |

- **`block`** — Default production behavior. Blocked requests receive an HTTP error response and the script exits.
- **`log`** — Useful for dry-run/audit deployments. Plugins are evaluated normally, but blocks are only logged (at `warning` level) without stopping the request or recording offenses in storage. This includes clients already on the durable storage blocklist: the hit is logged, the ban is neither enforced nor extended, and the request continues.
- **`exception`** — Throws instead of calling `exit()`, allowing host frameworks (Laravel, Symfony, etc.) to catch and render their own responses. A block throws `FirewallBlockedException`, which carries the status code (via `getStatusCode()`) and banning message. The challenge flow throws `ChallengeRequiredException` or `ChallengeSolvedException` instead — see [Error Handling & Exceptions](../guides/error-handling.md) for all of them and what to do with each.
- **`disabled`** — Bypasses the firewall entirely. No plugins are evaluated and the request is immediately allowed. Useful for maintenance or feature-flag toggling.

### Observing one rule while the rest enforce

`global.mode` is all or nothing. Putting the firewall in `log` to try out a single new rule
stops **everything else** enforcing too, which is rarely what an operator wants on a live
site.

A rule can carry its own `mode: log` instead:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Crs"
    response: block
    metadata:
      name: crs-paranoia-2
      mode: log        # match, report it, carry on
```

The rule is evaluated normally. When it matches, the match is logged at `warning` and then
treated as **no match**, so evaluation continues to the rules after it and the request is
never blocked by this one. Every other rule enforces as usual.

The line carries `enforced: false` as a separate context key rather than a different
message, so a log table can tell an observed match from an enforced one without parsing
prose:

```
firewall.WARNING: Rule matched in observe mode - not enforced
  {"plugin_name":"crs-paranoia-2","enforced":false, …}
```

That makes the intended workflow a query: add the rule in observe mode, leave it a week,
count what it *would* have blocked and who it would have caught, then remove the key.

!!! note "A mode this does not recognise enforces, and says so"

    `mode: observe` or a typo like `mode: lgo` is not observe mode. The rule enforces, which
    is the dangerous direction to be wrong in, so an unrecognised value logs a warning at
    construction rather than failing silently.

    Only `log` observes. `block` and `enforce` are accepted as explicit no-ops.

Available on any plugin extending `AbstractPluginBase`, which is every built-in one. A
custom plugin implementing `PluginInterface` directly can opt in by also implementing
`ObserveModeInterface` — see [Custom Plugins](../guides/custom-plugins.md).

## Panic Switch

`global.mode` lives in YAML, so changing it is a commit, a review and a release — during
exactly the window where all three are most expensive. `global.panic_file` names a file
that, when it exists, overrides the mode for the next request onward:

```yaml
global:
  mode: block
  panic_file: /var/run/firewall/panic
```

```console
$ echo log > /var/run/firewall/panic     # stop enforcing, keep recording
$ rm /var/run/firewall/panic             # back to the configured mode
```

There is no restart, no deploy and no cache to clear. The file is read once per `Firewall`
instance — one stat per request under PHP-FPM and mod_php — and takes effect immediately.

### Why not an environment variable

An environment variable already works, and needs nothing from this feature:

```yaml
global:
  mode: "%env(default:block:FIREWALL_MODE)%"
```

Use it if it suits you. What it cannot do is *change* without restarting the process that
reads it: under PHP-FPM that is a pool reload, and in a container it is usually a new
container. A file can be created by anyone with a shell on the box, which is the part of
"without a deploy" that matters at 2am.

### The file has to name a mode, and it fails safe if it does not

The file's contents are a mode name — `block`, `log`, `exception` or `disabled`, the same
four [`mode`](#mode) takes. Leading and trailing whitespace and case are ignored, so
`echo LOG >` works.

A file that exists but names nothing recognisable **changes nothing**. That is deliberate,
and it is the opposite of the obvious design. "Any panic file means turn the firewall off"
would mean a leftover file from last month's incident, or a stray deploy artefact, silently
disables the firewall — and nothing about a firewall that is quietly not running announces
itself. So an empty, unreadable or unrecognised file leaves the configured mode alone and
is reported at `error` level, because somebody reached for the switch and it did not take.

It overrides in both directions. `echo block > panic` on a deployment configured for `log`
is a legitimate use, and needs no extra machinery.

### The log line is the safety mechanism

The realistic failure is not somebody flipping the switch. It is somebody flipping it
during an incident and nobody noticing it is still on three weeks later. Nothing else
records that it happened — that is the whole point of a file — so while it is active every
affected request logs at `warning`:

```
firewall.WARNING: Firewall panic switch is ACTIVE
  {"panic_file":"/var/run/firewall/panic","configured_mode":"block","effective_mode":"log", …}
```

`bin/firewall-doctor` reports it as a warning, and `bin/firewall-check` prints it alongside
the verdict — the check suppresses the switch while evaluating, so it still tells you which
rule matches, and then says out loud that the live site is not behaving that way.

Code can ask directly:

```php
$firewall = Firewall::create($configs);

$firewall->getMode();            // FirewallMode::Log — what is actually happening
$firewall->getConfiguredMode();  // FirewallMode::Block — what the YAML says
$firewall->getPanicSwitch();     // ['active' => true, 'mode' => …, 'path' => …, 'problem' => null]
```

### Where to put the file

Anywhere the web user can read and an operator can write. Two things to weigh:

- **Not inside the document root, and not inside the deployed application tree.** A file
  that turns the firewall off is worth exactly as much as write access to its path. Keep it
  somewhere a deploy will not recreate it and a file-upload bug cannot reach it.
- **`panic_file` is unset by default, on purpose.** There is no built-in path to guess at,
  because a well-known default would be the first thing worth trying against every site
  running this library.

## Stale Rule Sources

`stale_source_error_after` is how long a [rule source](sources.md) may go unrefreshed before
[`firewall-doctor`](../guides/diagnosing.md#when-a-stale-rule-source-becomes-an-error)
reports it as an **error** rather than a warning — which is the difference between a green
deploy and a red one.

A week by default. One second past a source's `ttl` is a refresh that has not run yet; a week
past it is a sync that has stopped working, and the rule is still matching on a list nobody
has updated since.

```yaml
global:
  stale_source_error_after: 2592000   # 30 days, for a longer refresh cycle
  # stale_source_error_after: 0       # never escalate; warn only
```

The bound is absolute rather than a multiple of each source's `ttl`, because a multiple gets
the short ones wrong in the dangerous direction: ten times a 60-second `ttl` is ten minutes.

Only affects the diagnostic. Nothing about how a source is fetched, cached or applied at
request time changes.

## Status Code

The status code of the default message can be defined here. By default, it sets it to 400 but can be set to something
else if it is needed.

## Banning Message

The banning message can be configured and dynamically replaced with placeholders. Examples of placeholders can be found
below.

```
* Replace placeholders in a template string with values taken from a Symfony Request
* and/or an additional context array.
*
* Supported placeholders (case-insensitive):
*   • {{ request.method }}          →  GET / POST / …
*   • {{ request.scheme }}          →  http / https
*   • {{ request.host }}            →  example.com
*   • {{ request.path }}            →  /search
*   • {{ request.ip }}              →  client IP (trusts your Symfony trusted proxies config)
*   • {{ request.header.? }}        →  any HTTP header
*   • {{ request.query.? }}         →  ?q=something
*   • {{ request.post.? }}          →  body fields (application/x-www-form-urlencoded, multipart, JSON parsed by you, …)
*   • {{ request.cookie.? }}        →  cookies
```

## Multiple Offenses Defense

Some storage plugins can track multiple offenses from the same attacker over time. You can control how blocking escalates by using the `blocking_escalation` configuration setting.

Below is an example of how to configure it:

```yaml
global:
  blocking_escalation:
    - window: 300
      offense: 0
    - window: 3600
      duration: 3600
      offense: 1
    - window: 7200
      offense: 3
      duration: 18000
    - window: 7200
      offense: 3
      duration: 0
```

Each escalation rule includes the following:

- `window` – Time period in seconds to look back for offenses (e.g., 300 = 5 minutes).

- `offense` – Number of offenses required during the window to trigger the rule.

- `duration` – How long to ban the client (in seconds).

    - Use `0` for a permanent ban.

    - If duration is not set, the plugin's default ban duration will be used.

This system lets you gradually increase penalties for repeat offenders, starting with temporary bans and escalating to permanent blocks if necessary.
