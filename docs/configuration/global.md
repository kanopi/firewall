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
