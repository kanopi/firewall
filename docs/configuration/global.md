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
  # trusted_proxies: ["10.0.0.0/8"]       # see Trusted Proxies below
  require_config: false
  # panic_file: /var/run/firewall/panic   # no default — see Panic Switch below
  # stale_source_error_after: 604800      # off by default — see Stale Rule Sources
  # reverse_dns: { provider: cloudflare } # PHP's own lookups by default — see Reverse DNS
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

### Trusted proxies from YAML

The proxies can be declared in configuration, not only in your bootstrap:

```yaml
global:
  trusted_proxies: ["10.0.0.0/8", "173.245.48.0/20"]      # your proxies' own ranges
  trusted_headers: [x-forwarded-for, x-forwarded-proto]  # optional
```

| Entry | Trusts |
|---|---|
| An address or CIDR range, IPv4 or IPv6 | That proxy, or that range of them |
| `REMOTE_ADDR` | Whatever connected, for a load balancer whose address you do not know in advance. Resolved from the request being evaluated |
| `PRIVATE_SUBNETS` | Every private and loopback range, as Symfony defines them |

`trusted_headers` takes `forwarded`, `x-forwarded-for`, `x-forwarded-host`,
`x-forwarded-proto`, `x-forwarded-port` and `x-forwarded-prefix`. It defaults to
`x-forwarded-for`, `x-forwarded-proto` and `x-forwarded-port`: enough for the client
address and scheme. `x-forwarded-host` is left out unless you name it, because trusting it
changes what the request reports as its host.

**It applies to the firewall's own reads, and only while it evaluates.** Symfony keeps
trusted proxies in process-wide static state, so setting them for good would change what
your application sees as well. They are applied at the start of each `evaluate()` and put
back afterwards, including when a decision leaves as an exception. In `mode: block` the
firewall sends its response and exits, and PHP skips `finally` on `exit()`. The process
ends there, so only a shutdown function could still see them.

**Your bootstrap wins.** If the application has already called
`Request::setTrustedProxies()`, its proxies are used and `trusted_proxies` is ignored, with a
warning the first time. The host knows its infrastructure; use one source or the other.

**Refused at startup:**

- a range that trusts every address — `0.0.0.0/0`, `::/0`. That trusts every client's own
  `X-Forwarded-For`, which is the spoofing hole this setting exists to close;
- an entry that is not an address, a range or a keyword;
- a header name that is not a forwarding header. A header silently not trusted is a quiet
  version of the same problem.

`require_trusted_proxies: true` is satisfied by either source. And `firewall doctor` can
check this form from a terminal, which the bootstrap form it cannot: it reports the proxies
and headers in force, or why they were refused.

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
| `exception` | Yes | Yes | No (throws — see [Error Handling & Exceptions](../reference/error-handling.md)) |
| `disabled` | No | No | No (skips all evaluation) |

- **`block`** — Default production behavior. Blocked requests receive an HTTP error response and the script exits.
- **`log`** — Useful for dry-run/audit deployments. Plugins are evaluated normally, but blocks are only logged (at `warning` level) without stopping the request or recording offenses in storage. This includes clients already on the durable storage blocklist: the hit is logged, the ban is neither enforced nor extended, and the request continues.
- **`exception`** — Throws instead of calling `exit()`, allowing host frameworks (Laravel, Symfony, etc.) to catch and render their own responses. A block throws `FirewallBlockedException`, which carries the status code (via `getStatusCode()`) and banning message. The challenge flow throws `ChallengeRequiredException` or `ChallengeSolvedException` instead — see [Error Handling & Exceptions](../reference/error-handling.md) for all of them and what to do with each.
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
`ObserveModeInterface` — see [Custom Plugins](../how-to/custom-plugins.md).

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

`bin/firewall doctor` reports it as a warning, and `bin/firewall check` prints it alongside
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

## Lockdown

Refuse everyone but an explicit allowlist. The thing you want when a site is actively being
hammered and you would rather serve nobody than serve the attacker.

```yaml
global:
  mode: exception          # unchanged — lockdown does not replace it
  lockdown: true
  lockdown_allow:
    - 198.51.100.0/24      # the office
    - 203.0.113.10-203.0.113.20
    - 2001:db8::/32
```

| Key | Default | |
|---|---|---|
| `lockdown` | `false` | Turns it on |
| `lockdown_allow` | *(empty)* | Addresses, CIDRs and `start-end` ranges still served, the same notations the [`IpAddress`](../plugins/ip-address.md) rule takes. **Empty serves nobody** |
| `lockdown_status` | `503` | |
| `lockdown_retry_after` | `300` | Seconds in `Retry-After`; `0` omits the header |
| `lockdown_message` | built-in | Supports `{{request.id}}` |
| `lockdown_page` | *unset* | `true` or a map: an HTML page instead of the message. See [Block and lockdown pages](#block-and-lockdown-pages) |

### An entry it cannot read serves nobody

An entry that is not an address, a CIDR block or a `start-end` range (a hostname, a
typo, a range whose bounds are backwards or from different families) matches nobody.
The firewall does not guess what was meant. `firewall doctor` names every such entry,
and reports it as an error when the lockdown is already on:

```console
  ✗ Lockdown is ACTIVE and its allowlist has 1 entry that can never match
      "203.0.113.20-203.0.113.10" is not an address, a CIDR block or a start-end range, so it serves nobody. …
```

Run it before you flip the switch, not after.

### It is a flag, not a mode

`mode` decides *how* a refusal is delivered — exit, throw, log, nothing. Lockdown decides
*who* is refused. They are separate axes, so a host running `mode: exception` can enter
lockdown without the library suddenly calling `exit()` on its framework mid-incident.

`mode: lockdown` still works and is shorthand for "lock down, and refuse the way `block`
does" — including from a [panic file](#panic-switch):

```console
$ echo lockdown > /var/run/firewall/panic
```

Use the flag if your mode matters to you; use the shorthand at 2am.

### It records nobody

This is the reason lockdown exists as a feature rather than as two ordinary rules. A
catch-all block rule achieves the same refusal, and writes **every legitimate visitor** to
the durable block list with `blocking_escalation` applied — so lifting it leaves a block list
full of customers, each on a lengthening ban, and recovery means lifting them one by one.

A deliberate, temporary refusal of everybody is not evidence that any of them misbehaved.
Lockdown refuses and records nothing.

### What still applies

Lockdown adds a refusal; it never removes one.

- **A challenge submission still reaches the firewall**, so a visitor already holding an
  unsolved challenge can finish it rather than being bricked along with everyone else.
- **An allow *rule* does not grant entry.** Only `lockdown_allow` does. An allow rule written
  months ago to whitelist a payment webhook is not a considered answer to "who should reach
  this site while it is under attack".
- **Everything below still runs** for an allowlisted client — the durable block list, and
  every rule. Being on the list is not a bypass.

!!! warning "An empty allowlist locks you out too"

    `lockdown_allow` with nothing in it refuses every visitor, which is what deny-by-default
    means. `firewall doctor` reports an empty list as a warning before you rely on it, and as
    an error once lockdown is on.

## Path Source

Which path the rules match: every `path` condition, rate-limit pattern and preset, and the `path` in logs and block records.

```yaml
global:
  path_source: script_name   # default: pathinfo
  base_path: /blog           # optional: where the application is installed
```

| Key | Default | |
|---|---|---|
| `path_source` | `pathinfo` | `pathinfo` is the path relative to the front controller. `script_name` is the file the web server ran, falling back to `pathinfo` when that file is the front controller |
| `base_path` | *unset* | With `script_name`, where the application is installed. `<base_path>/index.php` is the front controller, and `base_path` is taken off the front of any other file's path |

### Which one you need

| Application | `path_source` |
|---|---|
| **WordPress** | **`script_name`** |
| Drupal, for rules on `core/install.php`, `core/rebuild.php` or `core/authorize.php` | `script_name` |
| Laravel, Symfony, Drupal's routes: anything where every request goes through `index.php` | the default, `pathinfo` |

`pathinfo` is Symfony's `getPathInfo()`, and it's right when every request goes through one `index.php`. **Keep it for a front-controller application.** `script_name` gives the same answer there, but it isn't more correct, and it matters that nobody turns it on thinking it is.

**`pathinfo` is wrong for a file the web server runs directly.** For such a file, `SCRIPT_NAME` is the file itself, and the path relative to it is `/`:

| Request | Server runs | `pathinfo` | `script_name` |
|---|---|---|---|
| `/wp-login.php` | `wp-login.php` | `/` | `/wp-login.php` |
| `/wp-admin/edit.php` | `wp-admin/edit.php` | `/` | `/wp-admin/edit.php` |
| `/wp-admin/` | `wp-admin/index.php` | `/` | `/wp-admin/index.php` |
| `/xmlrpc.php` | `xmlrpc.php` | `/` | `/xmlrpc.php` |
| `/core/install.php` (Drupal) | `core/install.php` | `/` | `/core/install.php` |
| `/learning/` | `index.php` | `/learning/` | `/learning/` |

So under `pathinfo`, a rule on `/wp-login.php` never fires on the real login page, a rate limit on it never counts, and a *negated* condition such as `!path@starts_with:/wp-admin` is true on every admin screen. WordPress serves its login page, XML-RPC, cron and every admin screen as files of their own. Drupal's `settings.php`, where the firewall usually runs, is also loaded by the files Drupal serves directly.

Note the admin index: the server runs `wp-admin/index.php`, so that's the path. A rule written `path@starts_with:/wp-admin` matches it; an exact `path:/wp-admin/` doesn't.

`pathinfo` stays the default in 2.x, because switching would change what `path` means for sites that work today.

### Why it's the file that ran, not the URL

The web server decodes and normalises the URL before it chooses a file. `/./wp-login.php`, `/%77p-login.php`, `//wp-login.php` and `/x/../wp-login.php` all run `wp-login.php`. Matched as the raw URL, each would walk past a `path:/wp-login.php` rate limit. `SCRIPT_NAME` is `/wp-login.php` for all of them, because it's what the server ran after all that work.

It's read from the request the firewall evaluates, never from `$_SERVER`, so it's also right under Octane, RoadRunner or Swoole, where `$_SERVER` belongs to the worker.

### One spelling for every path

Whichever source you use, the path is normalised before any rule sees it, the way the web
server normalises a URL before routing it (#425):

| Request | Matched as |
|---|---|
| `//wp-json/wp/v2/users` | `/wp-json/wp/v2/users` |
| `/./wp-json/…`, `/%2e/wp-json/…` | `/wp-json/…` |
| `/%77p-json/…` | `/wp-json/…` |
| `/user/login;jsessionid=1` | `/user/login` |
| `/wp-json/a/../../x` | `/wp-json/a/../../x` (`..` is **not** resolved) |

- Percent-encoded **unreserved** characters (`A-Z a-z 0-9 - . _ ~`) are decoded. Other
  encodings keep their meaning, upper-cased: `%2F` stays `%2F`, because decoding it would
  move a segment boundary.
- **`..` is kept as written.** The application routes on the raw path: WordPress still
  hands `/wp-json/a/../../x` to the REST API. Resolving the dots would show the rules `/x`,
  a way past every rule on `/wp-json/`. Every other step only removes an empty or `.`
  segment, so a path that begins with `/wp-json/` still does, and a rule on it still
  matches.
- A trailing slash is kept, so `/wp-admin` and `/wp-admin/` are still different paths.
- The normalised path is also what logs and block records show.

Without this, `//wp-json/wp/v2/users` reached WordPress as the REST route, because
WordPress trims every leading slash, while missing a rule on `/wp-json/`.

### Subdirectory installs

On a direct-file request, nothing in the request says where the application starts. `getBasePath()` for `/wp-admin/edit.php` is `/wp-admin`. So name it:

```yaml
global:
  path_source: script_name
  base_path: /blog
```

`/blog/index.php` is then the front controller, and `/blog/wp-login.php` is matched as `/wp-login.php`, so the presets work unchanged. The prefix is removed only at a segment boundary (`/blogroll` isn't inside `/blog`), and a file outside it is matched whole.

### WordPress in its own directory

With WordPress "in its own directory", the site's `index.php` is at the root and core lives
under `/wp/`. Leave `base_path` unset: the front controller really is `/index.php`. Core's
files then resolve as `/wp/wp-login.php`, `/wp/wp-admin/edit.php` and so on.
`presets/wordpress.yml` and `search-bots.yml` match WordPress's files and directories **at
any depth**, so they cover this layout and a subdirectory install with no extra setting
(#420).

If you write your own rules or rate limits for WordPress, do the same. Match on a segment
boundary rather than from the root:

```yaml
- "path@regex:#(^|/)wp-login(/|$|\\.)#"       # a Url rule
# a rate limit: a wildcard ignores case and matches any prefix
- { path: "*/wp-login.php", rate: 5, sample: 300 }
```

### Checking it

```console
$ vendor/bin/firewall check --config=firewall.yml --url=/wp-login.php --script-name=/wp-login.php
```

`--script-name` makes the check a direct-file request. Without it, the check matches the path as typed, which is not what the site sees under `pathinfo`. The tool warns about this when `--url` names a `.php` file. `firewall doctor` reports which source is in use, and reports an unknown `path_source` or an unusable `base_path` as an error. At runtime, the firewall falls back to `pathinfo` with a warning.

## Stale Rule Sources

`stale_source_error_after` is how long a [rule source](sources.md) may go unrefreshed before
[`firewall doctor`](../how-to/diagnosing.md#making-a-stale-rule-source-fail-the-deploy)
reports it as an **error** rather than a warning — which is the difference between a green
deploy and a red one.

**Off unless you set it.** One second past a source's `ttl` is a refresh that has not run
yet; a fortnight past it is a sync that has stopped working, and the rule is still matching
on a list nobody has updated since. Where the line between those falls is a question about
your own refresh cycle, so nothing is assumed:

```yaml
global:
  stale_source_error_after: 604800    # a week — a reasonable starting point
```

| Value | |
|---|---|
| unset, or `0` | Never escalate. A stale source is a warning, as it has always been |
| seconds | Past that age, a stale source becomes an error and `firewall doctor` exits `1` |

The bound is absolute rather than a multiple of each source's `ttl`, because a multiple gets
the short ones wrong in the dangerous direction: ten times a 60-second `ttl` is ten minutes,
and a ten-minute-old rule list is not an incident.

A value that is set and is not a number — `"30 days"`, which YAML hands over as a string
without complaint — turns the escalation off and is reported as a warning of its own. Asking
for a gate, believing you have one, and not having one is the outcome worth avoiding.

Only affects the diagnostic. Nothing about how a source is fetched, cached or applied at
request time changes.

## Reverse DNS

`reverse_dns` chooses who makes the DNS lookups behind
[`verify: reverse-dns`](../plugins/user-agent.md#verifying-the-crawler-is-who-it-says).
Unset, it's PHP's own lookups, as it always was. Naming a provider sends the lookups to
that provider, a third party, with a time limit on each:

```yaml
global:
  reverse_dns:
    provider: cloudflare
    timeout_ms: 300
```

Read [Reverse DNS](reverse-dns.md) before setting it: it covers the built-in providers,
what each one receives and says it logs, defining your own, and writing a resolver class.

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

A block also substitutes:

- `{{block.status}}`: the status being sent.
- `{{block.rule}}`: the name of the rule that refused the request. This tells the client
  which rule it tripped, so it's never in a default and only appears where you write it.

A rule can carry its own message as `metadata.banning_message`, which replaces this one for
blocks that rule causes.

The message is sent as `text/plain`, so HTML in it is shown as source. For a page, use
[`block_page`](#block-and-lockdown-pages).

## Block and lockdown pages

A block and a lockdown are plain text unless you ask for a page (#452). `block_page` and
`lockdown_page` take the same kind of settings as
[`challenge.page`](../plugins/challenges.md#wording-language-and-styling), and the page
is built on the challenge interstitial's card and stylesheet, so one set of `styles`
themes all three, and the same [colour properties](../plugins/challenges.md#colours) recolour them:

```yaml
global:
  block_page: true             # the built-in page, as it comes
  lockdown_page:
    lang: fr
    heading: "De retour bientôt"
    message: |
      Nous mettons le site à jour jusqu'à 18 h UTC.
      Référence : {{request.id}}
    styles: ".card { border-top: 4px solid #0b8f5a; }"
    stylesheet: /themes/custom/site/firewall.css
```

| Key | Default (block / lockdown) | |
|---|---|---|
| `lang` | `en` | The page's `lang` attribute |
| `title` | `Request blocked` / `Temporarily closed` | The browser tab's title |
| `heading` | `Request blocked` / `Temporarily closed` | The heading on the card |
| `message` | `banning_message` / `lockdown_message` if you set one, else the built-in text, which quotes `{{request.id}}` | One paragraph per line |
| `styles` | *none* | CSS after the built-in rules |
| `stylesheet` | *none* | A `<link rel="stylesheet">`: a path on this site or an `https:` URL |
| `template` | *none* | Your own HTML document instead of the built-in one. See [Your own template](#your-own-template) |

- **`true`** is the built-in page. **`false`**, or leaving it out, is the plain-text
  message it has always been.
- **Text is plain text,** with the same `{{…}}` placeholders as `banning_message`. What
  the client sent is substituted and the whole is escaped once, so it can't become markup.
- **A rule's own page** is `metadata.block_page`: `true`, or a map merged over
  `block_page` for the blocks that rule causes. It works whether or not `block_page` is set.
- **Sent with a strict `Content-Security-Policy`.** The page has no script and no form, so
  neither is allowed. Styles, images and fonts are allowed from this site and over
  `https:`, so a stylesheet and a logo in it work.
- **A value that can't be used stops the firewall starting** with a
  `ConfigurationException` naming every problem, and `firewall lint` reports it first. This
  covers an unknown key, text that isn't text, a malformed `lang`, CSS containing a closing
  `style` tag, and a stylesheet that isn't a path or an `https:` URL.
- **In `mode: exception`,** the page is the exception's message, and `getContentType()`
  says what it is. See [Error Handling](../reference/error-handling.md).

### Your own template

The built-in page is the default. To use your own layout, with your logo, header and
footer, set `template` to a whole HTML document (#456). `%file(...)%` loads it from disk
when the configuration loads:

```yaml
global:
  block_page:
    template: '%file(/etc/firewall/block.html)%'
    lang: fr
    heading: "Accès refusé"
    message: |
      Cette requête a été bloquée par le pare-feu du site.
      Référence : {{request.id}}

plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    metadata:
      name: no-facet-crawl
      block_page:
        message: "Automated access to search is not allowed."   # same template, its own message
```

The page's other keys fill the template's placeholders, so a rule's own `message`, or a
translated `heading`, lands in your layout:

```html
<!DOCTYPE html>
<html lang="{{page.lang}}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>{{page.title}} · Example Co.</title>
  <link rel="stylesheet" href="/themes/custom/site/css/firewall.css">
  <style>
    .brand { height: 32px; margin-bottom: 1.5rem; }
  </style>
</head>
<body>
  <main class="panel">
    <img class="brand" src="/themes/custom/site/logo.svg" alt="Example Co.">
    <h1>{{page.heading}}</h1>
    {{page.message}}
    <p class="meta">Status {{block.status}} · Reference <code>{{request.id}}</code></p>
  </main>
</body>
</html>
```

| Placeholder | Value |
|---|---|
| `{{page.message}}` | The message as `<p>` paragraphs, one per line, already escaped. From `message`, else `banning_message` / `lockdown_message`, else the built-in text |
| `{{page.heading}}`, `{{page.title}}` | The page's text, or the built-in wording |
| `{{page.lang}}` | `lang`, or `en` |
| `{{block.status}}`, `{{block.rule}}` | As in [Banning Message](#banning-message) |
| `{{request.*}}` | Every request placeholder, as in [Banning Message](#banning-message) |

- **Every placeholder is HTML-escaped,** except `{{page.message}}`, which is markup the
  firewall builds from escaped text. That makes them safe in element text and in quoted
  attributes (`title="{{request.path}}"`).
- **They aren't safe** inside `<script>` or `<style>`, in an unquoted attribute, or as a
  whole URL (`href="{{request.query.next}}"`). Don't put them there.
- **The same `Content-Security-Policy` applies.** Inline `<script>` and `onclick=` don't
  run. Inline `<style>`, a stylesheet from this site or over `https:`, images and fonts
  all work.
- **What a client sends is substituted once.** A header that contains `{{page.message}}`
  shows as that text; it isn't expanded.
- **An unknown placeholder is left as written,** so a typo like `{{page.mesage}}` shows
  on the page rather than disappearing.
- **`styles` and `stylesheet` can't be set with `template`,** because the template carries
  its own styling. That includes a global `template` with a rule's `styles`, or the reverse.
  Startup refuses it.
- **`template` must be a document,** with an `<html>` element. A fragment is refused.
  `firewall lint` warns about a template without `{{page.message}}`, because every block
  would then show the same words, whatever the rule says.
- **`lockdown_page.template`** works the same way, and a rule can set its own
  `metadata.block_page.template`.

### JSON for API clients

```yaml
global:
  banning_json: true
```

A client whose **first** preference in `Accept` is JSON (`application/json`, or any
`+json` type) gets `{"error":"blocked","status":403,"request_id":"…"}` instead of the
page or the message. A lockdown answers `{"error":"lockdown",…,"retry_after":300}`. A
browser lists `text/html` first and still gets the page.

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
