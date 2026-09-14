# Migrating From Another Firewall

Nobody adopts a firewall from nothing. You already have Wordfence, a ModSecurity ruleset, or
a page of Cloudflare rules, and the real evaluation question is **"can I express what I have
today?"**

This page answers it for the three, starting with the part that saves the most time.

## What does not map

Read this first. Finding it on day three is expensive.

### This runs at your origin

Cloudflare, Akamai and any other edge WAF make their decision **before the request reaches
your server**. This library runs inside your application, after PHP has started. Moving a
rule here does not stop the traffic arriving; it stops the traffic being *served*.

That matters for exactly one class of rule: the ones you have for bandwidth or for keeping
load off the origin. A volumetric flood blocked at Cloudflare costs you nothing; the same
flood blocked here still costs a PHP worker per request.

Everything else — blocking, challenging, rate limiting, geographic rules — moves fine, and
gains something in the process: rules live in your repository, in review, deployed with the
code they protect.

!!! tip "The two are not exclusive"

    Keep the edge rules that are about volume. Move the rules that are about application
    behaviour, where the firewall can see the request body, the session, and what your
    application actually does with them. [Edge Signals](../plugins/edge-signals.md) lets rules
    here read what the edge already decided.

### Response inspection

ModSecurity's phase 3 and 4 rules inspect the **response**. This library evaluates requests
only — response-side evaluation is [#69](https://github.com/kanopi/firewall/issues/69) and
not in 2.x. CRS's response-leak categories load and never fire.

### What Wordfence knows and this does not

Wordfence runs *inside* WordPress. It knows which user is logged in, which files changed
since yesterday, and what a core file is supposed to contain. This runs before WordPress
boots, and knows the request.

So these do not move, and nothing here replaces them:

| | |
|---|---|
| Malware and file-change scanning | Not a request-time concern at all |
| Two-factor authentication | Belongs to the application's login |
| "Block this user account" | There is no session yet when this evaluates |
| Repair-changed-files | Wordfence writes to your filesystem; this does not |

What *does* move is everything Wordfence does at the request layer, and it moves into
configuration you can review and deploy.

## From ModSecurity / OWASP CRS

The closest migration of the three, because this library **runs real CRS** through
[`kanopi/crs-engine`](../plugins/crs.md) — the same rule files, the same anomaly scoring,
the same rule IDs.

| ModSecurity | Here |
|---|---|
| `SecRuleEngine On` | `mode: block` *(default)* |
| `SecRuleEngine DetectionOnly` | `mode: monitor` |
| `SecRuleEngine Off` | `enable: false` on the rule |
| `SecAction "… setvar:tx.paranoia_level=2"` | `paranoia: 2` |
| `SecRuleRemoveById 942130` | `disabled_rules: [942130]` |
| `SecRuleRemoveByTag "attack-sqli"` | `disabled_categories: [sqli]` |
| `setvar:tx.inbound_anomaly_score_threshold=10` | `anomaly_thresholds.inbound: 10` |
| A custom `SecRule REQUEST_URI …` | A [URL rule](../plugins/url.md) |

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Crs"
    response: block
    weight: 50
    enable: true
    config:
      paranoia: 1
      mode: monitor          # DetectionOnly, while you port exclusions
      disabled_rules: [942130]
      anomaly_thresholds:
        inbound: 5
```

Your exclusions are the part worth carrying over carefully. `SecRuleRemoveById` lines are a
record of every false positive somebody already paid for, and the rule IDs are identical
here, so they transfer one for one.

**Custom `SecRule` directives do not transfer as syntax.** A rule matching a URI, a header or
a parameter is a [URL rule](../plugins/url.md) with the same variables under different names:

```
SecRule REQUEST_URI "@beginsWith /wp-admin" "id:1000,phase:1,deny,status:403"
```

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    metadata:
      name: admin-paths
      status_code: 403
    config:
      - "path@starts_with:/wp-admin"
```

What has no equivalent: chained rules (`chain`), Lua scripts, persistent collections
(`SecAction initcol`), and anything in phases 3–5.

## From Cloudflare firewall rules

Cloudflare's expression language maps field for field onto rule variables; what changes is
that the decision now happens at your origin.

| Cloudflare expression | Here |
|---|---|
| `ip.src in {1.2.3.4 5.6.7.8}` | [IpAddress](../plugins/ip-address.md) rule, `response: block` |
| `ip.geoip.country eq "CN"` | `country:CN` on a [GeoLocation](../plugins/geolocation.md) rule |
| `http.request.uri.path contains "/wp-login"` | `path@contains:/wp-login` |
| `http.user_agent contains "sqlmap"` | `user_agent@contains:sqlmap` on a [User Agent](../plugins/user-agent.md) rule |
| `http.request.method eq "POST"` | `method:POST` |
| `http.host eq "old.example.com"` | `host:old.example.com` |
| `cf.bot_management.score lt 30` | `bot_score <= 30` on an [Edge Signals](../plugins/edge-signals.md) rule |
| Action: *Block* | `response: block` |
| Action: *Managed Challenge* / *JS Challenge* | `response: challenge` — see [Challenges](../plugins/challenges.md) |
| Action: *Log* | `response: record`, or `metadata.mode: log` to observe one rule |
| Action: *Skip* | `response: allow`, which beats every rule below it |

A rule like `(ip.geoip.country eq "CN" and http.request.uri.path contains "/wp-login")`
becomes a group:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\GeoLocation"
    response: block
    metadata:
      name: cn-login
      provider: cloudflare
      source: header
    config:
      - type: AND
        rules:
          - "country:CN"
          - "path@contains:/wp-login"
```

See [Conditional Logic](../configuration/conditional-logic.md) for the full operator set.

!!! warning "Edge signals need trusted proxies, or they are ignored"

    `cf-bot-score`, `CF-IPCountry` and the rest are **claims** once they arrive at your
    origin, and anyone who finds your origin address can send them. Rules reading them do
    nothing unless the request came through a trusted proxy — see
    [Host Recipes](hosting.md#a-cloudflare-fronted-origin), which also covers locking the
    origin down so the CDN cannot be skipped.

Cloudflare's **Managed Rules** are a commercial WAF ruleset, not something to port
line-by-line. The equivalent here is [CRS](../plugins/crs.md), which is the open ruleset
their managed rules are historically derived from.

## From Wordfence

Wordfence is configured through a UI rather than a file, so this maps capability to
capability rather than syntax to syntax. Everything below is request-layer, which is the part
that moves.

| Wordfence | Here |
|---|---|
| Blocked IPs / ranges | [IpAddress](../plugins/ip-address.md) rule, or a [rule source](../configuration/sources.md) if the list lives elsewhere |
| Country blocking | [GeoLocation](../plugins/geolocation.md) |
| Rate limiting ("how many page views per minute") | [Rate Limit](../plugins/rate-limit.md) |
| "Immediately block IPs that access these URLs" | `presets/honeypot.yml`, or `response: record` on a URL rule |
| Block fake Google crawlers | [User Agent verification](../plugins/user-agent.md#verifying-the-crawler-is-who-it-says) — reverse DNS, same technique |
| Brute-force protection on login | A rate limit on `/wp-login.php`, keyed on the account |
| Firewall rules (the WAF) | [CRS](../plugins/crs.md) plus `presets/malicious-requests.yml` |
| Known-bad URL blocking | `presets/malicious-urls.yml`, `presets/wordpress.yml` |

The login protection is worth spelling out, because Wordfence's version counts by IP and the
version here can count by **account**:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    enable: true
    metadata:
      name: login-throttle
    config:
      - path: /wp-login.php
        rate: 5
        sample: 300
        key: [post.log]        # WordPress posts the username as `log`
      - path: /wp-login.php
        rate: 50
        sample: 300            # and the address, much looser
```

!!! danger "Keep both rules"

    An account key gives every account its own budget, so one address working through a
    username list is never limited by it. The address-keyed rule is what catches that. See
    [What a limit counts by](../plugins/rate-limit.md#what-a-limit-counts-by) — and
    `firewall-check --lint` warns if you have only one.

## Verify the migration rather than trusting it

Every guide above is a translation, and translations are worth checking:

**1. Start in a mode that cannot cause an outage.** `mode: monitor` on CRS,
`metadata.mode: log` on an individual rule, or `global.mode: log` for everything. Each
evaluates fully and enforces nothing — the same request, with the same rules, differing only
in that setting:

```
monitor: ALLOWED  GET /search?q=1%27+UNION+SELECT
block:   BLOCKED  GET /search?q=1%27+UNION+SELECT
```

**2. Replay the requests you know about.** For each rule you moved, check the request it was
supposed to catch:

```bash
vendor/bin/firewall-check --config=firewall.yml --url='/wp-login.php' --ip=203.0.113.5 --explain
```

`--explain` lists every rule that evaluated and every rule that never ran, which is usually
the answer to "why didn't my rule fire".

**3. Check the rules you did not mean to change.** Request something ordinary — a home page,
an asset, a logged-in editor's path — and confirm it is still `ALLOWED`.

**4. Lint before deploying.**

```bash
vendor/bin/firewall-check --config=firewall.yml --lint
```

It reports rules that cannot match, unreachable rules, duplicate names, and the specific
mistakes that look correct: an identity-keyed rate limit with no address-keyed companion, a
bot score compared the wrong way round, a schedule that cannot be read.

**5. Then ask the environment.**

```bash
vendor/bin/firewall-doctor firewall.yml
```

See [Diagnosing](diagnosing.md) for what it checks.
