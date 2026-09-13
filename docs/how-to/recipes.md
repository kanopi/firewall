# Recipes

Keyed on what you are trying to do, not on which feature does it. Each one is a working
configuration and a link to the reference behind it.

| I want to… | |
|---|---|
| [Block a country](#block-a-country) | GeoLocation |
| [Stop a login flood](#stop-a-login-flood) | Rate Limit |
| [Catch a scanner with a honeypot](#catch-a-scanner-with-a-honeypot) | `response: record` |
| [Let Googlebot in safely](#let-googlebot-in-safely) | User Agent + reverse-DNS verification |
| [Rate limit an API by key](#rate-limit-an-api-by-key) | Rate Limit |
| [Run in observe mode for a week](#run-in-observe-mode-for-a-week) | Mode |
| [Find out why a request was blocked](#find-out-why-a-request-was-blocked) | `firewall-check` |
| [Put the site behind a challenge during an incident](#put-the-site-behind-a-challenge-during-an-incident) | Challenge |

---

## Block a country

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\GeoLocation"
    response: block
    enable: true
    metadata:
      name: blocked-countries
      reader:
        type: reader
        db: /usr/local/share/GeoIP/GeoLite2-Country.mmdb
    config:
      - "country:CN"
      - "country:RU"
```

Needs a MaxMind database on disk — [Set Up GeoIP](geoip-setup.md). Without one the rule
cannot match, and `firewall-doctor` reports it rather than failing silently.

!!! tip "Allowlist your own people first"

    Country blocks catch staff travelling and VPN users. Put an allow rule with a negative
    weight above it; the [allow bucket runs first](../reference/evaluation-order.md)
    regardless of weights.

[GeoLocation](../plugins/geolocation.md)

---

## Stop a login flood

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    enable: true
    metadata:
      name: login-flood
      default_rate: 60
      default_sample: 60
      limit_unlisted_paths: false
      storage:
        type: "Kanopi\\Firewall\\RateLimitStorage\\FileRateLimitStorage"
        config:
          file: "{config_dir}/rate-limits.data"
    config:
      - path: /user/login
        rate: 5
        sample: 300        # five attempts per five minutes, per IP
```

!!! warning "`limit_unlisted_paths: false` is doing real work here"

    Without it, adding one rule for `/user/login` also imposes a **site-wide** cap at
    `default_rate` on every other URL, and every request performs a read-modify-write on the
    counter store.

[Rate Limit](../plugins/rate-limit.md)

---

## Catch a scanner with a honeypot

A path no legitimate client has any reason to fetch. Anything that asks for one is written
to the block list and refused **from its next request onward** — the request that springs
the trap is served normally, so the scanner learns nothing about what it found.

```yaml
configs:
  - "{presets_dir}/honeypot.yml"
```

Or your own:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: record
    enable: true
    metadata:
      name: honeypot
      default_expiration_time: 86400
    config:
      - "path:/.ssh/id_rsa"
      - "path:/backup.sql"
```

Verify each path does what you think before relying on it:

```console
$ firewall-check --config=firewall.yml --ip=203.0.113.9 --url=/.ssh/id_rsa --explain
RECORDED  GET /.ssh/id_rsa
  recorded by       honeypot
  effect            served now, refused from the next request onward
```

**`RECORDED`, not `BLOCKED`.** If it says `BLOCKED`, another rule matched that path first and
the stealth is gone — the scanner is told exactly which URL is wired. The shipped preset
deliberately avoids every path the other presets block, which is why it does not include
`/.git/`, `/.env` or `/wp-config*`.

!!! danger "A false positive here is a ban, not a refusal"

    Pick paths that are *never* part of a working site — credentials, keys, repositories,
    database dumps. And allowlist your own scanners first: a security audit you commissioned
    will walk into this and be banned mid-run.

    Keep them out of your sitemap.

[Evaluation Order](../reference/evaluation-order.md#refusing-and-recording-are-separate)

---

## Let Googlebot in safely

The naive version — allow anything whose user agent says `Googlebot` — is an open door,
because the user agent is a string the client chooses. Make the rule prove it:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\UserAgent"
    response: allow
    weight: -200
    enable: true
    metadata:
      name: verified-search-crawlers
      verify: reverse-dns
      verify_suffixes:
        - .googlebot.com
        - .google.com
        - .search.msn.com
        - .applebot.apple.com
    config:
      - "bot:true"
```

The match has to survive a reverse lookup of the client IP, a suffix check, and a forward
lookup back to the same address. A client claiming to be Googlebot from a residential ISP
fails at the first step.

!!! danger "A mistyped `verify` does not verify"

    `verify: reverse_dns` is not `verify: reverse-dns`, and `verify` with no
    `verify_suffixes` accepts any domain. Either mistake leaves you with the open door you
    were trying to close. `firewall-check --lint` reports it.

[User Agent](../plugins/user-agent.md)

---

## Rate limit an API by key

Name the field to count by:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    enable: true
    metadata:
      name: api-limits
      limit_unlisted_paths: false
    config:
      - path: /api/*
        rate: 1000
        sample: 3600
        key: [header.x-api-key]     # per key, whatever address it comes from
```

Any request field works — `header.*`, `post.*`, `cookie.*`, `query.*`, plus `client_ip`,
`path` and `rule_pattern`. See [Rate Limit](../plugins/rate-limit.md#what-a-limit-counts-by).

A composed key is stored hashed, so a token named in a `key:` never reaches the backend.

!!! warning "Counting by something other than the address does not ban an address"

    The durable block list is keyed on the client IP, so a rule with a non-address key
    refuses the request and writes no ban — otherwise an attacker could exhaust a victim's
    account budget and get the *victim's* address banned. See
    [Rate Limit](../plugins/rate-limit.md#what-a-limit-counts-by).

!!! tip "Counting by account stops credential stuffing — alongside, not instead"

    `key: [post.name]` on a login rule counts attempts against the *account*, so ten
    thousand addresses trying one account land in one bucket instead of ten thousand.

    Keep an address-keyed rule for the same path too. An account key gives every account its
    own budget, so one address working through a username list is never limited by it —
    the two catch opposite attacks. `firewall-check --lint` warns if you have only one.

If you need something the field vocabulary cannot express, `buildRateKey()` is still
`protected` — one method on a subclass:

```php
final class ApiKeyRateLimit extends \Kanopi\Firewall\Plugins\RateLimit
{
    protected function buildRateKey(\Symfony\Component\HttpFoundation\Request $request, array $rule): string
    {
        $key = $request->headers->get('X-Api-Key');

        // Fall back to the IP rather than to one shared bucket: an unkeyed
        // caller must not be able to exhaust every keyed caller's allowance.
        return sprintf('rate:%s:%s', $key ?? (string) $request->getClientIp(), $rule['path']);
    }
}
```

Point a rule at it with `plugin: "App\\Firewall\\ApiKeyRateLimit"`.

[Write a Custom Plugin](custom-plugins.md)

---

## Run in observe mode for a week

Everything evaluates, nothing is enforced, every decision is logged:

```yaml
global:
  mode: log
```

This is the right way to introduce an unfamiliar rule set. Turning one straight on is how a
site finds its false positives in production, and the usual recovery is to remove the
firewall rather than tune it.

**To observe one rule while the rest keep enforcing**, which is almost always what you
actually want:

```yaml
metadata:
  name: crs-paranoia-2
  mode: log        # match, report it, carry on
```

Count what it *would* have blocked:

```console
$ grep 'enforced":false' /var/log/firewall/firewall.log | wc -l
```

[Mode](../configuration/global.md#mode) · [Evaluation Order](../reference/evaluation-order.md#what-the-modes-change)

---

## Find out why a request was blocked

```console
$ firewall-check --config=firewall.yml --ip=203.0.113.9 --url=/checkout --explain
```

Names the rule, shows every rule evaluated in order, and lists the ones configured but never
reached. It runs against a throwaway store, so asking about an address cannot ban it.

[Check a Request](checking-requests.md) · [Troubleshooting](troubleshooting.md)

---

## Put the site behind a challenge during an incident

Everyone proves they are human; your own people do not:

```yaml
challenge:
  provider: math
  secret: '%env(FIREWALL_CHALLENGE_SECRET)%'
  path: /_firewall/challenge

plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -200
    enable: true
    metadata: { name: office }
    config: ['198.51.100.0/24']

  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: challenge
    weight: 500
    enable: true
    metadata: { name: incident-challenge-everyone }
    config: ['0.0.0.0/0', '::/0']
```

```
CHALLENGED  GET /      client 203.0.113.9    challenged by incident-challenge-everyone
ALLOWED     GET /      client 198.51.100.7   allowed by    office
```

**Add and remove it without editing YAML**, which is the point during an incident:

```console
$ firewall-rule add firewall.yml --ip=0.0.0.0/0 --ip=::/0 \
    --response=challenge --weight=500 --name=incident-challenge
$ firewall-rule remove incident-challenge firewall.yml
```

!!! warning "Challenging is not blocking, and that is deliberate"

    A challenge costs an attacker CPU and a real visitor a few seconds. If you want to serve
    nobody at all, that is a `block` rule with the same `0.0.0.0/0` config — but every
    refused visitor is then written to the durable block list with escalation applied, and
    stays banned after you remove the rule.
    [#304](https://github.com/kanopi/firewall/issues/304) is the proper fix for that.

[Add a Challenge](add-a-challenge.md) · [Manage Rules](managing-rules.md)
