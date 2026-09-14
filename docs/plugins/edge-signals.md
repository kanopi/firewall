# Edge Signals Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\EdgeSignal`

Matches on what the CDN worked out that the origin cannot: the client's TLS fingerprint, and
the edge's own bot score.

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\EdgeSignal"
    response: block
    weight: 20
    metadata:
      name: cloudflare-bots
      provider: cloudflare
    config:
      - "bot_score <= 5"
```

## What these signals are worth

**A TLS fingerprint** — `ja3`, `ja4` — identifies the *client stack*: which cipher suites,
extensions and curves it offered, in which order. A script wearing a browser's User-Agent
still negotiates TLS like a script, so this catches the thing a User-Agent rule cannot. It is
the gap [reverse-DNS verification](user-agent.md#verifying-the-crawler-is-who-it-says) closes
for crawlers, closed differently for everything else.

**A bot score** is the edge's own verdict, computed from request timing, TLS characteristics
and behaviour across the CDN's whole network — signals that never reach your origin.

Neither is computed here. The edge already decided; this reads the decision. Fingerprinting
belongs to the edge, which is why this plugin is small and can do nothing without a CDN in
front of it.

## The scale runs the other way

!!! danger "A high bot score means *human*"

    Cloudflare's score is **1 for a certain bot and 99 for a certain human** — the opposite
    direction to every reputation score elsewhere in this library, where high is bad.

    ```yaml
    - "bot_score <= 5"     # blocks bots          ✅
    - "bot_score > 30"     # blocks PEOPLE        ❌
    ```

    The mistake is invisible after the fact: the rule matches, the block page is served, the
    log says a rule fired, and the only symptom is that real visitors stopped arriving.
    `firewall-check --lint` warns on a `block` or `challenge` rule comparing `bot_score` with
    `>` or `>=`.

    On a `response: allow` rule that comparison is correct — "let the humans past" — so it is
    not warned about there.

## It does nothing without trusted proxies

These headers are **claims**. Anyone can send `cf-bot-score: 99` straight to your origin, and
against a `response: allow` rule that is not a weakened control but a complete bypass, since
an allow match short-circuits everything after it.

So every signal is ignored unless the request arrived through a trusted proxy — the same gate
[GeoLocation's edge headers](geolocation.md) use, and the same one your deployment needs
anyway for `getClientIp()` to be right:

```php
Request::setTrustedProxies($cdnRanges, Request::HEADER_X_FORWARDED_FOR);
```

A request that did not arrive that way logs at `warning`, because a rule matching nothing
looks exactly like a quiet day.

## Signals

| Signal | Type | |
|---|---|---|
| `bot_score` | int | The edge's verdict. Higher is *more human* |
| `verified_bot` | string | The edge confirmed a declared crawler |
| `ja3` | string | TLS fingerprint hash |
| `ja4` | string | Its successor, with more structure |

A signal the edge did not send resolves to nothing, and a rule comparing against it does not
match. That is deliberate: `bot_score` defaulting to `0` would make every "block the obvious
bots" rule match every request the moment somebody forgot to enable the header.

## Providers

| `provider` | Headers |
|---|---|
| `cloudflare` | `Cf-Bot-Score`, `Cf-Verified-Bot`, `Cf-Ja3-Hash`, `Cf-Ja4` |
| `fastly` | `X-Edge-Bot-Score`, `X-Edge-Verified-Bot`, `X-Edge-Ja3`, `X-Edge-Ja4` — set by the VCL below |
| `custom` | Whatever you map in `metadata.headers` |

!!! warning "None of these headers are present by default"

    On Cloudflare they are added by **Managed Transforms**, per zone. Until the transform is
    enabled the headers are absent, the rules match nothing, and nothing anywhere says so
    except a `debug` line. Check with `firewall-check --explain` against a real request.

### Fastly

Fastly exposes the values in VCL and leaves the naming to you, so the `fastly` profile
expects the names this snippet sets:

```vcl
sub vcl_recv {
  set req.http.X-Edge-Ja3 = tls.client.ja3_md5;
}
```

An existing deployment with different names uses `custom`.

### Akamai and CloudFront

Deliberately not named profiles. Akamai Bot Manager's headers are configured per property, so
there is no fixed name to ship; CloudFront computes no bot signal of its own. Both are
reachable through `custom` — a profile whose header names were invented would be worse than
no profile, because it would look authoritative:

```yaml
metadata:
  provider: custom
  headers:
    bot_score: Akamai-Bot-Score        # whatever your property is configured to send
```

`custom` also layers over a named profile: map one signal and the rest keep the profile's
names.

## Rules

The [conditional logic](../configuration/conditional-logic.md) every other plugin uses:

```yaml
config:
  - "bot_score <= 5"                          # near-certain bots
  - "ja3:e7d705a3286e19ea42f587b344ee6865"    # a fingerprint you have decided about
  - "!verified_bot:true"                      # not a crawler the edge vouched for
```

A misspelled signal is reported at startup rather than matching nothing quietly.

## What gets logged

A match logs at `info` with the provider. A request that did not arrive through a trusted
proxy logs at `warning`. An edge that sent none of the mapped headers logs at `debug` — that
is the Managed Transform case.
