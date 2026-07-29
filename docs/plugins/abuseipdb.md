# AbuseIPDB Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\AbuseIpdb`

Checks the client IP against [AbuseIPDB](https://www.abuseipdb.com/), which scores an address 0-100 by how confidently it has been reported for abuse. The plugin matches when that score reaches `threshold`, so a known-bad address can be turned away before the expensive rule-matching plugins run.

Requires a free API key from [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api). With no `api_key` the plugin is a no-op that matches nothing, so it is safe to add to a config before the key is provisioned.

## Configuration Example

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\AbuseIpdb"
    response: block
    # Cheaper than CRS, dearer than a static IP list — sit between them.
    weight: 40
    enable: true
    config:
      # Required. An %env()% token keeps the key out of the config file.
      api_key: "%env(ABUSEIPDB_API_KEY)%"
      # Abuse confidence (0-100) at or above which the plugin matches.
      threshold: 75
      # How long a verdict is reused before asking again (seconds).
      cache_ttl: 86400
      # How long a *failed* lookup is remembered (seconds). See below.
      error_cache_ttl: 300
      # Seconds to wait on the API before giving up and allowing the request.
      timeout: 2.0
      # How far back AbuseIPDB should consider reports.
      max_age_in_days: 30
      # Where verdicts are cached. Defaults to the system temp directory,
      # or KANOPI_FIREWALL_CACHE_DIR when that constant is defined.
      # cache_dir: /var/cache/firewall
      # HTTP status returned for blocked requests
      block_status: 403
      # How long the firewall remembers the offending IP (seconds)
      block_duration: 3600
```

The `api_key` uses an `%env()%` token so the key never lands in a config file — see [Environment Variables in YAML](../configuration/environment-variables.md). Note that `${ABUSEIPDB_API_KEY}` is *not* a supported form and resolves to nothing.

## Choosing a threshold

AbuseIPDB's confidence score is not a count of reports — it is a weighting of how many distinct reporters, how recently, and how reputable. 75 is the point AbuseIPDB's own guidance treats as strong enough to act on, and it is the default here.

| Threshold | Effect |
|---|---|
| `100` | Only addresses AbuseIPDB is certain about. Very few false positives, catches less. |
| `75` | The default. Corroborated reports from multiple reporters. |
| `50` | More aggressive; starts catching addresses with a thinner report history. |
| `25` and below | Not recommended. At this level the score largely reflects a handful of reports and will turn away real users on recycled residential IPs. |

Addresses AbuseIPDB marks as whitelisted — search-engine crawlers and similar known-good infrastructure — never match, whatever their score.

## It fails open, deliberately

A lookup that times out, is refused, or runs into a spent quota reports **no match**, logs at `warning` level, and lets evaluation continue to the next plugin. Nothing here blocks a request it could not get an answer for.

That is a deliberate trade. Reputation is corroborating evidence, not the last line of defence, and a third-party outage should not become an outage on your site.

!!! warning "This plugin is not a blocklist"

    Because it fails open, an address is only turned away when AbuseIPDB is reachable *and* answers. If you need an address blocked regardless, put it in the [IP Address plugin](ip-address.md) — that is what a local blocklist is for.

## Quota and caching

The free tier allows **1,000 checks per day**, which a modest site would exhaust before lunch if every request meant an API call. Two things keep it inside that budget:

- **Verdicts are cached per address** for `cache_ttl`, 24 hours by default. Cost is roughly one call per unique visitor per day; repeat visitors and crawlers are free. Clean results are cached too — that is most of the saving.
- **Private and reserved ranges are never looked up.** A local or intranet deployment spends no quota at all, and `127.0.0.1` in development costs nothing.

Failures are cached as well, for the much shorter `error_cache_ttl` (5 minutes). Without that, a provider outage would make every single request wait out the full `timeout` before failing open — availability preserved on paper while the site crawls. Raise `error_cache_ttl` to be more patient during an outage, lower it to notice recovery sooner.

If a site is large enough that unique visitors alone exceed the quota, put the plugin behind a cheaper filter so it only ever sees traffic that got past the static rules — see [Plugin Execution Order](index.md#plugin-execution-order).

## What gets logged

A match logs at `info` level with `ip`, `abuse_confidence_score`, `threshold`, `total_reports`, and `country_code`.

A failed lookup logs at `warning` with `error`, `http_status`, and a note that the request was allowed through. Distinct causes are named rather than collapsed into one message — a rejected API key, an exhausted quota, and an unreachable endpoint need different responses from whoever reads the log.

Skips (no API key, a non-routable address, a score under the threshold, a whitelisted address, a still-cached recent failure) log at `debug`.

Cache entries are named by SHA-1 of the address rather than the address itself, so client IPs are not readable from a directory listing.
