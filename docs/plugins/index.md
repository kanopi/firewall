# Plugin Architecture

Plugins are the core components that evaluate incoming requests. They are configured as an ordered list under the top-level `plugins:` key. Each entry declares one plugin instance and its `response` mode — either `allow` (let the request through), `block` (reject the request), or `challenge` (require the visitor to solve an interstitial before continuing).

## Common Plugin Configuration

All plugin entries share the same shape:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\PluginName"   # Fully qualified class name
    response: block          # 'allow', 'block', or 'challenge'
    weight: 0                # Execution order within its response group (lower runs first)
    enable: true             # Whether the plugin entry is active
    metadata: {}             # Plugin-specific configuration (DB readers, storage, etc.)
    config: []               # Rules or conditions for the plugin
```

The same class can appear multiple times in the list — each entry becomes its own plugin instance, so you can split rules across instances with different weights or response modes.

**YAML Syntax Note**: The `plugin:` value must be quoted with double backslashes:
- ✅ Correct: `plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"`
- ❌ Wrong: `plugin: Kanopi\Firewall\Plugins\IpAddress` (missing quotes and single backslash)
- ❌ Wrong: `plugin: \Kanopi\Firewall\Plugins\IpAddress` (leading backslash)

This also applies to all `type:` declarations (storage backends, rate limit storage).

## Plugin Execution Order

The firewall evaluates `response: allow` entries first (sorted by `weight`, lower runs first). If any allow plugin matches, the request is permitted immediately and no other plugins run. Otherwise:

1. `response: challenge` entries run next. If one matches and the visitor does **not** already hold a valid pass token, an interstitial is served and the request is paused until the challenge is solved.
2. `response: block` entries run last and the first match rejects the request.

A valid pass token (set by a previously solved challenge) short-circuits the challenge bucket but does **not** suppress block plugins. See [Challenge Response Type](challenges.md) below.

A POST to `challenge.path` (the challenge submission endpoint) skips all three buckets — otherwise an unrelated rule matching the magic path would trap a legitimate visitor in a challenge loop with no way out. The durable storage block list still applies: an IP that already earned a block is rejected before the solution is verified, so it cannot solve its way back out.

Suggested weight ranges:

- **-200 to -100**: Early filters (IP allow-lists, trusted networks)
- **-99 to -1**: Security checks (geo-blocking, ASN filtering)
- **0**: Default (URL rules, user agent checks)
- **1 to 100**: Post-evaluation (rate limiting, logging)

**Example: Layered Security**

```yaml
plugins:
  # Run first - allow trusted office IPs
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -200
    enable: true
    config:
      - 192.168.1.0/24

  # Run early - geographic blocking
  - plugin: "Kanopi\\Firewall\\Plugins\\GeoLocation"
    response: block
    weight: -100
    enable: true
    config:
      - "country:CN"

  # Run after geo - vulnerability scoring
  - plugin: "Kanopi\\Firewall\\Plugins\\VulnerabilityScore"
    response: block
    weight: -50
    enable: true
    config:
      # ... scoring config ...

  # Run last - rate limiting
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 100
    enable: true
    metadata:
      # ... rate limit config ...
```

## Loading Rules From Elsewhere

Rules can come from a file or URL instead of the configuration itself, in whatever format
that list is published in — newline-delimited text, JSON, NDJSON, YAML, CSV, or TSV:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: block
    enable: true
    metadata:
      sources:
        - name: cloud-ec2-us
          upstream: https://example.org/v1/ranges.json
          format: json
          select: "prefixes.*"
          where:
            - "service:EC2"
          template: "{value[ip_prefix]}"
          validate: cidr
    config:
      - 203.0.113.7        # inline rules are appended after every source
```

Sources declare their own format, which part of the document to take, how to filter it,
how to shape it, and what should happen when they cannot be read. See
[Rule Sources](../configuration/sources.md) for the full reference.

### `metadata.config` (deprecated for rule lists)

Plugins can also load rules by listing config files under `metadata.config`:

```yaml
metadata:
  config:
    - vulnerability-score-rules.yml
    - https://cdn.example.com/firewall/vuln-patterns.yml
```

Files are merged in order and inline `config` is applied last. This still works, but for
**rule lists** `metadata.sources` supersedes it and using it for one logs a deprecation
notice. It remains the mechanism for merging **nested configuration documents** — the
`scoring` and `risk_levels` trees `VulnerabilityScore` loads — which sources deliberately
do not do.
