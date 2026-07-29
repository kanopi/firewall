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

## Loading External Plugin Configuration

Plugins can load rules from external files (local or remote) using the `metadata.config` option. This is useful for managing large rule sets separately:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\VulnerabilityScore"
    response: block
    weight: -50
    enable: true
    metadata:
      # Load scoring rules from external file(s)
      config:
        - vulnerability-score-rules.yml
        # Can also load from remote URLs
        - https://cdn.example.com/firewall/vuln-patterns.yml
    # Inline config is merged with loaded files
    config:
      risk_levels:
        critical:
          threshold: 100
          block: true
```

The external files use the same structure as the inline `config` section. Multiple files can be specified and will be merged in order. Both local file paths (relative or absolute) and remote URLs are supported.
