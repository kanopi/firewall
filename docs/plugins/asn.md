# ASN Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\Asn`

Evaluates requests based on Autonomous System Numbers (ASN) using MaxMind's GeoIP2 ASN database.

## Configuration Example

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Asn"
    response: block
    weight: 0
    enable: true
    metadata:
      reader:
        type: reader
        db: /path/to/GeoLite2-ASN.mmdb
    config:
      # Block specific ASN numbers
      - "asn:13335"  # Cloudflare
      - "asn:15169"  # Google

      # Block by organization name
      - "asn_org:CLOUDFLARENET"
      - "asn_org@contains:AMAZON"
      - "asn_org@starts_with:DIGITAL"
```

## Available Variables

- `asn` - Autonomous System Number
- `asn_org` - Organization name associated with the ASN

## Matching a number

`asn` compares as a number for `equals` (`asn:16509`), `not_equals` and `in`, and the
`AS` prefix is optional: `asn:16509`, `asn:AS16509` and `asn@in:AS13335,AS16509` all match
a client in AS16509. That applies to values from a [rule source](../configuration/sources.md)
too, since `{value}` is substituted as text.

`contains`, `starts_with` and the other text operators compare the number as text, so
`asn@contains:1650` also matches 16509. Use `equals` or `in` for a network.

!!! note "Before 2.35.0"
    Every `asn` equality rule silently failed to match, because the lookup returns an
    integer and rule values are text. `asn@not_equals:` therefore matched every visitor,
    the named network included. Check any `not_equals` rule when you upgrade: it now
    excludes the network it names.
