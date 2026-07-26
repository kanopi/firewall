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
