# Add a Rule Source

A rule does not have to have its list written into your configuration. `metadata.sources`
points it at a list that lives somewhere else — a file on disk, a URL, a feed someone else
publishes — and turns whatever shape it arrives in into the rules the plugin expects.

This page is four worked examples. For every option there is, see
[Rule Sources](../configuration/sources.md).

## A file of addresses

The simplest thing that works. One address or CIDR per line, `#` comments ignored:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: block
    enable: true
    metadata:
      sources:
        - name: tor-exits
          upstream: "{config_dir}/lists/tor-exits.txt"
          validate: cidr
    config:
      - 203.0.113.7      # local additions still land last
```

`validate: cidr` is worth the one line: it rejects entries that are not addresses, so a
list that arrives as an HTML error page cannot quietly become a rule.

## A remote list, refreshed on its own schedule

Swap the path for a URL and give it a `ttl`:

```yaml
        - name: tor-exits
          upstream: https://example.org/v1/tor-exits.txt
          ttl: 21600          # six hours
          validate: cidr
```

!!! warning "Do this next, not later"

    A cold or expired cache means a *visitor* pays for the fetch. Refresh out of band and
    take the request path offline — see
    [Sync Rule Sources](syncing-sources.md), which is a five-line deploy step.

## A JSON document you did not design

Cloud providers publish ranges as structured documents with everything in one file. Narrow
it rather than consuming all of it:

```yaml
- plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
  response: challenge
  enable: true
  metadata:
    sources:
      - name: cloud-ec2-us
        upstream: https://example.org/v1/ranges.json
        format: json
        select: "{prefixes,ipv6_prefixes}.*"
        where:
          - "service:EC2"
          - "region@starts_with:us-"
        template: "{value[ip_prefix|ipv6_prefix]}"
        validate: cidr
        max_delta: 0.25
        ttl: 21600
```

`max_delta: 0.25` refuses a refresh that changes more than a quarter of the list. A feed
that breaks upstream usually breaks *large*, and that is the shape of it.

The same three stages work on CSV:

```yaml
- plugin: "Kanopi\\Firewall\\Plugins\\Asn"
  response: challenge
  enable: true
  metadata:
    reader:
      type: reader
      db: /usr/local/share/GeoIP/GeoLite2-ASN.mmdb
    sources:
      - name: hosting-asns
        upstream: "{config_dir}/lists/hosting-asns.csv"
        format: csv
        where:
          - "category:hosting"
        template: "asn:{value[asn]}"
```

## Several lists into one rule

Sources contribute in declaration order, and inline `config:` is appended after all of
them — so a deployment can always add an entry without editing a shared list:

```yaml
- plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
  response: allow
  weight: -200
  enable: true
  metadata:
    sources:
      - "{config_dir}/lists/circleci.txt"
      - "{config_dir}/lists/uptimerobot.txt"
      - "{config_dir}/lists/github-actions.txt"
  config:
    - 127.0.0.1
    - 10.0.0.0/8
```

## One list, three different answers

A source carries data, not policy. The same list can allow, challenge or block depending on
what the deployment wants from it — so you rarely need three lists:

```yaml
plugins:
  # Trusted automation — straight through, nothing else runs
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -200
    enable: true
    metadata:
      sources:
        - name: uptimerobot
          upstream: "{config_dir}/lists/uptimerobot.txt"
          validate: cidr
          required: true

  # Bulk cloud egress — plausible, but prove it
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: challenge
    weight: 0
    enable: true
    metadata:
      sources:
        - name: cloud-egress
          upstream: "{config_dir}/lists/cloud-egress.txt"
          validate: cidr

  # Known bad — gone
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: block
    weight: 10
    enable: true
    metadata:
      sources:
        - name: tor-exits
          upstream: "{config_dir}/lists/tor-exits.txt"
          validate: cidr
```

## Then what

| | |
|---|---|
| Keep fetches off the request path | [Sync Rule Sources](syncing-sources.md) |
| A private feed needing a token | [Authentication](../configuration/sources.md#authentication) |
| Every option, format and guardrail | [Rule Sources](../configuration/sources.md) |
| Check what a source resolved to | `firewall-sources config.yml --dry-run` |
