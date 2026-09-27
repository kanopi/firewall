# IP Address Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\IpAddress`

Evaluates requests based on IP addresses, supporting IPv4, IPv6, CIDR blocks, and IP ranges.

## Configuration Example

```yaml
plugins:
  # Allow list - trusted IPs bypass further evaluation
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -100   # Run early
    enable: true
    config:
      # Single IPv4 address
      - 192.168.1.1
      # Single IPv6 address
      - ::1
      - 2001:db8::1
      # CIDR notation
      - 10.0.0.0/8
      - 172.16.0.0/12
      # IP range (start-end)
      - 192.168.1.100-192.168.1.200

  # Block list - reject malicious IPs
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: block
    weight: -100
    enable: true
    config:
      - 192.168.1.50
      - 10.10.10.0/24
```

## A request with no client address

A request with no `REMOTE_ADDR` has no address to compare, so an `IpAddress` rule does not
match it. That is true for an `allow` rule and a `block` rule alike. PHP-FPM behind a web
server always sets the address; a request built by a long-running runtime's bridge, a queue
worker or a test may not.

Other rules can still refuse such a request, but it is **not written to the block list**.
Every address-less request would share one entry, so one client's offence would refuse all
of them. A rate limit counting by `client_ip` skips it for the same reason, while one keyed
on something else — `post.name`, a header — still counts. The firewall logs a warning once
when it sees one. Before 2.33.0 an `IpAddress` rule failed with a `TypeError` here
([#403](https://github.com/kanopi/firewall/issues/403)).

