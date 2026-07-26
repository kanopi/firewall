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
