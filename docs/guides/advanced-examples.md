# Advanced Examples

## Multi-layered Security Configuration

```yaml
# High-performance storage
storage:
  type: "Kanopi\\Firewall\\Storage\\DatabaseStorage"
  config:
    storage_table: firewall_blocked
    connection:
      dsn: "mysql://firewall:secure@localhost/security"

plugins:
  # =====================================================================
  # Trusted sources (response: allow)
  # =====================================================================
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -200
    enable: true
    config:
      - 203.0.113.0/24  # Office network
      - 198.51.100.50   # VPN endpoint

  # =====================================================================
  # Geographic restrictions
  # =====================================================================
  - plugin: "Kanopi\\Firewall\\Plugins\\GeoLocation"
    response: block
    weight: -100
    enable: true
    metadata:
      reader:
        type: reader
        db: /usr/share/GeoIP/GeoLite2-City.mmdb
    config:
      # Block high-risk countries
      - type: OR
        rules:
          - "country@in:CN,RU,KP,IR"
          - "continent:AF"

  # =====================================================================
  # Suspicious user agents
  # =====================================================================
  - plugin: "Kanopi\\Firewall\\Plugins\\UserAgent"
    response: block
    weight: -50
    enable: true
    config:
      # Block all bots except Google and Bing
      - type: AND
        rules:
          - "bot:true"
          - "!client.name@in:Googlebot,Bingbot"

      # Block outdated browsers
      - type: OR
        rules:
          - variable: client.name
            operator: equals
            value: "Internet Explorer"
          - type: AND
            rules:
              - "client.name:Chrome"
              - "client.version < 80"

  # =====================================================================
  # Vulnerability scoring for comprehensive threat assessment
  # =====================================================================
  - plugin: "Kanopi\\Firewall\\Plugins\\VulnerabilityScore"
    response: block
    weight: -25
    enable: true
    metadata:
      country_reader:
        type: reader
        db: /usr/share/GeoIP/GeoLite2-Country.mmdb
      asn_reader:
        type: reader
        db: /usr/share/GeoIP/GeoLite2-ASN.mmdb
    config:
      scoring:
        methods:
          DELETE: 30
          PUT: 20
          POST: 10
        countries:
          CN: 25
          RU: 25
          KP: 50
        patterns:
          - pattern: "/(union.*select|drop.*table)/i"
            score: 50
            type: regex
            locations: ["uri", "query_string", "body"]
          - pattern: "/<script|javascript:/i"
            score: 40
            type: regex
            locations: ["uri", "query_string", "body"]
      risk_levels:
        high:
          threshold: 50
          block: true
          status_code: 403
          expiration_time: 7200

  # =====================================================================
  # URL-based protection
  # =====================================================================
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    weight: 0
    enable: true
    config:
      # Protect admin areas
      - type: AND
        rules:
          - "path@starts_with:/admin"
          - "!header.authorization@exists"

      # Block vulnerability scanners
      - 'path@regex:/(\.git|\.env|\.htaccess|wp-config\.php|phpmyadmin)/i'

      # Block SQL injection attempts
      - "query@regex:/(union.*select|select.*from|insert.*into|drop.*table)/i"

  # =====================================================================
  # Aggressive rate limiting
  # =====================================================================
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 100
    enable: true
    metadata:
      default_rate: 120
      default_sample: 60
      storage:
        type: "Kanopi\\Firewall\\RateLimitStorage\\RedisRateLimitStorage"
        config:
          redis:
            host: redis.internal
            port: 6379
            auth: ["default", "redis_password"]
    config:
      # API rate limits by endpoint
      - path: "/api/v1/auth/*"
        rate: 5
        sample: 300

      - path: "/api/v1/public/*"
        rate: 100
        sample: 60

      - path: "/api/v1/private/*"
        rate: 30
        sample: 60

# Comprehensive logging
logger:
  # General log file
  - class: Monolog\Handler\RotatingFileHandler
    args:
      - /var/log/firewall/firewall.log
      - 7  # Keep 7 days
      - Monolog\Level::Info
    formatter:
      class: Monolog\Formatter\JsonFormatter
  
  # Security alerts
  - class: Monolog\Handler\StreamHandler
    args:
      - /var/log/firewall/security-alerts.log
      - Monolog\Level::Warning
    formatter:
      class: Monolog\Formatter\LineFormatter
      args:
        - "[%datetime%] %level_name%: %message% %context%\n"
```
