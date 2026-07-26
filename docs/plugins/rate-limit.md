# Rate Limit Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\RateLimit`

Implements rate limiting to prevent abuse and DDoS attacks.

## Configuration Example

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 100   # Run after other plugins
    enable: true
    metadata:
      # Default settings for all paths
      default_rate: 60        # Requests allowed
      default_sample: 60      # Time window in seconds
      default_expiration_time: 300  # Block duration in seconds

      # Storage backend for rate limit data
      storage:
        # Option 1: Redis (recommended for production)
        type: "Kanopi\\Firewall\\RateLimitStorage\\RedisRateLimitStorage"
        config:
          redis:
            host: localhost
            port: 6379
            # Authentication options:
            # auth: "password"
            # auth: ["password"]
            # auth: ["username", "password"]

        # Option 2: File storage
        # type: "Kanopi\\Firewall\\RateLimitStorage\\FileRateLimitStorage"
        # config:
        #   file: /var/log/firewall/ratelimit.data

        # Option 3: Database storage
        # type: "Kanopi\\Firewall\\RateLimitStorage\\DatabaseRateLimitStorage"
        # config:
        #   storage-table: firewall_ratelimit
        #   connection:
        #     dsn: "mysql://user:pass@localhost/db"

        # Option 4: PSR-6 cache pool
        # type: "Kanopi\\Firewall\\RateLimitStorage\\CacheRateLimitStorage"
        # config:
        #   # Class implementing Psr\Cache\CacheItemPoolInterface
        #   adaptor: "Symfony\\Component\\Cache\\Adapter\\FilesystemAdapter"
        #   # Constructor arguments, spread in order
        #   args: ['firewall', 0, '/var/cache/firewall']
        #   ttl: 3600

        # Option 5: In-memory (testing only)
        # type: "Kanopi\\Firewall\\RateLimitStorage\\InMemoryRateLimitStorage"

    config:
      # Strict rate limit for homepage
      - path: "/"
        rate: 10
        sample: 60

      # API endpoints with higher limits
      - path: "/api/*"
        rate: 100
        sample: 60

      # Admin area with moderate limits
      - path: "/admin/*"
        rate: 30
        sample: 60

      # Login endpoint with strict limits
      - path: "/login"
        rate: 5
        sample: 300  # 5 attempts per 5 minutes

      # Use regex for complex patterns
      - path: '/\.(php|asp|aspx)$/i'
        rate: 1
        sample: 3600  # Block direct script access
```

## Path Patterns

- Exact match: `/login`
- Wildcard: `/api/*` (matches /api/users, /api/posts/123, etc.)
- Regex: `/^\/api\/v[0-9]+\//` (matches /api/v1/, /api/v2/, etc.)
