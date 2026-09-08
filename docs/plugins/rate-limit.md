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
      # Fallback for a rule that omits its own rate or sample, and for
      # paths with no rule at all -- see "Paths with no rule of their own".
      default_rate: 60        # Requests allowed
      default_sample: 60      # Time window in seconds
      default_expiration_time: 300  # Block duration in seconds

      # Set false to limit only the paths listed under config:
      # limit_unlisted_paths: false

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

## Paths with no rule of their own

Every path is rate limited by default, not only the ones listed under `config:`. A request
matching no rule falls through to a catch-all built from `default_rate` and
`default_sample`.

That is worth stating plainly, because it has two consequences:

- Adding a rule to protect `/user/login` also brings a **site-wide cap on every other
  URL**, at whatever `default_rate` says.
- Every request to the site performs a read-modify-write of the counter store, including
  requests the operator never intended to limit.

To limit only what you listed:

```yaml
metadata:
  default_rate: 60
  default_sample: 60
  limit_unlisted_paths: false
config:
  - path: /user/login
    rate: 5
    sample: 300
```

An unlisted path is then not counted and not recorded — it never reaches the counter store
at all.

`default_rate` still applies to a **listed** rule that omits its own `rate`, which is why
this is a separate key rather than a special value for `default_rate`. A rate that meant
"switch the catch-all off" would silently unlimit those rules too.

!!! warning "`default_rate: 0` does not mean unlimited"

    The limit check is `count >= rate`, and a count is never negative, so a rate of `0` is
    satisfied by no request at all — including the first. Before v2.19.2 that refused every
    request on the site.

    Since v2.19.2 a rate below 1 is treated as unenforceable and logged at construction, so
    it no longer takes a site down. Use `limit_unlisted_paths: false` to express the intent
    properly.

## Path Patterns

- Exact match: `/login`
- Wildcard: `/api/*` (matches /api/users, /api/posts/123, etc.)
- Regex: `/^\/api\/v[0-9]+\//` (matches /api/v1/, /api/v2/, etc.)
