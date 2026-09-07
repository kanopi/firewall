# Rate Limiting Quick Reference

A quick reference for every rate limit defined in the shipped [`rate-limiting.yml`](https://github.com/kanopi/firewall/blob/2.x/presets/rate-limiting.yml) preset. See [Using Presets](../presets/usage.md) for how to include and override it.

## Default Limits

- **General Traffic**: 60 requests per minute
- **Status Code**: 429 (Too Many Requests)
- **Expiration**: 300 seconds (5 minutes)

## Rate Limit Rules by Category

### Authentication & Security

| Path | Limit | Window | Purpose |
|------|-------|--------|---------|
| `/wp-login.php` | 5 | 5 min | WordPress login protection |
| `/wp-login.php?action=lostpassword` | 3 | 10 min | Password reset protection |
| `/login` | 10 | 5 min | General login protection |
| `/signin` | 10 | 5 min | Alternative login endpoint |
| `/auth/login` | 10 | 5 min | Auth API login |
| `/password/reset` | 5 | 10 min | Password reset |
| `/forgot-password` | 5 | 10 min | Password recovery |
| `/register` | 10 | 1 hour | Registration limits |
| `/signup` | 10 | 1 hour | Signup limits |

### API Endpoints

| Path | Limit | Window | Purpose |
|------|-------|--------|---------|
| `/api/*` | 100 | 1 min | General API traffic |
| `/api/auth/*` | 20 | 1 min | API authentication |
| `/api/v1/post` | 30 | 1 min | API write operations |
| `/api/v1/put` | 30 | 1 min | API updates |
| `/api/v1/delete` | 20 | 1 min | API deletions |
| `/graphql` | 50 | 1 min | GraphQL queries |
| `/wp-json/*` | 200 | 1 min | WordPress REST API |

### WordPress Specific

| Path | Limit | Window | Purpose |
|------|-------|--------|---------|
| `/xmlrpc.php` | 10 | 1 min | Prevent XML-RPC abuse |
| `/wp-admin/*` | 120 | 1 min | Admin panel access |
| `/wp-admin/admin-ajax.php` | 200 | 1 min | AJAX operations |
| `/wp-cron.php` | 5 | 1 min | Cron job protection |
| `/wp-comments-post.php` | 10 | 10 min | Comment spam prevention |

### Forms & User Input

| Path | Limit | Window | Purpose |
|------|-------|--------|---------|
| `/search` | 30 | 1 min | Search rate limiting |
| `/?s=*` | 30 | 1 min | WordPress search |
| `/contact` | 5 | 10 min | Contact form spam prevention |
| `/contact-us` | 5 | 10 min | Contact forms |

### Admin & Management

| Path | Limit | Window | Purpose |
|------|-------|--------|---------|
| `/admin/*` | 180 | 1 min | Admin areas |
| `/install.php` | 3 | 1 hour | Installation protection |
| `/setup` | 3 | 1 hour | Setup protection |

### File Operations

| Path | Limit | Window | Purpose |
|------|-------|--------|---------|
| `/upload` | 20 | 5 min | Upload limits |
| `/wp-admin/async-upload.php` | 20 | 5 min | WordPress uploads |

### Static Assets (Relaxed)

| Path | Limit | Window | Purpose |
|------|-------|--------|---------|
| `*.css` | 500 | 1 min | Stylesheet requests |
| `*.js` | 500 | 1 min | JavaScript requests |
| `*.jpg, *.png, *.gif, etc.` | 500 | 1 min | Image requests |

### Webhooks

| Path | Limit | Window | Purpose |
|------|-------|--------|---------|
| `/webhook/*` | 100 | 1 min | General webhooks |
| `/api/webhook/*` | 100 | 1 min | API webhooks |
| `/webhook/stripe` | 200 | 1 min | Payment webhooks |
| `/webhook/paypal` | 200 | 1 min | Payment webhooks |

### Monitoring & Health

| Path | Limit | Window | Purpose |
|------|-------|--------|---------|
| `/health` | 1000 | 1 min | Health checks |
| `/healthz` | 1000 | 1 min | Kubernetes-style health |
| `/ping` | 1000 | 1 min | Ping endpoints |
| `/status` | 1000 | 1 min | Status checks |

### Feeds & Sitemaps

| Path | Limit | Window | Purpose |
|------|-------|--------|---------|
| `/feed` | 10 | 1 min | RSS feeds |
| `/rss` | 10 | 1 min | RSS feeds |
| `*.xml` | 10 | 1 min | XML feeds |
| `/sitemap.xml` | 10 | 1 min | Sitemap access |
| `/sitemap_index.xml` | 10 | 1 min | Sitemap index |

### Special Paths

| Path | Limit | Window | Purpose |
|------|-------|--------|---------|
| `/robots.txt` | 30 | 1 min | Robots file |
| `/` | 120 | 1 min | Homepage |

## Storage Backends

All five backends keep only the current window. Each recorded request is a timestamp, and
a rate limit is a rolling window, so once a timestamp falls out of the widest window its
key is counted over it can never affect a verdict again — the plugin drops it on the next
allowed request for that key.

That was not always true. Before it, nothing removed a record: the Redis and cache
backends were bounded only by their `ttl` (how long a key *survives*, not how large it
gets), and the file and database backends were not bounded at all. A long-running site
accumulated every request it had ever rate limited. If you have been running one of those
two, see [Reclaiming space](#reclaiming-space) below.

### Redis (Recommended)

**Pros:**
- Extremely fast (in-memory)
- Distributed/clustered support
- Automatic TTL/expiration
- Horizontal scaling
- Battle-tested for rate limiting

**Cons:**
- External dependency
- Requires Redis server

**Use when:**
- Production environment
- Load-balanced/distributed system
- High traffic (>1000 req/min)
- Need sub-millisecond performance

### Database (MySQL/PostgreSQL)

**Pros:**
- Uses existing infrastructure
- Persistent across restarts
- SQL query capabilities
- Familiar tooling

**Cons:**
- Slower than Redis
- More disk I/O
- May impact database performance

**Use when:**
- Already using database
- Don't want external dependencies
- Moderate traffic (<500 req/min)
- Need audit trail

### File Storage

**Pros:**
- No external dependencies
- Simple setup
- Works immediately

**Cons:**
- Single server only
- Slowest option
- File locking overhead

**Use when:**
- Development/testing
- Single server deployment
- Low traffic (<100 req/min)
- Simple infrastructure

### PSR-6 Cache

**Pros:**
- Integrates with existing cache
- Framework-agnostic
- Flexible backend

**Cons:**
- Depends on cache implementation
- Performance varies

**Use when:**
- Using Symfony/Laravel with cache
- Want to use existing cache layer
- Framework integration important

## Sharing a database connection

The database backend needs the same connection details as `storage.config.connection` when
both point at one database. Declare it once and reference it, rather than keeping two
copies in step:

```yaml
storage:
  type: "Kanopi\\Firewall\\Storage\\DatabaseStorage"
  config:
    connection:
      driver: pdo_mysql
      host: "%env(DB_HOST)%"
      dbname: "%env(DB_NAME)%"
      user: "%env(DB_USER)%"
      password: "%env(DB_PASSWORD)%"

plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    metadata:
      storage:
        type: "Kanopi\\Firewall\\RateLimitStorage\\DatabaseRateLimitStorage"
        config:
          connection: "%config(storage.config.connection)%"
```

Within a single file a YAML anchor does the same thing with no library involvement and is
the better choice; `%config()%` is what works once the two blocks live in different
[included files](../configuration/loading-and-includes.md). See
[`%config(...)%`](../configuration/environment-variables.md#config-reusing-a-value-from-elsewhere-in-the-config).

## Reclaiming space

Pruning happens per key, on the next allowed request for that key. So records belonging to
keys that never come back — a client that has not returned, a path nobody requests any more
— are never visited again and stay where they are. On a site that ran without pruning, that
is most of what is stored.

Nothing needs to happen for rate limiting to keep working correctly; this is disk space,
not correctness. To reclaim it, delete anything older than the widest `sample` you have
configured.

**Database.** With a widest window of, say, 3600 seconds:

```sql
DELETE FROM firewall_rate_limit_storage WHERE timestamp < UNIX_TIMESTAMP() - 3600;
```

The table is also created with an index on `(rule, timestamp)`, which is the shape both
queries against it use. **An existing table does not gain it** — the schema is only created
when the table is absent — and without it every count is a full scan. Add it once:

```sql
CREATE INDEX firewall_rate_limit_storage_rule_window_idx
  ON firewall_rate_limit_storage (rule, timestamp);
```

**File.** The store is a single JSON file of `key => [timestamps]`. Deleting it is safe: the
worst case is that clients mid-window get their allowance reset, and the file is rebuilt on
the next request.

```bash
rm /path/to/ratelimit_data.json
```

**Redis and PSR-6 cache.** Nothing to do. Their `ttl` already drops whole keys, so anything
left over from before clears itself within one TTL.

## Custom storage backends

`plugins[].metadata.storage.type` accepts any class implementing
`RateLimitStorageInterface`, and that interface is unchanged — a backend written before
pruning existed keeps working exactly as it did.

To have yours pruned too, also implement `PrunableRateLimitStorageInterface`:

```php
use Kanopi\Firewall\RateLimitStorage\PrunableRateLimitStorageInterface;
use Kanopi\Firewall\RateLimitStorage\RateLimitStorageInterface;

class MyRateLimitStorage implements RateLimitStorageInterface, PrunableRateLimitStorageInterface
{
    // ...

    public function forget(string $key, int $before): int
    {
        // Drop records for $key older than $before. Touch no other key.
        // A record exactly at $before must be KEPT: countRequests() treats
        // its $start as inclusive, so dropping it loses a request the
        // current window still counts.
        // Return how many were dropped. Report failures and return 0 —
        // pruning is housekeeping and must not fail a request.
    }
}
```

The plugin calls it on the allowed path only, immediately before recording. Records are
added nowhere else, so pruning there is enough to bound growth — and a key that is over its
limit stops being appended to, so it stops growing on its own.

## Common Customizations

### Stricter Login Protection

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 0
    enable: true
    config:
      - path: /login
        rate: 3      # Only 3 attempts
        sample: 600  # Per 10 minutes
```

### Higher API Limits for Premium Tier

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 0
    enable: true
    config:
      - path: /api/premium/*
        rate: 500
        sample: 60
```

### Disable Rate Limiting for Specific Path

Remove the path from config or set very high limits:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 0
    enable: true
    config:
      - path: /unlimited-endpoint
        rate: 999999
        sample: 60
```

### Custom Endpoint

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 0
    enable: true
    config:
      - path: /my-custom-api
        rate: 50
        sample: 60
```

## Troubleshooting

### Rate limit not working

1. Check storage is configured correctly
2. Verify Redis/Database is accessible
3. Check file permissions (if using file storage)
4. Enable debug logging to see rate limit checks

### Too many false positives

1. Increase rate limits for affected endpoints
2. Add an IpAddress `response: allow` plugin entry for trusted sources
3. Increase time window (sample)
4. Check if behind proxy (ensure X-Forwarded-For is trusted)

### Performance issues

1. Switch to Redis if using file/database
2. On a database table created before pruning existed, add the `(rule, timestamp)` index —
   see [Reclaiming space](#reclaiming-space). Without it every count is a full scan
3. Use connection pooling for database
4. Consider caching layer

### Rate limits not resetting

1. Check expiration time settings
2. Verify Redis/Database TTL working
3. Check system time is correct — the window is computed from it

### Storage keeps growing

Only records for keys that come back are pruned, so anything belonging to a client or path
that never returns stays put. That is disk space rather than a correctness problem, and
[Reclaiming space](#reclaiming-space) covers clearing it.

## Best Practices

1. **Start Conservative**: Begin with stricter limits, then relax if needed
2. **Monitor First**: Run in log-only mode initially, then enable blocking
3. **Bypass Trusted IPs**: Whitelist monitoring services, internal IPs
4. **Different Tiers**: Use different limits for authenticated/premium users
5. **Progressive Limits**: Start lenient, tighten after detecting abuse
6. **Index the table**: If your database table predates pruning, add the
   `(rule, timestamp)` index — the schema is only created when the table is absent
7. **Test Thoroughly**: Test rate limits in staging before production
8. **Document Changes**: Keep track of customizations for troubleshooting

## Performance Benchmarks

Approximate overhead per request:

- **Redis**: < 1ms
- **Database**: 2-5ms
- **File**: 5-20ms
- **Cache**: 1-3ms (varies by implementation)

For high-traffic sites (>1000 req/sec), Redis is strongly recommended.
