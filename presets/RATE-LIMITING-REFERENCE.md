# Rate Limiting Quick Reference

This document provides a quick reference for all rate limits defined in the `rate-limiting.yml` preset.

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
- Manual cleanup needed

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
2. Optimize database queries (add indexes)
3. Use connection pooling for database
4. Consider caching layer

### Rate limits not resetting

1. Check expiration time settings
2. Verify Redis/Database TTL working
3. For file storage, manually clean old entries
4. Check system time is correct

## Best Practices

1. **Start Conservative**: Begin with stricter limits, then relax if needed
2. **Monitor First**: Run in log-only mode initially, then enable blocking
3. **Bypass Trusted IPs**: Whitelist monitoring services, internal IPs
4. **Different Tiers**: Use different limits for authenticated/premium users
5. **Progressive Limits**: Start lenient, tighten after detecting abuse
6. **Clean Up**: Regularly clean old rate limit data (especially file storage)
7. **Test Thoroughly**: Test rate limits in staging before production
8. **Document Changes**: Keep track of customizations for troubleshooting

## Performance Benchmarks

Approximate overhead per request:

- **Redis**: < 1ms
- **Database**: 2-5ms
- **File**: 5-20ms
- **Cache**: 1-3ms (varies by implementation)

For high-traffic sites (>1000 req/sec), Redis is strongly recommended.

## Legacy format (deprecated)

Earlier releases configured plugins via top-level `bypass:` and `block:` sections keyed by class name. That format is still accepted but is auto-normalized at load time by `Kanopi\Firewall\Utility\PluginConfigNormalizer` into the canonical `plugins:` array, and **it will be removed in a future major version**. New configs should use the `plugins:` array.

Mini side-by-side for the RateLimit plugin:

Legacy (deprecated):

```yaml
block:
  Kanopi\Firewall\Plugins\RateLimit:
    priority: 0
    enable: true
    config:
      - path: /login
        rate: 5
        sample: 300
```

Canonical (new):

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 0
    enable: true
    config:
      - path: /login
        rate: 5
        sample: 300
```

Mapping: `bypass:` → `response: allow`, `block:` → `response: block`, `priority:` → `weight:`, and the class-keyed map becomes a flat list of entries with `plugin:` set to the (double-quoted, backslash-escaped) class name.
