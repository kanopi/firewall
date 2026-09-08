# Storage Configuration

Storage defines how the firewall persists blocked IP addresses across requests.

## Available Storage Classes

### 1. In-Memory Storage

Non-persistent storage that resets with each request. Useful for testing.

```yaml
storage:
  type: "Kanopi\\Firewall\\Storage\\InMemoryStorage"
```

### 2. File Storage

Persists blocked IPs to the filesystem.

```yaml
storage:
  type: "Kanopi\\Firewall\\Storage\\FileStorage"
  config:
    storage_file: /var/log/firewall/blocked_ips.data
    offense_file: /var/log/firewall/blocked_ip_offenses.data
```

### 3. Database Storage

Stores blocked IPs in a SQL database using Doctrine DBAL.

```yaml
storage:
  type: "Kanopi\\Firewall\\Storage\\DatabaseStorage"
  config:
    storage_table: firewall_blocked_ips
    offenses_table: firewall_blocked_ip_offenses
    connection:
      # Option 1: Using DSN (recommended)
      dsn: "mysql://user:password@localhost:3306/database?serverVersion=8.0"
      
      # Option 2: Individual parameters
      # dbname: 'my_database'
      # user: 'db_user'
      # password: 'db_password'
      # host: 'localhost'
      # port: 3306
      # driver: 'pdo_mysql'
```

A database the firewall cannot reach is a startup failure, not a silent one: construction throws `Kanopi\Firewall\Exception\StorageConnectionException` (a `StorageException`) carrying the driver's own message and the target it tried — `driver=pdo_mysql host=db port=3306 dbname=app`. Credentials are never included, in the message or the log, so the reason can be shown to an administrator as-is. The original driver exception is attached as `previous`.

```php
use Kanopi\Firewall\Exception\StorageConnectionException;

try {
    $firewall = Firewall::create([__DIR__ . '/firewall.yml']);
} catch (StorageConnectionException $e) {
    // "Firewall database storage could not connect (driver=pdo_mysql host=db
    //  port=3306 dbname=app): An exception occurred in the driver: ..."
    $logger->critical($e->getMessage());
}
```

The rate-limit plugin builds its storage lazily, so a `DatabaseRateLimitStorage` that cannot connect surfaces the same exception on the first request the plugin evaluates rather than at startup.

### 4. Redis Storage

Stores blocked clients in Redis, shared across every server that points at it.

Requires `ext-redis`, which is a Composer `suggest` rather than a `require` — every other
backend works without it.

```yaml
storage:
  type: "Kanopi\\Firewall\\Storage\\RedisStorage"
  config:
    redis:
      host: 127.0.0.1
      port: 6379
      prefix: "firewall:"     # namespaces every key this backend owns
      # auth: "password"
      # auth: ["username", "password"]
```

**Use this when more than one server shares a block list.** `FileStorage` cannot, and its
cost rises with the size of the list — measured at 15.66 ms per request with 2,000 blocked
clients against 7.58 ms for the database, and it gets worse *during* an attack, which is
when the block list is largest and the firewall busiest.

#### Expiry is the server's job

A block is stored with a Redis TTL rather than a stored timestamp, so a lapsed ban is
removed by Redis itself. `expire()` therefore has nothing to do.

That matters more than it sounds: on file storage the same sweep runs on every request and
is free until a batch of bans lapses together, at which point the whole cost lands on one
visitor — 185 ms at 500 expired bans before it was
[batched](https://github.com/kanopi/firewall/issues/250). Here it never happens.

#### Offenses outlive the block

Offenses are kept in their own sorted set, `{prefix}offense:{address}`, with no TTL. An
expired ban leaves its history behind on purpose: that history is exactly what
[escalating bans](global.md#multiple-offenses-defense) need to give a repeat offender a
longer ban next time.

`deleteMatching()` is the opposite case and removes both — an operator lifting a ban should
not have it escalated straight back on the client's next offence.

#### Two keyspaces, one prefix

| Key | Holds |
|---|---|
| `{prefix}block:{address}` | The block record, as JSON, with the ban's lifetime as a TTL |
| `{prefix}offense:{address}` | A sorted set of offence timestamps |

`prefix` defaults to `firewall:`. Give each site its own if several share a Redis, and note
that `reset()` only clears keys under the configured prefix — a neighbouring application's
keys are left alone.

#### One connection per server, not per backend

`RedisStorage` and
[`RedisRateLimitStorage`](../plugins/rate-limit.md) share a connection when they are pointed
at the same server, so using Redis for both the block list and rate limiting costs one
connection per request rather than two.

Sharing is decided by the resolved options, so different hosts — or different databases on
one host — still get their own. An injected `instance` always wins over the shared one.

#### A Redis it cannot reach degrades rather than fails

Unlike `DatabaseStorage`, an unreachable Redis is **not** a startup exception. The error is
logged and every read answers as though nothing were stored, so a firewall whose block list
is unreachable carries on enforcing every rule that does not depend on it.

That is a deliberate trade and worth understanding: it fails *open* for the block list
specifically. If a shared block list is load-bearing for you, watch for
`Failed to initialize Redis storage` in the log.

## Searching and Un-blocking

`StorageInterface` gives you keyed access — `get()`, `set()`, `delete()` for an address you already know. That covers the firewall's own hot path, but it leaves two operational questions unanswered: *who is currently blocked?*, and *how do I lift a block that should not have been applied?*

Storages that can answer those implement `Kanopi\Firewall\Storage\QueryableStorageInterface`, which adds two methods:

| Method | Purpose |
|---|---|
| `find(string $pattern): array` | Records matching a single address or a CIDR range, keyed by address |
| `deleteMatching(array $patterns): int` | Delete everything matching any of the given addresses / ranges; returns the count |

All three shipped storages implement it. `FileStorage` inherits the behaviour from `InMemoryStorage`.

```php
use Kanopi\Firewall\Storage\QueryableStorageInterface;
use Kanopi\Firewall\Storage\StorageFactory;

$storage = StorageFactory::create($config);

if ($storage instanceof QueryableStorageInterface) {
    // Who is blocked in this range, and why?
    foreach ($storage->find('203.0.113.0/24') as $address => $record) {
        printf(
            "%s — expires %s, %d offense(s)\n",
            $address,
            $record['expires_at'] ?? 'never',
            $record['offenses']
        );
    }

    // Lift a block that should not have been applied.
    $lifted = $storage->deleteMatching(['203.0.113.5', '198.51.100.0/24']);
}
```

### Why a separate interface

Not every backend can enumerate its own keys — Memcached, the worked example in [Custom Storage Backends](../guides/custom-storage.md), cannot list keys at all. Folding these methods into `StorageInterface` would oblige every implementation to supply something it may be unable to implement honestly, and would break existing custom storages on upgrade. Enumeration is a capability, so it is modelled as one, and callers check with `instanceof` before using it.

### Behaviour worth knowing

- **Both IPv4 and IPv6 ranges** are supported: `203.0.113.0/24`, `2001:db8::/32`.
- **A malformed pattern matches nothing**, never everything. An out-of-range prefix such as `/33` on IPv4 is treated as invalid rather than silently clamped to a single host — otherwise you would clear one record believing you had cleared a range.
- **One bad pattern does not abort the rest.** Invalid entries are skipped and logged, so a typo in one of twenty ranges still lifts the other nineteen. The return count tells you what actually happened.
- **`find()` hides expired records** so you are not shown a block that lapsed an hour ago, but **`deleteMatching()` still removes them** — otherwise an un-block would report nothing matched while the row was still on disk.
- **Offense history is cleared alongside the block.** Left behind, [`blocking_escalation`](global.md#multiple-offenses-defense) would escalate the address straight back to a longer ban on its next request, and the un-block would appear not to have worked.
