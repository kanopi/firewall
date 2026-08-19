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
