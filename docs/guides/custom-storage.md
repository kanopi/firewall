# Custom Storage Backends

## Custom Storage Backends

`storage.type` accepts **any** fully-qualified class name that implements `Kanopi\Firewall\Storage\StorageInterface`, so you can persist blocks anywhere — DynamoDB, Memcached, a platform-specific KV store, your app's ORM. Extend `AbstractStorageBase` and you only have to implement the persistence methods; the base class already provides `getKey()`, `isBlocked()`, and `getStorageData()` (request serialization).

```php
<?php

namespace App\Firewall;

use Kanopi\Firewall\Storage\AbstractStorageBase;

class MemcachedStorage extends AbstractStorageBase
{
    private \Memcached $client;

    public function __construct(array $config = [])
    {
        parent::__construct($config);
        $this->client = new \Memcached();
        $this->client->addServer($config['host'] ?? 'localhost', $config['port'] ?? 11211);
    }

    public function set(string $key, array $value, int $expire = 0): bool
    {
        return $this->client->set($key, $value, $expire);
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $value = $this->client->get($key);

        return $value === false ? $default : $value;
    }

    public function exists(string $key): bool
    {
        return $this->client->get($key) !== false;
    }

    public function delete(string $key): bool
    {
        return $this->client->delete($key);
    }

    public function reset(): bool
    {
        return $this->client->flush();
    }

    public function expire(): bool
    {
        // Memcached expires items itself — nothing to sweep.
        return true;
    }

    public function addToExpire(string $key, int $amount): bool
    {
        return $this->client->touch($key, time() + $amount);
    }

    public function recordOffense(string $key): bool
    {
        $offenses = $this->client->get($key . ':offenses') ?: [];
        $offenses[] = time();

        return $this->client->set($key . ':offenses', $offenses);
    }

    public function countOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX): int
    {
        $offenses = $this->client->get($key . ':offenses') ?: [];

        return count(array_filter($offenses, fn (int $t): bool => $t >= $start && $t <= $end));
    }
}
```

```yaml
storage:
  type: "App\\Firewall\\MemcachedStorage"
  config:
    host: cache.internal
    port: 11211
```

**Contract summary** (see `src/Storage/StorageInterface.php` for full PHPDoc):

| Method | Responsibility |
|---|---|
| `set()` / `get()` / `exists()` / `delete()` | Store, read, test, and remove one block record. `$expire` is an absolute unix timestamp; `0` means never. |
| `reset()` | Drop everything. Used by tests and administrative resets. |
| `expire()` | Sweep records past their expiry. Return `true` for backends that expire on their own. |
| `addToExpire()` | Extend an existing block by `$amount` seconds. |
| `recordOffense()` / `countOffenses()` | Offense history — this is what [Multiple Offenses Defense](../configuration/global.md#multiple-offenses-defense) escalation reads. A backend that no-ops these cannot escalate bans. |
| `getKey()` | Derive the storage key from the request. `AbstractStorageBase` uses the client IP. |
| `isBlocked()` | Return the block record or `false`. Provided by `AbstractStorageBase`. |
| `getStorageData()` | Build the record written on a block (serialized request + plugin). Provided by `AbstractStorageBase`. |

If `storage.type` is missing, is not loadable, or does not implement `StorageInterface`, the factory falls back to `InMemoryStorage` — which means **blocks will not persist between requests**. It logs `Storage type defaulted to InMemoryStorage` at `info` level with a `reason` of `not_string`, `class_not_found`, or `invalid_interface`. Check for that message first when a custom backend appears to do nothing.

## Custom Rate Limit Storage

`metadata.storage.type` on the Rate Limit plugin works the same way for `Kanopi\Firewall\RateLimitStorage\RateLimitStorageInterface`. The contract is only two methods, and extending `AbstractRateLimitStorage` gives you `$this->config` plus the logging trait:

```php
<?php

namespace App\Firewall;

use Kanopi\Firewall\RateLimitStorage\AbstractRateLimitStorage;

class DynamoRateLimitStorage extends AbstractRateLimitStorage
{
    public function recordRequest(string $key, int $timestamp): void
    {
        // Append $timestamp to the list held for $key.
    }

    public function countRequests(string $key, int $start, int $end): int
    {
        // Count timestamps for $key within the inclusive window.
        return 0;
    }
}
```

An unresolvable rate limit storage type falls back to `InMemoryRateLimitStorage`, so counters reset every request and limits effectively never fire. Look for `Rate limit storage type defaulted to InMemoryRateLimitStorage` at `info` level, which carries the same `reason` field.

This factory also accepts an **already-instantiated** `RateLimitStorageInterface` object and uses it as-is, which is how you inject a backend built by your framework's container. Pass it through [Dynamic Configuration Overrides](../configuration/overrides.md), since YAML cannot carry an object:

```php
Firewall::create([__DIR__ . '/firewall.yml'], [
    '[plugins][0][metadata][storage][type]' => $myRateLimitStorage,
]);
```

## Optional: Searching and Un-blocking

`AbstractStorageBase` gives your backend the firewall's hot path. If it can also enumerate its own keys, implement `QueryableStorageInterface` so operators can answer "who is blocked?" and lift a block across a range:

```php
use Kanopi\Firewall\Storage\AbstractStorageBase;
use Kanopi\Firewall\Storage\QueryableStorageInterface;
use Kanopi\Firewall\Traits\AddressMatchTrait;

class MyStorage extends AbstractStorageBase implements QueryableStorageInterface
{
    // AddressMatchTrait supplies addressMatches(), isValidPattern() and
    // validPatterns(), so every backend agrees on what `203.0.113.0/24`
    // means. A range that matched here but not elsewhere would make an
    // un-block silently partial.
    use AddressMatchTrait;

    public function find(string $pattern): array { /* … */ }

    public function deleteMatching(array $patterns): int { /* … */ }
}
```

**This is deliberately optional.** The Memcached example above cannot reliably list keys, and a backend that cannot enumerate should simply not implement the interface rather than return an empty set that reads as "nothing is blocked". Callers are expected to check with `instanceof` — see [Searching and Un-blocking](../configuration/storage.md#searching-and-un-blocking).

If you do implement it, two behaviours are worth matching so operators get consistent results across backends: `find()` should exclude records whose expiry has lapsed, and `deleteMatching()` should clear the address's offense history alongside the block.
