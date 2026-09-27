# Named Connections

Declare a connection once, give it a name, and hand the connection itself to anything that
needs one:

```yaml
connections:
  cache: "memcached://cache.internal:11211"
  redis: { dsn: "redis://redis.internal:6379", timeout: 3 }
  db:    { driver: pdo_mysql, host: "%env(DB_HOST)%", dbname: firewall, user: "%env(DB_USER)%", password: "%env(DB_PASSWORD)%" }

storage:
  type: "Kanopi\\Firewall\\Storage\\MemcachedStorage"
  config:
    instance: "%connection(cache)%"

logger:
  - class: "Monolog\\Handler\\RedisHandler"
    args: ["%connection(redis)%", "firewall:log"]
  - class: "Kanopi\\Firewall\\Logging\\Handler\\DatabaseHandler"
    args: [{ table: firewall_log, connection: "%connection(db)%" }]
```

## When you need this, and when you do not

[`%config(...)%`](environment-variables.md#config-reusing-a-value-from-elsewhere-in-the-config)
already lets two settings share a connection's **description**, across included files too.
That is enough for most configurations, and simpler.

`%connection(...)%` hands over the **connection itself**, which is what two things needed and
YAML could not give them:

- **A setting that takes a live client.** Monolog's `RedisHandler`, `MongoDBHandler`,
  `ElasticsearchHandler` and others take a connected client as a constructor argument, and a
  YAML value cannot be one. Before 2.33.0 these needed PHP.
- **One connection shared by several things.** A storage, a log handler and a cache pointing
  at the same server each open their own connection. Named, they open one.

## Declaring a connection

The kind is taken from the declaration:

| Declaration | Builds | Accepted where |
|---|---|---|
| `"memcached://host:port"`, or `{ dsn: ..., <options> }` | a `\Memcached` client | `instance:` on `MemcachedStorage`, a cache `adaptor:`, handler arguments |
| `"redis://host:port"` / `"rediss://..."`, or `{ dsn: ..., <options> }` | a `\Redis` client | `instance:` on `RedisStorage` and `RedisRateLimitStorage`, a cache `adaptor:`, handler arguments |
| `{ driver: pdo_mysql, host: ..., ... }`, `{ dsn: "pdo-mysql://..." }`, or `"pdo-mysql://..."` | a Doctrine DBAL connection | `connection:` on `DatabaseStorage`, `DatabaseRateLimitStorage` and `DatabaseHandler` |

Memcached and Redis DSNs use the same syntax as [cache pools](../plugins/user-agent.md#using-a-different-backend),
and the same bounded defaults: 1.5-second connect and read timeouts, and for Memcached a
server that fails is dropped for the rest of the request. Anything else in the map is passed
to Symfony's `createConnection()` as an option — `timeout`, `read_timeout`, `connect_timeout`,
`persistent_id` — over those defaults. A database declaration takes the parameters
`DatabaseStorage`'s `connection:` already accepts.

## Using one

`%connection(name)%` must be the **whole value**. A connection is an object; written inside a
longer string it would be meaningless, so `"prefix-%connection(db)%"` is refused at startup.

A cache setting can take a named Memcached or Redis connection as its `adaptor:`, so a cache
shares the client a storage already uses:

```yaml
    metadata:
      cache:
        adaptor: "%connection(cache)%"
        namespace: device-detector
```

## What happens when it goes wrong

| | |
|---|---|
| A name that is not declared | `ConfigurationException` from `Firewall::create()`, listing the names that are. `firewall-check --lint` reports it without connecting anything |
| A declaration that describes nothing — no DSN, no driver, an unknown driver | `ConfigurationException` at startup |
| A Memcached or Redis server that is down, or a missing `ext-memcached` / `ext-redis` | **Not** a startup failure. Recorded in `Firewall::getDegradedBackends()` as `named connection`, and whatever uses it degrades in its own terms, as it would with its own connection |
| A database that is down | The connection is lazy, so nothing happens until it is used — then exactly what happens with a `connection:` written out in full |

A Redis connection that cannot connect is handed over **unconnected** rather than as nothing.
Given nothing, `RedisStorage` would fall back to its own defaults — a server on `localhost` —
and could quietly talk to the wrong place.

`firewall-doctor` reports each declared connection, answering or not, with its user and
password left out.

## How far a name reaches

- **One connection per name, per firewall.** Every reference to `cache` in one configuration
  is the same client. Two firewalls in one process each build their own, so nothing is
  shared by accident.
- **Built only when referenced.** A connection declared and never used is never opened.
- **Across included files.** `connections:` merges like any other top-level key, so it can
  live in one file and be used in another.
- **Resolved where components are built, not when the configuration is loaded.** Loading a
  configuration to lint it does not open connections, and the compiled config cache keeps
  the reference as a string.

## What stays PHP

Objects your application owns — a Drupal logger channel, a framework's `cache.app` service —
are not connections this library can open. Pass those through
[runtime overrides](overrides.md), as before.
