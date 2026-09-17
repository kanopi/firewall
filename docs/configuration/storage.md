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
    # offense_file: /var/log/firewall/blocked_ips.data.offenses
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

#### Where offenses are kept

Offense counts drive [escalating bans](global.md#multiple-offenses-defense), and they live in
a sidecar beside the storage file — `blocked_ips.data.offenses` for the example above — unless
`offense_file` names somewhere else.

!!! warning "This default changed in 2.22.0"

    It used to be `storage_data_offenses.json` in the **directory** holding the storage file,
    so two stores in one directory shared a single offense history: two sites, two
    environments, or one site running two stores all escalated each other's clients. An
    address that offended twice against one and once against another reached a
    three-offense stage on both.

    On first start after upgrading, an existing shared file is **copied** to each store's own
    sidecar, so escalation stages survive rather than resetting every client to zero. The old
    file is left in place and can be deleted once every store that used it has started.

    Nothing changes for a configuration that already sets `offense_file`.

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
specifically. `Firewall::getDegradedBackends()` reports it, so a status page can say so
without scraping for `Failed to initialize Redis storage` — see
[Checking that a backend can reach its server](../reference/error-handling.md#checking-that-a-backend-can-reach-its-server).

#### Connections are given a bounded timeout

`new Redis(...)` connects during construction, and with no timeout configured `ext-redis`
falls back to PHP's `default_socket_timeout` — **60 seconds** on a stock install. A Redis
host that refuses a connection or fails to resolve answers straight away, so the bad case is
the one that silently drops packets: a firewalled port, a wrong subnet, a security group
nobody updated. That hung the request for a minute.

`connectTimeout` and `readTimeout` therefore default to **1.5 seconds**, which is far longer
than a Redis on the same network needs and far shorter than the alternative. A deployment
reaching a Redis over a slower link can say so:

```yaml
storage:
  type: "Kanopi\\Firewall\\Storage\\RedisStorage"
  config:
    redis:
      host: redis.internal
      connectTimeout: 5
      readTimeout: 5
```

## A block list shared across a fleet

Ten nodes behind a load balancer each learn about the same attacker independently. An
attacker gets ten times the budget before any single node blocks them, a ban earned on node 3
does nothing on node 7, and — the one people notice last —
[`blocking_escalation`](global.md#multiple-offenses-defense) counts one attacker as ten
first-time offenders, so the escalation that should make a second offence expensive never
fires.

Pointing every node at one Redis fixes all of that. What it costs is that an unreachable
Redis means **no block list at all**: `RedisStorage` degrades by answering "nothing is
blocked" for every address, which is the right posture for a store the firewall can live
without and the wrong one for the list whose whole job is to say otherwise.

`SharedStorage` is that arrangement with a local copy underneath it:

```yaml
storage:
  type: "Kanopi\\Firewall\\Storage\\SharedStorage"
  config:
    shared:
      type: "Kanopi\\Firewall\\Storage\\RedisStorage"
      config:
        redis:
          host: redis.internal
          port: 6379
    local:
      type: "Kanopi\\Firewall\\Storage\\FileStorage"
      config:
        storage_file: /var/lib/firewall/blocked.data
        offense_file: /var/lib/firewall/offenses.data
```

Both sides take the same `{type, config}` block as `storage:` itself, so any backend works on
either side.

| | Shared store reachable | Shared store unreachable |
|---|---|---|
| Reads | Shared, always | Local |
| Writes | Shared, **mirrored** to local | Local |

**Reads never come from the local copy while the share is up.** A ban lifted on another node
applies here on the next request — there is no propagation delay to reason about and no cache
to go stale. The mirror exists so the node is not starting from nothing the moment the share
goes away.

### What an outage costs, precisely

The node keeps enforcing every ban it had mirrored and records new ones locally, so an
attacker blocked during an outage stays blocked on the node that blocked them.

What is lost is the *sharing*: for the length of the outage the fleet is back to learning
independently, and bans written locally are **not** replayed to the share when it returns.
They expire where they were written.

That is deliberate. Replaying an outage's worth of local writes into a recovered share means
reconciling ten nodes' disagreements about the same address, and a ban enforced on one node
rather than ten is a much better failure than being wrong about who is banned across the
whole fleet.

### Escalation changes, and that is the point

!!! warning "Existing fleet installs will see bans get longer"

    `blocking_escalation` lengthens a ban by how often an address has offended. Counted per
    node, ten nodes see one attacker as ten first-timers. Counted once, the second offence is
    finally the second offence.

    Single-node installs are unaffected. If you are moving a fleet onto a shared list, expect
    the escalation thresholds you tuned against per-node counts to fire sooner, and re-read
    them before you switch.

### Checking it

`firewall-doctor` says whether the list is shared, and checks the local copy is writable —
which matters more than it looks, because the local copy is the entire reason the
arrangement exists:

```
  ✓ Block list is shared across the fleet
      Written to RedisStorage, with FileStorage kept locally so this node keeps enforcing if
      the share cannot be reached.
  ✓ Storage path writable (storage_file) [local fallback]
```

An unreachable share is reported as a degraded backend, so a status page can see it without
reading logs — see [Error Handling](../reference/error-handling.md#checking-that-a-backend-can-reach-its-server).

## What a block record keeps

When a rule blocks or records a client, the firewall writes down what the request looked like, so `bin/firewall-block --show` can later answer *why is this address blocked and what did they do*.

Until 2.31.0 that meant **everything**: the visitor's whole cookie jar and header set, verbatim. A blocked visitor's session cookie, their `Authorization` header and their challenge pass were persisted into the block list — and printed back by `--show --json`.

```yaml
storage:
  type: "Kanopi\\Firewall\\Storage\\FileStorage"
  config:
    storage_file: /var/lib/firewall/blocked.data
    record_request:
      cookies: []                                      # default: none
      headers: [user-agent, referer, accept-language]   # default: a short list
      query: ["*"]                                      # default: everything
      body: []                                          # default: none
```

Every backend accepts `record_request`, because every backend records the same thing.

### Why this matters more than it first reads

- **The block list is the artifact you share.** It is what gets pasted into a ticket, read out on a call and, with [a shared list](#a-block-list-shared-across-a-fleet), replicated to every node.
- **A record outlives the request by design.** It is kept for the ban's duration, which under `blocking_escalation` is days.
- **The session cookie is not the firewall's to hold.** It belongs to the application in front of it.

### An allowlist, not a denylist

A denylist is a promise to have thought of every header name a framework might invent — `X-Session`, `X-Auth`, the next vendor's. An allowlist is wrong in the direction that loses evidence rather than the one that keeps credentials, and evidence is recoverable by configuration.

`["*"]` keeps everything in a bucket, for a deployment that has decided it wants the forensics and understood what that means.

### The four defaults are not the same, on purpose

They reflect where the risk actually is rather than a wish to look tidy.

| Bucket | Default | Why |
|---|---|---|
| `cookies` | none | The session-cookie problem, and it is unambiguous |
| `headers` | a short list | `Cookie`, `Authorization` and every `X-*-Token` are the hazard; `User-Agent` and `Referer` are most of the value |
| `query` | everything | For a scanner — the commonest case — the query string **is** the attack |
| `body` | none | A blocked login attempt has the password in it |

The `query` default is the one to think about for your own site. It is kept because redacting it would gut the record for the thing it is most often read about; the risk is narrower but real — a password reset link, an API key somebody put in a URL. Narrow it with an allowlist if your URLs carry secrets.

!!! note "Narrowing `query` also narrows `uri`"

    `uri` carries the query string, so removing a parameter from one field and leaving it in the field beside it would be a setting that silently does nothing. The recorded `uri` is rebuilt from what survived.

### Two things it deliberately does not do

**It does not touch records already written.** Redaction happens on the way *in* — the only place it can, since redacting in `--show`'s output would leave the credential in the store, where a shared list replicates it and a database backup keeps it. Records written before the upgrade still hold what they held.

`firewall-doctor` counts them, so you know whether there is anything to act on:

```
  ! 412 existing block records still hold cookies or headers
      Written before the allowlist existed, and unaffected by it — redaction happens
      on write. They expire with their bans; `bin/firewall-block --lift` clears them
      sooner, at the cost of un-blocking whoever is in them.
```

**There is no command that scrubs them in place.** A record's *remaining* ban time cannot be read back portably across the backends, so rewriting one would silently reset its ban to a full term — turning a privacy fix into a change in how long people are blocked for. Letting them expire, or clearing deliberately, are the honest options.

## Searching and Un-blocking

`StorageInterface` gives you keyed access — `get()`, `set()`, `delete()` for an address you already know. That covers the firewall's own hot path, but it leaves two operational questions unanswered: *who is currently blocked?*, and *how do I lift a block that should not have been applied?*

!!! tip "From the command line"

    Both questions have a command, and reaching for PHP is no longer the first step:

    ```bash
    vendor/bin/firewall-block firewall.yml --list
    vendor/bin/firewall-block firewall.yml --find=203.0.113.0/24
    vendor/bin/firewall-block firewall.yml --show=203.0.113.5      # with offence history
    vendor/bin/firewall-block firewall.yml --lift=203.0.113.5 --dry-run
    vendor/bin/firewall-block firewall.yml --lift=203.0.113.5
    ```

    It reads and writes the **real** block list, unlike `firewall-check`, which swaps in a
    throwaway so that checking a request cannot ban anyone. The backend is named in the
    output for that reason, and a store that cannot outlive the process says so — otherwise
    "nothing blocked" reads as *your customer is fine* when it means *I looked somewhere
    that has never held anything*.

    `--dry-run` exists because lifting is not reversible: the record goes and the offence
    history with it.

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

Not every backend can enumerate its own keys — Memcached, the worked example in [Custom Storage Backends](../how-to/custom-storage.md), cannot list keys at all. Folding these methods into `StorageInterface` would oblige every implementation to supply something it may be unable to implement honestly, and would break existing custom storages on upgrade. Enumeration is a capability, so it is modelled as one, and callers check with `instanceof` before using it.

### Behaviour worth knowing

- **Both IPv4 and IPv6 ranges** are supported: `203.0.113.0/24`, `2001:db8::/32`.
- **A malformed pattern matches nothing**, never everything. An out-of-range prefix such as `/33` on IPv4 is treated as invalid rather than silently clamped to a single host — otherwise you would clear one record believing you had cleared a range.
- **One bad pattern does not abort the rest.** Invalid entries are skipped and logged, so a typo in one of twenty ranges still lifts the other nineteen. The return count tells you what actually happened.
- **`find()` hides expired records** so you are not shown a block that lapsed an hour ago, but **`deleteMatching()` still removes them** — otherwise an un-block would report nothing matched while the row was still on disk.
- **Offense history is cleared alongside the block.** Left behind, [`blocking_escalation`](global.md#multiple-offenses-defense) would escalate the address straight back to a longer ban on its next request, and the un-block would appear not to have worked.
