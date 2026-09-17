# Tarpit Response Type

`response: tarpit` holds a request still for a few seconds before letting it continue. It costs an attacker throughput without refusing anybody, which is useful against a scraper or a slow credential-stuffing run that a block would simply teach to rotate addresses.

```yaml
tarpit:
  max_concurrent: 5     # holds allowed at once, across every tarpit rule
  max_seconds: 30       # ceiling on any single hold

plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\UserAgent"
    response: tarpit
    weight: -10
    metadata:
      name: slow-the-scrapers
      tarpit_seconds: 5
    config:
      - "user_agent@contains:python-requests"
```

!!! danger "Read this before turning it on"

    A tarpit holds a **php-fpm worker** for its duration. That worker is a resource an attacker can consume on purpose: with `pm.max_children = 20` and a ten-second hold, **twenty requests take the site down** — and the rule that did it looks like it is working.

    This is why the feature shipped a release later than the other response types, and why the cap below is not optional.

## The cap is the feature

Every hold claims a slot before it sleeps. A claim that would exceed `max_concurrent` is given straight back and **the request is served normally instead of being delayed**.

So under attack the tarpit stops tarpitting. That is the failure the site survives, and it is deliberately the one that happens: the alternative is the site stops serving.

| | |
|---|---|
| `tarpit.max_concurrent` | Holds allowed at once. Default `5` |
| `tarpit.max_seconds` | Ceiling on one hold. Default `30` |
| `metadata.tarpit_seconds` | What this rule asks for. Clamped by the ceiling |

**The default of 5 is small on purpose.** The number that matters is `pm.max_children`, which the firewall cannot see. A tenth of the worker pool is a reasonable starting point; a cap near the size of the pool is the outage this is meant to prevent.

`firewall-check --lint` reports what your configuration can hold, so the arithmetic happens before the deploy rather than during an incident:

```
  ! Tarpit rules can hold 40 workers at once
      For up to 20s each. Check that against your `pm.max_children` — a cap near
      the size of the worker pool means a handful of requests can take the site
      down, which is the failure a tarpit is supposed to prevent rather than cause.
```

## Your storage backend has to be able to count

A cap needs to know how many holds are in flight **right now, across processes**. `StorageInterface` has no atomic increment and `RateLimitStorageInterface` counts a *rate*, which is not the same question.

So counting is an optional interface — `ConcurrencyGaugeInterface` — in the shape [`QueryableStorageInterface`](../how-to/custom-storage.md) already established:

| Backend | Counts | Scope |
|---|---|---|
| `FileStorage` | Yes, with an exclusive lock | This host |
| `RedisStorage` | Yes, with `INCR`/`DECR` | The fleet |
| `DatabaseStorage` | **No** | — |
| `InMemoryStorage` | **No** | — |

A tarpit rule configured against a backend that cannot count is a **startup failure**:

```
response: tarpit rules are configured, but Kanopi\Firewall\Storage\InMemoryStorage
cannot count how many holds are in flight. A tarpit holds a php-fpm worker for its
duration, so without an atomic cap a handful of requests can take the site down —
and the rule looks like it is working while they do.
```

That refusal is the point, not a nicety. A gauge that under-counts admits more holds than the cap allows, which is the original problem with an extra step — so a backend that cannot do it atomically **does not implement the interface** rather than approximating it.

`InMemoryStorage` is the instructive case: incrementing a PHP array is perfectly atomic within one process, and a cap across workers is exactly what one process cannot see.

**Per-host is the right scope, not a compromise.** What a tarpit consumes is workers, and workers are per-host — so `FileStorage` counting one machine is counting the right pool. Redis counts the fleet, which is broader than necessary and also fine.

## It does not refuse anything

A tarpit is **non-terminal**: the delay is paid, and then the request carries on down the [evaluation ladder](../reference/evaluation-order.md). It sits after `record` and before `challenge`.

That means a tarpit rule and a block rule matching the same client compose into a slow block, rather than needing a feature of their own:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Asn"
    response: tarpit
    metadata: { name: slow-them, tarpit_seconds: 5 }
    config: ["asn:AS14618"]

  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    metadata: { name: no-admin }
    config: ["path@starts_with:/wp-admin"]
```

It runs **after the storage block list**, so a client already blocked is refused rather than held. Holding a worker on behalf of somebody being refused anyway is the self-DoS with extra steps.

In `mode: log` nothing is held at all. A dry run that still takes a worker out of the pool for ten seconds is not a dry run.

## Should you use one at all?

Often the honest answer is no.

A CDN, a load balancer or `nginx`'s `limit_req` does this **without holding a PHP worker**, because they are built for it and PHP is not. If something in front of your application can delay a request, that is where the delay belongs.

The case for doing it here is that the rule lives with every other rule — same matching, same logging, same `--explain` — and that a firewall rule can express *"this user agent, on this path, during these hours"* in a way an `nginx` config cannot reach.

## What it costs you when a worker dies

A slot is released in a `finally` **and** from a shutdown function, because the firewall terminates with `exit()` on the paths below the tarpit and a fatal ends the process outright — shutdown functions run in both cases.

A worker killed outright (`SIGKILL`, an FPM `request_terminate_timeout`) can still leak a slot. The counter carries a TTL as the backstop, so a leak clears on its own. Until it does, the leaked count makes the cap **stricter**, which is the safe direction to be wrong in.

## Watching it

`firewall_requests_total{decision="held"}` and `{decision="not_held"}` count the two outcomes separately, and `firewall_tarpit_in_flight` is the gauge the cap is about. See [Export Metrics](../how-to/metrics.md).

`not_held` climbing is the signal that matters: it means the cap is saturated, and either an attack is under way or the cap is too small for ordinary traffic.

```
Tarpit at capacity; serving the request instead of holding it
  in_flight: 5
  max_concurrent: 5
```
