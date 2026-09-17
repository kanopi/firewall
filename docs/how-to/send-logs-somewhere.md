# Send Logs Somewhere

The firewall logs every decision through [Monolog](https://github.com/Seldaek/monolog), so
any Monolog handler works. Each entry under `logger:` is one destination, and you can stack
as many as you need.

This page is the common setups. For every handler and every option, see
[Logging](../configuration/logging.md).

## A file, to start with

```yaml
logger:
  - class: Monolog\Handler\StreamHandler
    args:
      - /var/log/firewall/firewall.log
      - Monolog\Level::Info
```

A relative path resolves **against the YAML file that declares it**, not the working
directory — so the same config writes to the same place under `php -S`, php-fpm and cron.

## A file that does not grow forever

`StreamHandler` never rotates. On a busy site that is a disk-space incident waiting to
happen, so prefer:

```yaml
logger:
  - class: Monolog\Handler\RotatingFileHandler
    args:
      - /var/log/firewall/firewall.log
      - 14                          # keep two weeks
      - Monolog\Level::Info
```

## Somewhere you can query it

A file answers "what happened just now". It does not answer "how often did this rule fire
last month", which is the question that actually comes up. For that, log to a database
table:

```yaml
logger:
  - class: Kanopi\Firewall\Logging\DatabaseHandler
    args:
      - { dsn: "mysql://firewall:secret@localhost/security" }
      - firewall_log
      - Monolog\Level::Info
```

That has real costs — a write on the request path, a table that grows, and a schema that
changes between releases. All three are covered in
[Database logging](../configuration/logging.md#database-logging); read it before turning
this on in production, and set up [retention](../configuration/logging.md#retention) at the
same time rather than later.

## Paging a human, but only when it matters

Every handler takes its own level, so tee everything to a file and escalate only what
deserves waking somebody:

```yaml
logger:
  # Everything
  - class: Monolog\Handler\StreamHandler
    args:
      - /var/log/firewall/firewall.log
      - Monolog\Level::Info

  # Only the things that mean something is broken
  - class: Monolog\Handler\SlackWebhookHandler
    args:
      - "%env(SLACK_WEBHOOK_URL)%"
      - "#alerts"
      - "firewall"
      - true
      - null
      - false
      - true
      - Monolog\Level::Critical
```

!!! warning "A chatty alert channel is an ignored alert channel"

    `Warning` is the level the firewall uses for every observed-mode match and every panic
    switch reminder. Pointing Slack at `Warning` will page you continuously on a healthy
    site. `Critical` and above is the useful threshold for anything that interrupts a
    person.

Slack, Pushover, IFTTT and Telegram all need `ext-curl`. Mail handlers may need a transport
package installed.

!!! danger "Every one of those blocks the request while it sends"

    `SlackWebhookHandler`, `LogglyHandler`, `InsightOpsHandler`, `TelegramBotHandler` and the
    rest make a **synchronous HTTPS round trip inside `write()`, once per record** — on a
    component that logs per decision. A log service having a slow afternoon becomes a slow site.

    The firewall catches a handler that *throws* and reports it as a degraded backend. Nothing
    catches one that *hangs*, and a slow site is harder to diagnose than a failed one.

    Two ways out, below, and the first one is better.

## Better: write lines, let something else ship them

```yaml
logger:
  - class: Monolog\Handler\StreamHandler
    args:
      - php://stdout
      - Monolog\Level::Info
    formatter:
      class: Monolog\Formatter\JsonFormatter
```

Then point [Vector](https://vector.dev), [Fluent Bit](https://fluentbit.io), Filebeat or
promtail at it. Delivery, retries, batching and backpressure are handled by software built for
exactly that, and the firewall's cost is a `write()` to a local stream.

For a containerised deployment this is simply the right answer, and it needs nothing from this
package. Reach for the next section only when you cannot do it.

## If you must send HTTP from PHP: defer it

```yaml
logger:
  - class: Kanopi\Firewall\Logging\Handler\DeferredHandler
    args:
      # The handler to flush into, once the visitor has been served.
      - class: Monolog\Handler\LogglyHandler
        args: ["%env(LOGGLY_TOKEN)%", Monolog\Level::Warning]
      - 0                       # buffer limit; 0 holds everything
      - Monolog\Level::Warning
```

```
handle()   →  buffer in memory, return immediately
shutdown   →  fastcgi_finish_request()   ← the visitor is served here
           →  flush the buffer to the wrapped handler
```

A wrapper rather than a thirteenth HTTP handler: Monolog's are maintained, and reimplementing
the Datadog, Loki and Splunk payload formats is a treadmill. What was missing is a way to get
*any* of them off the request path.

It works with any handler, not only the HTTP ones — and on a framework that already closes the
connection itself (Symfony's `Response::send()` calls `fastcgi_finish_request()`), the call
here is a harmless no-op.

!!! warning "What deferring does not fix"

    **It cannot bound how long the flush takes.** After the response is sent a hung request is
    no longer a slow page, but it is still an FPM worker held out of the pool, and enough of
    them is an outage by another route. Set a timeout on the handler you wrap where it has one
    — `SocketHandler` has `setConnectionTimeout()` and `setWritingTimeout()`; the curl-based
    handlers expose none, which is worth knowing before choosing one.

    **Buffering trades durability for latency.** A fatal that kills the process before shutdown
    loses the buffer. That is the right trade for a firewall log and the wrong one for an audit
    log.

    **Under CLI there is nothing to release.** `bin/firewall-check` and `firewall-doctor` have
    no connection to close, so records are flushed at shutdown without the early release rather
    than dropped.

### Wrapping handlers, generally

A wrapping handler takes another handler as its first argument, and until 2.31.0 YAML had no
way to say that — so the answer for wrapping anything was "write PHP instead". Any nested
`{class, args}` block is now built as a handler, which makes Monolog's own wrappers
configurable too:

```yaml
logger:
  # Keep debug records in memory; write them all only if something goes wrong.
  - class: Monolog\Handler\FingersCrossedHandler
    args:
      - class: Monolog\Handler\StreamHandler
        args: [/var/log/firewall/firewall.log, Monolog\Level::Debug]
      - Monolog\Level::Error
```

A nested block that is not a handler class is rejected the same way a top-level one is, and a
handler whose constructor genuinely takes an array is unaffected.

## Check it is actually writing

```console
$ firewall-doctor config/firewall.yml
```

A handler that cannot reach its destination — an unwritable path, an unreachable database —
is reported there rather than failing silently on the next request.

## Then what

| | |
|---|---|
| Every handler and option | [Logging](../configuration/logging.md) |
| Keep secrets out of the log | [Sensitive value redaction](../configuration/logging.md#sensitive-value-redaction) |
| Wrap handlers (`FingersCrossed`, `Buffer`, `Filter`) | [Wrapping handlers](#wrapping-handlers-generally), or [inject your own logger](../configuration/logging.md#injecting-your-own-logger) |
| Stop a remote handler slowing the request | [Defer it](#if-you-must-send-http-from-php-defer-it) |
| Trim an oversized log table | `firewall-log-prune config.yml` |
| React to decisions in code instead of reading logs | [React to Decisions](decision-events.md) |
