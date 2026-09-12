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
| Wrap handlers (`FingersCrossed`, `Buffer`, `Filter`) | [Inject your own logger](../configuration/logging.md#injecting-your-own-logger) |
| Trim an oversized log table | `firewall-log-prune config.yml` |
| React to decisions in code instead of reading logs | [React to Decisions](decision-events.md) |
