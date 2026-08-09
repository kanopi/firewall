# Logging Configuration

The firewall uses [Monolog](https://github.com/Seldaek/monolog) for flexible logging, so any Monolog handler can be wired up through the `logger` key. Each entry under `logger` is a separate handler — combine as many as you need (file + Slack + email is a common pattern).

Each handler entry accepts:

- `class` — fully qualified handler class name (must implement `Monolog\Handler\HandlerInterface`).
- `args` — positional constructor arguments, in order.
- `formatter` *(optional)* — `class` + `args` for a `Monolog\Formatter\FormatterInterface` implementation, applied to that handler.

Log levels are passed as strings like `Monolog\Level::Info` (Debug, Info, Notice, Warning, Error, Critical, Alert, Emergency). Relative log file paths (e.g., `args[0]` for `StreamHandler`) are resolved **relative to the YAML file** that declares them.

> **Heads up:** several Monolog handlers require additional PHP extensions or third-party packages. Slack/IFTTT/Pushover/Telegram need `ext-curl`; `SendGridHandler` and `SymfonyMailerHandler` may require `composer require` of the relevant transport package. See the [Monolog handler docs](https://seldaek.github.io/monolog/doc/02-handlers-formatters-processors.html) for each handler's prerequisites.

## File logging

Write every event to a flat file:

```yaml
logger:
  - class: Monolog\Handler\StreamHandler
    args:
      - /var/log/firewall/firewall.log
      - Monolog\Level::Info
    formatter:
      class: Monolog\Formatter\LineFormatter
      args:
        - "[%datetime%] [%level_name%] [%context.plugin%] %message% %context% %extra%\n"
        - "Y-m-d H:i:s"
```

## Rotating file logging

Rotate logs daily and keep the last seven days. Useful when StreamHandler files grow unbounded:

```yaml
logger:
  - class: Monolog\Handler\RotatingFileHandler
    args:
      - /var/log/firewall/firewall.log
      - 7                          # maxFiles to keep (0 = unlimited)
      - Monolog\Level::Info
```

## JSON-structured logging

Emit one JSON object per line — easy to ingest into Loki, ELK, Datadog, etc:

```yaml
logger:
  - class: Monolog\Handler\StreamHandler
    args:
      - /var/log/firewall/firewall.ndjson
      - Monolog\Level::Info
    formatter:
      class: Monolog\Formatter\JsonFormatter
```

## Syslog

Forward events to the host's syslog (handy on managed/cloud platforms that scrape syslog automatically):

```yaml
logger:
  - class: Monolog\Handler\SyslogHandler
    args:
      - firewall                   # ident / tag
      - user                       # facility — see below
      - Monolog\Level::Warning
```

> `SyslogHandler` accepts a facility *name* (string) such as `user`, `daemon`, `mail`, `auth`, `local0`–`local7`. The PHP `LOG_*` constants are integers that YAML cannot reference; passing the literal string `LOG_USER` triggers `UnexpectedValueException`. Stick to the lowercase names above.

## PHP error log

Pipe firewall events into the configured PHP `error_log` — useful in shared hosting or when you don't control filesystem paths:

```yaml
logger:
  - class: Monolog\Handler\ErrorLogHandler
    args:
      - 0                          # 0 = operating system, 4 = SAPI
      - Monolog\Level::Warning
```

## Email alerts

Send an email when something critical happens. `NativeMailerHandler` uses PHP's `mail()` — no extra package required:

```yaml
logger:
  - class: Monolog\Handler\NativeMailerHandler
    args:
      - security@example.com       # to (string or list of recipients)
      - "Firewall Alert"           # subject
      - noreply@example.com        # from
      - Monolog\Level::Critical
```

For higher-volume alerting via SendGrid (requires `ext-curl`):

```yaml
logger:
  - class: Monolog\Handler\SendGridHandler
    args:
      - apikey                     # SendGrid API user (use "apikey" for API key auth)
      - "%env(SENDGRID_API_KEY)%"  # API key
      - noreply@example.com        # from
      - security@example.com       # to (string or list)
      - "Firewall Alert"           # subject
      - Monolog\Level::Critical
```

## Slack alerts

Post directly to a Slack channel through an [Incoming Webhook](https://api.slack.com/messaging/webhooks). Requires `ext-curl`:

```yaml
logger:
  - class: Monolog\Handler\SlackWebhookHandler
    args:
      - "%env(SLACK_WEBHOOK_URL)%" # webhook URL
      - "#security-alerts"         # channel override (or null)
      - "Firewall"                 # bot username
      - true                       # useAttachment
      - ":shield:"                 # iconEmoji
      - false                      # useShortAttachment
      - true                       # includeContextAndExtra
      - Monolog\Level::Warning
```

If you prefer the Slack Web API (legacy token-based handler):

```yaml
logger:
  - class: Monolog\Handler\SlackHandler
    args:
      - "%env(SLACK_BOT_TOKEN)%"   # Slack bot token
      - "#security-alerts"         # channel
      - "Firewall"                 # username
      - true                       # useAttachment
      - ":shield:"                 # iconEmoji
      - Monolog\Level::Critical
```

## Pushover (push notifications)

Send mobile push notifications via [Pushover](https://pushover.net/):

```yaml
logger:
  - class: Monolog\Handler\PushoverHandler
    args:
      - "%env(PUSHOVER_APP_TOKEN)%"  # application API token
      - "%env(PUSHOVER_USER_KEY)%"   # user/group key (string or list)
      - "Firewall Alert"             # notification title
      - Monolog\Level::Critical
```

## IFTTT webhooks

Trigger an [IFTTT Maker](https://ifttt.com/maker_webhooks) applet — useful for chaining custom automations (SMS, smart lights, voice assistants, etc.):

```yaml
logger:
  - class: Monolog\Handler\IFTTTHandler
    args:
      - firewall_alert             # event name configured in the IFTTT applet
      - "%env(IFTTT_MAKER_KEY)%"   # Maker webhook key
      - Monolog\Level::Error
```

IFTTT receives three values: `value1` = channel, `value2` = level name, `value3` = message.

## Telegram bot

Send messages to a Telegram channel or chat via a bot token:

```yaml
logger:
  - class: Monolog\Handler\TelegramBotHandler
    args:
      - "%env(TELEGRAM_BOT_TOKEN)%"  # bot token from @BotFather
      - "@my_security_channel"       # chat ID or @channel
      - Monolog\Level::Critical
```

## Per-handler severity thresholds

Each handler entry has its own `level` argument, so you can tune verbosity per destination. The pattern below writes every Info-and-above event to file but only escalates Critical events to email:

```yaml
logger:
  - class: Monolog\Handler\StreamHandler
    args:
      - /var/log/firewall/firewall.log
      - Monolog\Level::Info

  - class: Monolog\Handler\NativeMailerHandler
    args:
      - security@example.com
      - "Firewall Alert"
      - noreply@example.com
      - Monolog\Level::Critical
```

> Handlers that wrap other handlers (e.g. `FingersCrossedHandler`, `BufferHandler`, `FilterHandler`, `GroupHandler`) take a `HandlerInterface` as a constructor argument, which the YAML loader cannot construct recursively. To use those, build the logger programmatically with `Monolog\Logger` and inject it via `LoggingFactory::setLogger()` before calling `Firewall::create()`.

## Combining multiple handlers

You can stack any number of handlers — each entry under `logger` is independent. A common production setup tees everything to a file, surfaces warnings to syslog, and pages humans via Slack/Pushover only on critical events:

```yaml
logger:
  # Everything to file
  - class: Monolog\Handler\RotatingFileHandler
    args:
      - /var/log/firewall/firewall.log
      - 14
      - Monolog\Level::Info

  # Warnings and above to syslog
  - class: Monolog\Handler\SyslogHandler
    args:
      - firewall
      - user
      - Monolog\Level::Warning

  # Critical events ping the on-call channel
  - class: Monolog\Handler\SlackWebhookHandler
    args:
      - "%env(SLACK_WEBHOOK_URL)%"
      - "#security-oncall"
      - "Firewall"
      - true
      - ":rotating_light:"
      - false
      - true
      - Monolog\Level::Critical

  # And buzz a phone if no one acks
  - class: Monolog\Handler\PushoverHandler
    args:
      - "%env(PUSHOVER_APP_TOKEN)%"
      - "%env(PUSHOVER_USER_KEY)%"
      - "Firewall CRITICAL"
      - Monolog\Level::Critical
```

For the full catalogue of available handlers (Telegram, Mandrill, Loggly, Elasticsearch, Sentry via PSR, etc.), see the [Monolog handlers reference](https://seldaek.github.io/monolog/doc/02-handlers-formatters-processors.html).

## Sensitive Value Redaction

Conditional rules can match against any part of a request, including headers and cookies. At `debug` level the matched value is logged so you can see *why* a rule fired — which would otherwise write session cookies and API keys into your firewall log verbatim.

To prevent that, matched values for a set of variable names are logged as `[REDACTED]`. **This is on by default**, covering:

```
header.cookie
header.authorization
header.proxy-authorization
header.x-api-key
header.x-auth-token
header.x-csrf-token
header.x-session-token
cookie.*
```

Matching is case-insensitive, and a trailing `.*` makes the entry a prefix wildcard — `cookie.*` covers every individual cookie. Redaction applies to the logged value only; **rule evaluation always sees the real value**, so redacting a variable never changes whether a request is blocked.

Replace the list from PHP, before evaluation:

```php
use Kanopi\Firewall\Logging\LoggingFactory;

// Keep the defaults and add your own headers.
LoggingFactory::setRedactedVariables([
    ...LoggingFactory::getRedactedVariables(),
    'header.x-internal-token',
    'query.access_token',
    'post.password',
]);

\Kanopi\Firewall\Firewall::create([__DIR__ . '/firewall.yml'])->evaluate();
```

`setRedactedVariables()` **replaces** the list rather than appending to it, which is why the example above spreads `getRedactedVariables()` first. Passing an empty array turns redaction off entirely:

```php
// Everything gets logged verbatim. Only do this in local debugging.
LoggingFactory::setRedactedVariables([]);
```

Use the same dot-notation as your conditional rules (`header.*`, `cookie.*`, `query.*`, `post.*`). `LoggingFactory::shouldRedactVariable('header.cookie')` tells you whether a given name currently matches.

**Redaction only covers rule-match logging.** It does not scrub values that reach your log through other paths — the banning message, for instance, interpolates `{{ request.header.? }}` placeholders you write yourself. Don't put a secret-bearing header in a banning message and expect it to be redacted.

## Injecting Your Own Logger

By default the library builds its own Monolog `Logger` on the `firewall` channel from the `logger:` config. There are two ways to send firewall events to logging your application already owns.

**Option 1 — inject your handlers (recommended).** `class` accepts an *instantiated* `Monolog\Handler\HandlerInterface`, not just a class name. Because a YAML scalar cannot carry an object, pass it through [Dynamic Configuration Overrides](overrides.md):

```php
\Kanopi\Firewall\Firewall::create(
    [__DIR__ . '/firewall.yml'],
    ['[logger][0][class]' => $myMonologHandler]
)->evaluate();
```

This keeps everything the firewall logs — including the messages emitted *during* `create()` — flowing to your handler. It works whether or not your YAML declares a `logger:` section; index `0` is created if it does not exist. Entries you do declare are preserved, so `[logger][1][class]` adds a second handler alongside the first.

**Option 2 — replace the whole logger after construction.** `LoggingFactory::setLogger()` takes a Monolog `Logger` instance (not any PSR-3 logger):

```php
use Kanopi\Firewall\Logging\LoggingFactory;

$firewall = \Kanopi\Firewall\Firewall::create([__DIR__ . '/firewall.yml']);

// Must come *after* create() — see the note below.
LoggingFactory::setLogger($myMonologLogger);

$firewall->evaluate();
```

> **Ordering matters.** `Firewall::create()` always ends up calling `setLogger()` itself with a logger built from the `logger:` config, so a logger you install *before* `create()` is discarded. Install it after `create()` and before `evaluate()`. Startup messages (config loading, plugin registration, trusted-proxy warnings) are emitted during `create()` and will still go to the YAML-configured logger — which is why Option 1 is the better choice if you need those too.

`LoggingFactory::logger()` returns whichever logger is currently in effect, and `LoggingFactory::logMessage($level, $message, $context)` writes to it — useful from a custom plugin.
