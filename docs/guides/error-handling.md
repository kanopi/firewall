# Error Handling & Exceptions

Every exception the library throws extends `Kanopi\Firewall\Exception\FirewallException`, which extends `\RuntimeException`. Catching that one base class is always safe.

```
\RuntimeException
└── FirewallException
    ├── ConfigurationException     Bad config — thrown from Firewall::create()
    │   └── (no subclasses)
    ├── StorageException           Storage file is unusable
    │   └── StorageConnectionException  Database storage cannot be reached
    ├── FirewallBlockedException    ─┐
    ├── ChallengeRequiredException   ├─ only in mode: exception
    └── ChallengeSolvedException    ─┘
```

| Exception | When | What to do |
|---|---|---|
| `ConfigurationException` | During `Firewall::create()`: an empty `challenge.secret` while challenge plugins are configured, a `challenge.provider` that does not resolve to a `ChallengeProviderInterface`, or no trusted proxies when `require_trusted_proxies: true`. | Fail the deploy. This always signals operator error, never attacker input. |
| `StorageException` | A `FileStorage` / `FileRateLimitStorage` path cannot be created, read, or written. | Fix permissions on the storage path. Thrown at construction, so it also surfaces from `create()`. |
| `StorageConnectionException` | A `DatabaseStorage` / `DatabaseRateLimitStorage` cannot build its connection, create its schema manager, or reach the database. Carries the redacted target (`driver=… host=… dbname=…`) and the driver exception as `previous`. | Fix the credentials or reachability. Thrown at construction, so `DatabaseStorage` surfaces from `create()`; rate-limit storage is built lazily and surfaces on the first evaluated request. |
| `FirewallBlockedException` | `mode: exception` only — a `block` plugin matched. Carries `getStatusCode()` and the interpolated banning message. | Render your framework's error response with that status code. |
| `ChallengeRequiredException` | `mode: exception` only — a `challenge` plugin matched and the visitor holds no valid pass token, **or** a posted solution was rejected. | Render the interstitial yourself, or return the status your API expects. |
| `ChallengeSolvedException` | `mode: exception` only — a posted solution verified. Carries `getToken()` (the minted pass token) and `getRedirect()` (a sanitized, same-origin target). | Set the pass-token cookie / return the token to the client, then redirect to `getRedirect()`. |

Note that the three request-time exceptions are thrown **only** in `mode: exception`. In the default `block` mode the firewall writes the response and calls `exit()` itself, so there is nothing to catch.

Config *loading* problems are conditional: a missing, unreadable, or malformed config file — including circular `configs:` includes, unresolvable `%env(...)%` tokens, and use of a disabled filesystem processor — is logged at `error` level and produces an empty or partial ruleset, and raises `ConfigurationException` only when [`global.require_config: true`](../configuration/global.md#requiring-the-config-to-load) is set. See [Fail open or fail closed?](#fail-open-or-fail-closed) for why that matters.

## Checking that every rule is running

A rule whose constructor throws — a rate limit backend pointed at a Redis host that is not answering, a storage path that lost its permissions — is logged at `error` level and skipped. The request is evaluated by the rules that *did* build, which is deliberate: a broken backend should not take the site down. But for a `block` rule it is a fail-open, and a firewall running three rules short looks exactly like a firewall running correctly.

`getFailedRules()` is how a health check asks:

```php
$firewall = Firewall::create([__DIR__ . '/firewall.yml']);

foreach ($firewall->getFailedRules() as $rule) {
    // bucket: allow | challenge | block
    // plugin: Kanopi\Firewall\Plugins\RateLimit:2
    // error:  Connection refused
    $status->addError(sprintf(
        'Firewall %s rule %s is not running: %s',
        $rule['bucket'],
        $rule['plugin'],
        $rule['error']
    ));
}
```

The plugin name carries the index of the rule within your `plugins:` list, so two rules of the same class are distinguishable — `RateLimit:2` is the third entry, not the second rule of that type.

Two things about the call:

- **It builds every rule to find out.** Rules are constructed lazily, on the first request that evaluates them, so a status page that only asked what had failed so far would always be told "nothing" — and that is the false clean bill of health this exists to replace. Building a rule is what opens its storage connection, so reachability is genuinely tested. **Call it from a status report or a health check, not from a request path.** Anything it builds is reused by a later `evaluate()` in the same process, so nothing is paid twice.
- **A rule that already failed is never retried.** Re-running a constructor that throws on every request buys nothing, least of all a connection that is not coming back.

An empty array means every configured rule is constructed and active. It says nothing about rules you disabled with `enable: false` or left out of the config — those never enter the registry, and are not failures.

## Checking that a backend can reach its server

`getFailedRules()` answers one question — *which rules are not running?* There is a second, and an empty answer to the first does not settle it: **a rule can be running and have nothing to consult.**

`RedisStorage` and `RedisRateLimitStorage` deliberately catch a connection failure, log it, and answer every read as though nothing were stored, so the firewall carries on enforcing every rule that does not depend on them. The plugin therefore constructs successfully, and `getFailedRules()` correctly reports nothing — while a rate limit rule counts nothing and lets every request through.

```php
foreach ($firewall->getDegradedBackends() as $backend) {
    // component: 'block list' | 'rate limit'
    // backend:   Kanopi\Firewall\Storage\RedisStorage
    // error:     Connection refused
    $status->addWarning(sprintf(
        'The firewall %s is running without its store: %s (%s)',
        $backend['component'],
        $backend['error'],
        $backend['backend']
    ));
}
```

The two together are the health check. A rule in `getFailedRules()` **is not running**; a backend in `getDegradedBackends()` **is running blind**.

- **It builds every rule to find out**, for the same reason `getFailedRules()` does — a rate limit store is constructed by its plugin, so before the rules exist there is no backend to have failed.
- **It reports what was found at construction**, which is when a connection is opened. A backend that connects and later loses its server logs, as it always did, and does not appear here.
- **A `DatabaseStorage` that cannot connect does not appear either** — that one throws at construction, so it shows up in `getFailedRules()` instead. The two lists are exhaustive between them, not overlapping.

## Handling blocks in a framework

```php
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;

try {
    Firewall::create([__DIR__ . '/firewall.yml'])->evaluate();
} catch (FirewallBlockedException $e) {
    // mode: exception — a plugin blocked the request. Render your own page.
    return new Response($e->getMessage(), $e->getStatusCode());
} catch (ConfigurationException $e) {
    // Startup validation failed. See "Fail open or fail closed?" below.
    $logger->critical('Firewall failed to start: ' . $e->getMessage());

    throw $e;
}
```

### Fail open or fail closed?

"Fail open" means a broken firewall lets traffic through; "fail closed" means it refuses traffic. Which one you get depends on *how* the firewall broke, and the three cases behave differently:

| What went wrong | Throws? | What happens if you catch it and continue |
|---|---|---|
| A `block` plugin matched a request (`mode: exception`) | `FirewallBlockedException` | The request you were meant to block proceeds. |
| Startup validation failed — empty `challenge.secret`, unresolvable `challenge.provider`, or no trusted proxies with `require_trusted_proxies: true` | `ConfigurationException` | The firewall never started. **Nothing is filtered.** |
| A remote `configs:` include cannot be fetched, but a cached copy exists | **Nothing** — logged at `warning` | The firewall starts on the cached rules. They are active, but not necessarily current. |
| Your config file is missing, unreadable, or malformed, with `require_config: true` | `ConfigurationException` | The firewall never started. **Nothing is filtered.** |
| The same, with `require_config: false` (default) | **Nothing** — logged at `error` | The firewall starts with a partial ruleset, possibly an empty one that allows every request. |
| The configured database storage cannot be reached | `StorageConnectionException` | The firewall never started. **Nothing is filtered.** |

**The last row is the one to design around.** Config loading is lenient by default: `Config::loadFile()` skips files it cannot read and catches YAML, include, and `%env(...)%` resolution errors, so a mistyped path or a broken include yields a firewall with **no plugins**. `Firewall::create()` succeeds and `evaluate()` returns `true` for everything. Each failure is at least logged:

```
firewall.ERROR: Firewall config file failed to load — its rules are NOT active
    {"file":"/var/www/firewall.yml","reason":"File does not exist.","require_config":false}
```

An exception handler alone still will not catch that, because none is thrown. Turn it into a startup failure instead:

```yaml
global:
  require_config: true
```

See [Requiring the config to load](../configuration/global.md#requiring-the-config-to-load) for the constant and override forms, which cover the case where the file carrying the flag is the one that failed to load. If you would rather assert on the result yourself, `Config::getLoadErrors()` reports what a lenient load dropped:

```php
$configPath = __DIR__ . '/firewall.yml';

\Kanopi\Firewall\Utility\Config::clearLoadErrors();
$config = \Kanopi\Firewall\Utility\Config::load([$configPath]);

if (\Kanopi\Firewall\Utility\Config::getLoadErrors() !== []) {
    throw new \RuntimeException("Firewall config did not load cleanly: {$configPath}");
}

Firewall::create([$configPath])->evaluate();
```

For the cases that *do* throw, pick a policy deliberately:

- **Fail closed** — rethrow, or return a 503. Correct default for anything where serving unfiltered traffic is worse than serving an error: authenticated apps, checkout flows, admin surfaces. A startup misconfiguration is an operator error caught in deploy, not something to paper over at runtime.
- **Fail open** — log at `critical` and continue. Reasonable only for public, low-risk content where availability outweighs filtering, and only if that alert actually pages someone.

Whichever you choose, make it explicit in code. The library does not decide for you: it propagates the exception and leaves the policy to your error handler.

## Handling the challenge flow in a framework

In `mode: exception` you own the HTTP side of the challenge round-trip. `evaluate()` intercepts POSTs to `challenge.path` before any plugin runs, so a single call site handles both directions:

```php
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;

// Same secret as challenge.secret in your YAML.
$provider = new MathChallengeProvider(new TokenManager($_ENV['FIREWALL_SECRET']));

try {
    Firewall::create([__DIR__ . '/firewall.yml'])->evaluate($request);
} catch (ChallengeSolvedException $e) {
    // Visitor answered correctly. Issue the pass token and send them on.
    $response = new RedirectResponse($e->getRedirect());
    $response->headers->setCookie(
        Cookie::create('fw_challenge_pass', $e->getToken())
            ->withHttpOnly(true)
            ->withSecure(true)
            ->withSameSite('strict')
    );

    return $response;
} catch (ChallengeRequiredException $e) {
    // No valid token, or a wrong answer. Serve the interstitial again.
    return new Response($provider->renderInterstitial($request, [
        'submit_url' => '/_firewall/challenge',
        'redirect_to' => $request->getRequestUri(),
        'ttl' => '3600',
        'cookie_name' => 'fw_challenge_pass',
        'header_name' => 'X-Firewall-Challenge',
    ]), 200);
} catch (FirewallBlockedException $e) {
    return new Response($e->getMessage(), $e->getStatusCode());
}
```

`ChallengeRequiredException` deliberately does not distinguish "you need to solve a challenge" from "your answer was wrong" — telling a bot which of the two happened is free information. If your UX needs to show a retry message, key it off the request being a POST to `challenge.path`.

The cookie attributes above mirror what the firewall sets for you in `block` mode (`HttpOnly`, `Secure`, `SameSite=Strict`). Keep them.
