# Error Handling & Exceptions

Every exception the library throws extends `Kanopi\Firewall\Exception\FirewallException`, which extends `\RuntimeException`. Catching that one base class is always safe.

```
\RuntimeException
└── FirewallException
    ├── ConfigurationException     Bad config — thrown from Firewall::create()
    │   └── (no subclasses)
    ├── StorageException           Storage file is unusable
    ├── FirewallBlockedException    ─┐
    ├── ChallengeRequiredException   ├─ only in mode: exception
    └── ChallengeSolvedException    ─┘
```

| Exception | When | What to do |
|---|---|---|
| `ConfigurationException` | During `Firewall::create()`: an empty `challenge.secret` while challenge plugins are configured, a `challenge.provider` that does not resolve to a `ChallengeProviderInterface`, or no trusted proxies when `require_trusted_proxies: true`. | Fail the deploy. This always signals operator error, never attacker input. |
| `StorageException` | A `FileStorage` / `FileRateLimitStorage` path cannot be created, read, or written. | Fix permissions on the storage path. Thrown at construction, so it also surfaces from `create()`. |
| `FirewallBlockedException` | `mode: exception` only — a `block` plugin matched. Carries `getStatusCode()` and the interpolated banning message. | Render your framework's error response with that status code. |
| `ChallengeRequiredException` | `mode: exception` only — a `challenge` plugin matched and the visitor holds no valid pass token, **or** a posted solution was rejected. | Render the interstitial yourself, or return the status your API expects. |
| `ChallengeSolvedException` | `mode: exception` only — a posted solution verified. Carries `getToken()` (the minted pass token) and `getRedirect()` (a sanitized, same-origin target). | Set the pass-token cookie / return the token to the client, then redirect to `getRedirect()`. |

Note that the three request-time exceptions are thrown **only** in `mode: exception`. In the default `block` mode the firewall writes the response and calls `exit()` itself, so there is nothing to catch.

Config *loading* problems are conditional: a missing, unreadable, or malformed config file — including circular `configs:` includes, unresolvable `%env(...)%` tokens, and use of a disabled filesystem processor — is logged at `error` level and produces an empty or partial ruleset, and raises `ConfigurationException` only when [`global.require_config: true`](../configuration/global.md#requiring-the-config-to-load) is set. See [Fail open or fail closed?](#fail-open-or-fail-closed) for why that matters.

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
| Your config file is missing, unreadable, or malformed, with `require_config: true` | `ConfigurationException` | The firewall never started. **Nothing is filtered.** |
| The same, with `require_config: false` (default) | **Nothing** — logged at `error` | The firewall starts with a partial ruleset, possibly an empty one that allows every request. |

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
