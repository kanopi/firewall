# Challenge Response Type

`response: challenge` serves an interstitial (a CAPTCHA-style proof-of-effort page) when a plugin matches, instead of rejecting the request outright. A visitor who solves the challenge is issued an HMAC-signed pass token that short-circuits any future `response: challenge` plugin until the token expires.

The pass token is:

- **Signed** with the configured `challenge.secret` (HMAC-SHA256) so it cannot be forged.
- **IP-bound** — the token only verifies for the same client IP that solved the challenge.
- **Audience-bound** — the token carries an `aud` claim and only verifies against the instance that issued it. See [Scoping tokens across instances](#scoping-tokens-across-instances).
- **Delivered two ways** — as an `HttpOnly; Secure; SameSite=Strict` cookie *and* as a value the interstitial JS writes to `localStorage` so SPA callers can attach it to XHRs via a custom header (defaults to `X-Firewall-Challenge`).
- **Expires** after `metadata.default_expiration_time` seconds for the matched plugin (default `3600`).

## Minimum configuration

```yaml
challenge:
  provider: math                # 'math' is the built-in; or a FQCN that implements ChallengeProviderInterface
  secret: "${FIREWALL_SECRET}"  # REQUIRED. Long random string, ideally from an env var.
  cookie_name: fw_challenge_pass
  header_name: X-Firewall-Challenge
  path: /_firewall/challenge    # The URL the interstitial POSTs to

plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Asn"
    response: challenge
    weight: -10
    enable: true
    metadata:
      default_expiration_time: 3600   # Pass token TTL in seconds
    config:
      - "asn:AS14618"   # Show the challenge to AWS traffic
```

If any plugin uses `response: challenge`, `challenge.secret` is **required**. Startup fails fast with `ConfigurationException` when it is empty — the firewall will not silently fall back to plaintext tokens.

## Single-use solutions

A stateless provider verifies a solution purely from the posted payload, so the same payload keeps verifying until it expires. For a proof-of-work challenge that quietly defeats the point: an attacker solves one challenge and hands the payload to as many clients as they like, each minting its own IP-bound pass token, and the per-solve cost is amortised to nothing.

Providers can opt out of that by implementing `Kanopi\Firewall\Challenge\SingleUseSolutionInterface`, which hands the firewall an identifier for the solution in the current request. The firewall records it in the configured storage backend and refuses any later submission carrying the same identifier. `altcha` implements this; a solved payload is accepted exactly once.

Two consequences worth knowing:

- **The challenge flow now writes to storage.** Records are small (one per solved challenge) and expire on their own when the underlying challenge would have gone stale. With `InMemoryStorage` they do not survive the process, so use a shared backend if you serve challenges from more than one worker.
- **The check is read-then-write, not atomic.** Two submissions of the same solution arriving in the same instant can both succeed. This shrinks the reuse window from the full challenge lifetime to microseconds, which is the part that matters — the attack being closed is redistribution over seconds or minutes, not winning a race.

`math` deliberately does **not** implement it: its signed state is `answer|expiry`, and with only nine possible answers two visitors served in the same second routinely share one, so treating that value as single-use would reject legitimate solvers.

## Scoping tokens across instances

A pass token attests "this client solved *a* challenge" — so if two Firewall instances share a `challenge.secret`, they would accept each other's tokens without further scoping. That matters when the challenges differ in strength: a token earned on the trivial `math` challenge could otherwise be replayed against a route protected by `altcha`, and the weakest challenge in your deployment would set the effective security of every route that shares the secret.

Tokens therefore carry an `aud` claim, which defaults to the configured provider name and is covered by the signature. A `math` token will not verify against an `altcha` instance.

If you run **the same provider** in several places with the same secret — say a low-value public route and a sensitive admin area — the default audiences are identical, so set them apart explicitly:

```yaml
challenge:
  provider: altcha
  secret: "${FIREWALL_SECRET}"
  audience: admin-portal   # defaults to the provider name
```

The alternative is to give each instance its own `challenge.secret`, which isolates them just as effectively.

> **Upgrade note.** Pass tokens minted before the `aud` claim existed are rejected, because verification fails closed rather than treating a missing audience as a match. The visible effect is that everyone holding a live pass token is challenged once more after deploying. Tokens are short-lived (default one hour), so this clears on its own.

## Built-in providers

Two providers ship with the firewall — set `challenge.provider` to either short name:

=== "math"

    ![The built-in math challenge interstitial, showing the question "What is 2 + 7?" above an answer field and a Continue button](../assets/images/challenges/math-interstitial.png "The math provider's interstitial — no JavaScript bundle, no external requests")

    A single-digit addition question rendered server-side. Nothing loads from a
    third party, so it works under a restrictive CSP and adds no latency.

=== "altcha"

    ![The ALTCHA challenge interstitial, showing the widget in its "Verifying..." state above a disabled Continue button](../assets/images/challenges/altcha-interstitial.png "The ALTCHA widget while the browser brute-forces the proof-of-work — Continue stays disabled until it resolves")

    The ALTCHA widget solves a proof-of-work in the background and enables
    **Continue** on its own. The visitor clicks nothing; a bot pays CPU for
    every solve.

Both screenshots come from the [demo application](../guides/demo.md), which
serves each provider on its own route.

- **`math`** — asks "What is A + B?" with single-digit operands. Low-friction proof-of-effort, no JS bundle, no external script load. Defeats the laziest bots; trivial for a human.
- **`altcha`** — embeds the [ALTCHA](https://altcha.org/docs/v2/) v2 widget with a pre-computed challenge (no server round-trip to fetch one). The visitor's browser brute-forces `SHA-256(salt + N) == challenge`; the salt embeds an expiry and the challenge is HMAC-signed with `challenge.secret`, so the server stays stateless. Privacy-respecting, and imposes a per-solve CPU cost on bots. Solved challenges are single-use — see [Single-use solutions](#single-use-solutions).

  The widget script is pinned to an exact version and served with a Subresource Integrity digest. To self-host it, or to serve it from a host your CSP already allows, set both options — supplying `widget_src` without `widget_integrity` emits no `integrity` attribute, since a digest that does not match the bytes would block the script entirely:

  ```yaml
  challenge:
    provider: altcha
    provider_options:
      widget_src: /assets/altcha.min.js
      widget_integrity: 'sha384-…'   # openssl dgst -sha384 -binary altcha.min.js | openssl base64 -A
  ```

  The bundle is an ES module, so it is loaded with `<script type="module">`. If you host it yourself, keep that in mind: a classic script tag fails with `Unexpected token 'export'`.

For stronger bot resistance (Turnstile, hCaptcha, reCAPTCHA, etc.), implement `Kanopi\Firewall\Challenge\ChallengeProviderInterface` and set `challenge.provider` to its FQCN.

## Writing a custom provider

A provider owns both halves of the round-trip: rendering the interstitial, and verifying what comes back. Providers must be **stateless** — embed whatever you need to verify the answer in the interstitial itself (a hidden field, signed with the shared `TokenManager`) rather than storing a per-challenge record. That is what lets the firewall scale horizontally without a shared session store.

```php
<?php

namespace App\Firewall;

use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Challenge\TokenManager;
use Symfony\Component\HttpFoundation\Request;

class TurnstileProvider implements ChallengeProviderInterface
{
    // The factory passes the shared TokenManager to every provider. Use it
    // to sign your own per-challenge state; ignore it if you don't need to.
    public function __construct(private readonly TokenManager $tokenManager)
    {
    }

    public function getName(): string
    {
        return 'turnstile';
    }

    public function renderInterstitial(Request $request, array $context): string
    {
        // $context carries: submit_url, redirect_to, ttl, cookie_name, header_name.
        // Echo redirect_to and ttl back as hidden fields — the Firewall reads
        // them off the POST to size and target the pass token.
        return <<<HTML
        <!DOCTYPE html>
        <html lang="en"><body>
          <form method="post" action="{$context['submit_url']}">
            <div class="cf-turnstile" data-sitekey="YOUR_SITE_KEY"></div>
            <input type="hidden" name="redirect_to" value="{$context['redirect_to']}">
            <input type="hidden" name="ttl" value="{$context['ttl']}">
            <button type="submit">Continue</button>
          </form>
          <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
        </body></html>
        HTML;
    }

    public function verifySolution(Request $request): bool
    {
        $token = (string) $request->request->get('cf-turnstile-response', '');

        // Verify server-side against the provider's siteverify endpoint.
        // Return FALSE on any failure — never throw.
        return $token !== '' && $this->verifyWithCloudflare($token, $request);
    }
}
```

```yaml
challenge:
  provider: "App\\Firewall\\TurnstileProvider"
  secret: "${FIREWALL_SECRET}"
  path: /_firewall/challenge
```

Requirements and gotchas:

- **Escape everything you interpolate.** `redirect_to` originates from the request URI. The built-in `MathChallengeProvider` runs every substitution through `htmlspecialchars()`; do the same.
- **Echo back `redirect_to` and `ttl`** as form fields named exactly that. The Firewall reads them from the POST to decide where to send the visitor and how long to mint the pass token for. Omit them and you get `/` and 3600s.
- **`verifySolution()` must never throw.** It runs on attacker-controlled input; return `false` for anything you don't like.
- **Register via FQCN**, not a short name. `challenge.provider` only resolves `math` as a built-in; everything else must be a loadable class implementing the interface, or `create()` throws `ConfigurationException`.
- **The constructor signature is fixed** — `ChallengeProviderFactory` always calls `new $class($tokenManager)`. Read any further configuration from your own environment or constants.
- Use `$this->tokenManager->sign()` / `verifySignature()` if you need tamper-proof state in the form. You do **not** need to mint the pass token — the Firewall does that once `verifySolution()` returns `true`.

## How dispatch interacts with allow / block

| Visitor state                          | Result                                       |
|----------------------------------------|----------------------------------------------|
| Matched by an `allow` plugin           | Allowed (challenge skipped).                 |
| Holds a valid pass token + matches `challenge` | Allowed (challenge bucket skipped).  |
| No token, matches a `challenge` plugin | Interstitial served; original URL is remembered for the post-success redirect. |
| Matches a `block` plugin               | Blocked, even if a valid pass token is held. |
