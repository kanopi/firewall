<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Challenge;

use Symfony\Component\HttpFoundation\Request;

/**
 * Built-in ALTCHA proof-of-work challenge.
 *
 * Embeds the ALTCHA widget pre-loaded with a server-issued challenge so
 * the page never round-trips back for a challenge JSON — the server stays
 * stateless between render and verify. The visitor's browser brute-forces
 * `number` such that `SHA-256(salt + number) == challenge`, the widget
 * posts the base64-encoded solution back as the `altcha` field, and
 * verifySolution() re-runs the hash plus an HMAC check on the challenge
 * value.
 *
 * Wire format (per https://altcha.org/docs/v2/):
 *   server → client (rendered into the widget):
 *     {algorithm, challenge, maxnumber, salt, signature}
 *   client → server (base64-encoded JSON in the `altcha` field):
 *     {algorithm, challenge, number, salt, signature}
 *
 * The salt embeds an `?expires=<unix>` query string so a precomputed
 * solution goes stale before it can be replayed at scale. The signature
 * is an HMAC over the challenge value via TokenManager::sign(), so a
 * tampered challenge or salt fails verification even with a valid PoW.
 *
 * Compared to MathChallengeProvider this trades a tiny bit of CPU on the
 * visitor's device (50-150 ms typical at the default maxnumber) for a
 * fully automated flow — no typing required — and a measurable cost per
 * solve, which makes mass single-shot bot attacks less attractive.
 */
final class AltchaChallengeProvider implements ChallengeProviderInterface
{
    /**
     * Form field that carries the base64-encoded solution payload posted
     * back from the widget. Name is fixed by the ALTCHA widget itself.
     */
    public const PAYLOAD_FIELD = 'altcha';

    /**
     * Form field carrying the post-success redirect target. Same name as
     * MathChallengeProvider — `Firewall::handleChallengeSubmission` reads
     * a shared field name regardless of which provider is wired up.
     */
    public const REDIRECT_FIELD = 'redirect_to';

    /**
     * Form field carrying the per-plugin TTL.
     */
    public const TTL_FIELD = 'ttl';

    private const ALGORITHM = 'SHA-256';
    private const MAXNUMBER = 100000;
    private const CHALLENGE_LIFETIME = 300;
    private const WIDGET_SRC = 'https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js';

    public function __construct(private readonly TokenManager $tokenManager)
    {
    }

    public function getName(): string
    {
        return 'altcha';
    }

    public function renderInterstitial(Request $request, array $context): string
    {
        $salt = bin2hex(random_bytes(12)) . '?expires=' . (time() + self::CHALLENGE_LIFETIME);
        $number = random_int(1, self::MAXNUMBER);
        $challenge = hash('sha256', $salt . $number);
        $signature = $this->tokenManager->sign($challenge);

        $challengeJson = (string) json_encode([
            'algorithm' => self::ALGORITHM,
            'challenge' => $challenge,
            'maxnumber' => self::MAXNUMBER,
            'salt' => $salt,
            'signature' => $signature,
        ]);

        return $this->renderTemplate([
            'challenge_json' => $challengeJson,
            'submit_url' => $context['submit_url'] ?? '',
            'redirect_to' => $context['redirect_to'] ?? '/',
            'ttl' => $context['ttl'] ?? '3600',
            'cookie_name' => $context['cookie_name'] ?? '',
            'header_name' => $context['header_name'] ?? '',
            'payload_field' => self::PAYLOAD_FIELD,
            'redirect_field' => self::REDIRECT_FIELD,
            'ttl_field' => self::TTL_FIELD,
            'widget_src' => self::WIDGET_SRC,
        ]);
    }

    public function verifySolution(Request $request): bool
    {
        $encoded = trim((string) $request->request->get(self::PAYLOAD_FIELD, ''));
        if ($encoded === '') {
            return false;
        }

        $json = base64_decode($encoded, true);
        if ($json === false) {
            return false;
        }

        $payload = json_decode($json, true);
        if (!is_array($payload)) {
            return false;
        }

        foreach (['algorithm', 'challenge', 'number', 'salt', 'signature'] as $key) {
            if (!isset($payload[$key]) || !is_scalar($payload[$key])) {
                return false;
            }
        }

        if ($payload['algorithm'] !== self::ALGORITHM) {
            return false;
        }

        $salt = (string) $payload['salt'];
        $challenge = (string) $payload['challenge'];
        $signature = (string) $payload['signature'];
        $rawNumber = $payload['number'];

        if (is_int($rawNumber)) {
            $number = $rawNumber;
        } elseif (is_string($rawNumber) && ctype_digit($rawNumber)) {
            $number = (int) $rawNumber;
        } else {
            return false;
        }

        $expires = $this->parseExpires($salt);
        if ($expires === null || $expires <= time()) {
            return false;
        }

        if (!hash_equals($challenge, hash('sha256', $salt . $number))) {
            return false;
        }

        return $this->tokenManager->verifySignature($challenge, $signature);
    }

    /**
     * Pull the `expires` value out of the salt's query string. Returns
     * null if absent or not a valid unix timestamp.
     */
    private function parseExpires(string $salt): ?int
    {
        $pos = strpos($salt, '?');
        if ($pos === false) {
            return null;
        }

        parse_str(substr($salt, $pos + 1), $params);
        if (!isset($params['expires']) || !is_string($params['expires']) || !ctype_digit($params['expires'])) {
            return null;
        }

        return (int) $params['expires'];
    }

    /**
     * Inline HTML + JS template.
     *
     * Every {{key}} substitution is HTML-escaped. The widget script is
     * loaded from the official CDN; if that's blocked by your CSP you can
     * subclass and override WIDGET_SRC, or implement
     * ChallengeProviderInterface directly against a self-hosted bundle.
     *
     * @param array<string, string|int> $vars
     */
    private function renderTemplate(array $vars): string
    {
        $escape = static fn(string|int $v): string => htmlspecialchars(
            (string) $v,
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8'
        );

        $e = array_map($escape, $vars);

        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Verification required</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: #f5f6f8; color: #1a1a1a; margin: 0; display: flex; min-height: 100vh; align-items: center; justify-content: center; }
    .card { background: #fff; padding: 2rem 2.5rem; border-radius: 8px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); max-width: 28rem; width: 90%; }
    h1 { font-size: 1.25rem; margin: 0 0 0.75rem; }
    p { margin: 0 0 1.25rem; color: #555; }
    altcha-widget { display: block; margin-bottom: 1rem; }
    button { width: 100%; padding: 0.65rem 1rem; font-size: 1rem; background: #1f6feb; color: #fff; border: 0; border-radius: 4px; cursor: pointer; }
    button:disabled { background: #9bb8e6; cursor: not-allowed; }
    button:not(:disabled):hover { background: #1858c4; }
    .error { color: #b42318; margin-top: 0.75rem; font-size: 0.9rem; display: none; }
    .error.visible { display: block; }
  </style>
</head>
<body>
  <main class="card">
    <h1>Quick verification</h1>
    <p>Please complete the check below to continue.</p>
    <form id="challenge-form" method="post" action="{$e['submit_url']}">
      <altcha-widget challengejson="{$e['challenge_json']}" auto="onload" hidefooter></altcha-widget>
      <input type="hidden" name="{$e['redirect_field']}" value="{$e['redirect_to']}">
      <input type="hidden" name="{$e['ttl_field']}" value="{$e['ttl']}">
      <button type="submit" id="submit" disabled>Continue</button>
      <div id="error" class="error" role="alert">Verification failed. Please try again.</div>
    </form>
  </main>
  <script type="module" src="{$e['widget_src']}" async defer></script>
  <script>
    (function () {
      var form = document.getElementById('challenge-form');
      var err = document.getElementById('error');
      var submit = document.getElementById('submit');
      var widget = document.querySelector('altcha-widget');
      var cookieName = "{$e['cookie_name']}";
      var headerName = "{$e['header_name']}";
      var redirectTo = "{$e['redirect_to']}";

      if (widget) {
        widget.addEventListener('verified', function () { submit.disabled = false; });
        widget.addEventListener('expired', function () { submit.disabled = true; });
      }

      form.addEventListener('submit', function (event) {
        event.preventDefault();
        err.classList.remove('visible');

        var data = new FormData(form);
        if (!data.get('{$e['payload_field']}')) {
          err.classList.add('visible');
          return;
        }

        fetch(form.action, {
          method: 'POST',
          body: data,
          headers: { 'Accept': 'application/json' },
          credentials: 'same-origin'
        }).then(function (resp) {
          return resp.json().then(function (body) { return { ok: resp.ok, body: body }; });
        }).then(function (result) {
          if (!result.ok || !result.body || !result.body.token) {
            err.classList.add('visible');
            return;
          }
          try {
            if (headerName) {
              localStorage.setItem('firewall.' + headerName, result.body.token);
            }
          } catch (e) { /* localStorage blocked — cookie still works */ }
          window.location.href = result.body.redirect || redirectTo;
        }).catch(function () {
          err.classList.add('visible');
        });
      });
    })();
  </script>
</body>
</html>
HTML;
    }
}
