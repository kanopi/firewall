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
 * Built-in arithmetic challenge.
 *
 * Renders "What is A + B?" where A and B are small random integers. The
 * expected answer is signed into a hidden form field (`challenge_state`)
 * with a short embedded expiry, so the server stays stateless between
 * the render and verify steps — there is no per-challenge record to
 * store or look up.
 *
 * Wire format of the signed state: `answer|exp.signature`
 *   answer    = the expected integer answer (server-side truth)
 *   exp       = unix timestamp after which the challenge is stale
 *   signature = HMAC over "answer|exp" via TokenManager::sign()
 *
 * The challenge_state lifetime is short (5 minutes) — long enough that a
 * legitimate visitor can read and type, short enough that a precomputed
 * answer harvested from a bot farm goes stale before it can be replayed
 * at scale.
 *
 * This is deliberately a low-friction proof-of-effort, not a CAPTCHA.
 * Operators who need stronger bot resistance can implement
 * ChallengeProviderInterface against Turnstile/hCaptcha/etc.
 */
final class MathChallengeProvider implements ChallengeProviderInterface
{
    /**
     * Form field that carries the signed `answer|exp.signature` payload
     * from render → verify.
     */
    public const STATE_FIELD = 'challenge_state';

    /**
     * Form field that carries the visitor's typed answer.
     */
    public const ANSWER_FIELD = 'challenge_answer';

    /**
     * Form field carrying the post-success redirect target.
     */
    public const REDIRECT_FIELD = 'redirect_to';

    /**
     * Form field carrying the per-plugin TTL (so the Firewall knows how
     * long to mint the resulting pass token for).
     */
    public const TTL_FIELD = 'ttl';

    private const STATE_LIFETIME = 300;

    public function __construct(private TokenManager $tokenManager)
    {
    }

    public function getName(): string
    {
        return 'math';
    }

    public function renderInterstitial(Request $request, array $context): string
    {
        $a = random_int(1, 9);
        $b = random_int(1, 9);
        $expected = (string) ($a + $b);
        $exp = time() + self::STATE_LIFETIME;

        $stateData = $expected . '|' . $exp;
        $signedState = $stateData . '.' . $this->tokenManager->sign($stateData);

        return $this->renderTemplate([
            'question' => sprintf('What is %d + %d?', $a, $b),
            'submit_url' => $context['submit_url'] ?? '',
            'redirect_to' => $context['redirect_to'] ?? '/',
            'ttl' => $context['ttl'] ?? '3600',
            'cookie_name' => $context['cookie_name'] ?? '',
            'header_name' => $context['header_name'] ?? '',
            'state' => $signedState,
            'state_field' => self::STATE_FIELD,
            'answer_field' => self::ANSWER_FIELD,
            'redirect_field' => self::REDIRECT_FIELD,
            'ttl_field' => self::TTL_FIELD,
        ]);
    }

    public function verifySolution(Request $request): bool
    {
        $state = (string) $request->request->get(self::STATE_FIELD, '');
        $answer = trim((string) $request->request->get(self::ANSWER_FIELD, ''));

        if ($state === '' || $answer === '' || substr_count($state, '.') !== 1) {
            return false;
        }

        [$data, $signature] = explode('.', $state, 2);
        if (!$this->tokenManager->verifySignature($data, $signature)) {
            return false;
        }

        if (substr_count($data, '|') !== 1) {
            return false;
        }

        [$expected, $exp] = explode('|', $data, 2);

        if (!ctype_digit($exp) || (int) $exp <= time()) {
            return false;
        }

        return hash_equals($expected, $answer);
    }

    /**
     * Inline HTML + JS template.
     *
     * Every {{key}} substitution is HTML-escaped — `question` is the only
     * server-generated text, but we treat the rest defensively in case a
     * future caller passes a user-controlled `redirect_to`.
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
    label { display: block; font-weight: 600; margin-bottom: 0.5rem; }
    input[type="text"] { width: 100%; padding: 0.6rem 0.75rem; font-size: 1rem; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
    button { margin-top: 1rem; width: 100%; padding: 0.65rem 1rem; font-size: 1rem; background: #1f6feb; color: #fff; border: 0; border-radius: 4px; cursor: pointer; }
    button:hover { background: #1858c4; }
    .error { color: #b42318; margin-top: 0.75rem; font-size: 0.9rem; display: none; }
    .error.visible { display: block; }
  </style>
</head>
<body>
  <main class="card">
    <h1>Quick verification</h1>
    <p>Please answer the question below to continue.</p>
    <form id="challenge-form" method="post" action="{$e['submit_url']}">
      <label for="answer">{$e['question']}</label>
      <input type="text" id="answer" name="{$e['answer_field']}" inputmode="numeric" autocomplete="off" autofocus required>
      <input type="hidden" name="{$e['state_field']}" value="{$e['state']}">
      <input type="hidden" name="{$e['redirect_field']}" value="{$e['redirect_to']}">
      <input type="hidden" name="{$e['ttl_field']}" value="{$e['ttl']}">
      <button type="submit">Continue</button>
      <div id="error" class="error" role="alert">Incorrect answer. Please try again.</div>
    </form>
  </main>
  <script>
    (function () {
      var form = document.getElementById('challenge-form');
      var err = document.getElementById('error');
      var cookieName = "{$e['cookie_name']}";
      var headerName = "{$e['header_name']}";
      var redirectTo = "{$e['redirect_to']}";

      form.addEventListener('submit', function (event) {
        event.preventDefault();
        err.classList.remove('visible');

        var data = new FormData(form);
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
