<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Challenge;

/**
 * Renders the shared challenge interstitial document.
 *
 * Both built-in providers serve the same page: a centered card, a form
 * that POSTs to the challenge endpoint, hidden `redirect_to` / `ttl`
 * fields, a submit button, and an error region. Only the challenge
 * control itself differs — a text input for the math provider, a widget
 * element for ALTCHA.
 *
 * Keeping one copy of the document means the submit JS (and the escaping
 * rules it depends on) live in exactly one place. Providers supply the
 * pieces that are genuinely theirs via the `$parts` array.
 */
final class InterstitialRenderer
{
    /**
     * Escape a value for interpolation into HTML text or an attribute.
     */
    public static function escapeHtml(string|int $value): string
    {
        return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * Encode a value as a complete JavaScript string literal, quotes included.
     *
     * HTML entity escaping is NOT valid inside a `<script>` block — the
     * browser does not decode entities there, and `htmlspecialchars()`
     * leaves backslashes untouched, so a value ending in `\` escapes the
     * closing quote and produces a SyntaxError that kills the whole
     * script. That matters: the ALTCHA submit button ships disabled and
     * is only enabled by this script, so a parse error locks the visitor
     * out of the page with no fallback.
     *
     * `json_encode()` with the HEX flags is the correct tool — it escapes
     * backslashes, quotes and `<` / `>` / `&`, so neither the string
     * literal nor the enclosing `</script>` can be broken out of.
     */
    public static function escapeJs(string|int $value): string
    {
        $encoded = json_encode(
            (string) $value,
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_INVALID_UTF8_SUBSTITUTE
        );

        // Defensive: never emit an empty expression, which would itself be
        // a syntax error. json_encode() should not fail given the
        // substitution flag, but the fallback costs nothing.
        return $encoded === false ? '""' : $encoded;
    }

    /**
     * Build the interstitial document.
     *
     * `form_fields`, `extra_script`, `extra_head`, `extra_styles` and
     * `submit_guard` are injected verbatim — the calling provider owns
     * escaping anything it interpolates into them. Every other value is
     * escaped here.
     *
     * @param array{
     *   intro: string,
     *   extra_styles: string,
     *   extra_head: string,
     *   form_fields: string,
     *   submit_disabled: bool,
     *   error_message: string,
     *   submit_guard: string,
     *   extra_script: string,
     *   submit_url: string|int,
     *   redirect_to: string|int,
     *   ttl: string|int,
     *   header_name: string|int,
     *   redirect_field: string|int,
     *   ttl_field: string|int
     * } $parts
     *   Provider-supplied document pieces.
     */
    public static function render(array $parts): string
    {
        $submitUrl = self::escapeHtml($parts['submit_url']);
        $redirectTo = self::escapeHtml($parts['redirect_to']);
        $ttl = self::escapeHtml($parts['ttl']);
        $redirectField = self::escapeHtml($parts['redirect_field']);
        $ttlField = self::escapeHtml($parts['ttl_field']);

        // Script-context values need JS literal encoding, not HTML escaping.
        $headerNameJs = self::escapeJs($parts['header_name']);
        $redirectToJs = self::escapeJs($parts['redirect_to']);

        $intro = $parts['intro'];
        $extraStyles = $parts['extra_styles'];
        $extraHead = $parts['extra_head'];
        $formFields = $parts['form_fields'];
        $errorMessage = $parts['error_message'];
        $submitGuard = $parts['submit_guard'];
        $extraScript = $parts['extra_script'];
        $disabled = $parts['submit_disabled'] ? ' disabled' : '';

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
    button { width: 100%; padding: 0.65rem 1rem; font-size: 1rem; background: #1f6feb; color: #fff; border: 0; border-radius: 4px; cursor: pointer; }
    button:not(:disabled):hover { background: #1858c4; }
    .error { color: #b42318; margin-top: 0.75rem; font-size: 0.9rem; display: none; }
    .error.visible { display: block; }
{$extraStyles}
  </style>
{$extraHead}
</head>
<body>
  <main class="card">
    <h1>Quick verification</h1>
    <p>{$intro}</p>
    <form id="challenge-form" method="post" action="{$submitUrl}">
{$formFields}
      <input type="hidden" name="{$redirectField}" value="{$redirectTo}">
      <input type="hidden" name="{$ttlField}" value="{$ttl}">
      <button type="submit" id="submit"{$disabled}>Continue</button>
      <div id="error" class="error" role="alert">{$errorMessage}</div>
    </form>
  </main>
  <script>
    (function () {
      var form = document.getElementById('challenge-form');
      var err = document.getElementById('error');
      var submit = document.getElementById('submit');
      var headerName = {$headerNameJs};
      var redirectTo = {$redirectToJs};
{$extraScript}
      form.addEventListener('submit', function (event) {
        event.preventDefault();
        err.classList.remove('visible');

        var data = new FormData(form);
{$submitGuard}
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
