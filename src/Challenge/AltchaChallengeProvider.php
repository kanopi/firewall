<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Challenge;

use Kanopi\Firewall\Traits\RequestFieldTrait;
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
 * The salt embeds an `?expires=<unix>` query string so a solution goes
 * stale shortly after it is issued. The signature is an HMAC over the
 * challenge value via TokenManager::sign(), so a tampered challenge or
 * salt fails verification even with a valid PoW.
 *
 * Expiry alone does not make the work non-reusable, though: within the
 * challenge lifetime the same solved payload verifies every time it is
 * submitted. This provider therefore implements SingleUseSolutionInterface
 * so `Firewall` records each solved challenge and rejects the second
 * submission — without that, one solve could be redistributed to any
 * number of clients, each minting its own pass token, and the per-solve
 * cost below would be amortised to nothing.
 *
 * Compared to MathChallengeProvider this trades a tiny bit of CPU on the
 * visitor's device (50-150 ms typical at the default maxnumber) for a
 * fully automated flow — no typing required — and a per-solve cost that,
 * because solutions are single-use, actually has to be paid per client.
 */
final class AltchaChallengeProvider implements ChallengeProviderInterface, SingleUseSolutionInterface
{
    use RequestFieldTrait;

    /**
     * Form field that carries the base64-encoded solution payload posted
     * back from the widget. Name is fixed by the ALTCHA widget itself.
     */
    public const PAYLOAD_FIELD = 'altcha';

    private const ALGORITHM = 'SHA-256';

    private const MAXNUMBER = 100000;

    private const CHALLENGE_LIFETIME = 300;

    /**
     * Default widget bundle, pinned to an exact version.
     *
     * @see self::DEFAULT_WIDGET_INTEGRITY for the matching SRI digest.
     */
    public const DEFAULT_WIDGET_SRC = 'https://cdn.jsdelivr.net/npm/altcha@2.3.0/dist/altcha.min.js';

    /**
     * Subresource Integrity digest for DEFAULT_WIDGET_SRC.
     *
     * Must be regenerated whenever DEFAULT_WIDGET_SRC changes:
     *   curl -sL <url> | openssl dgst -sha384 -binary | openssl base64 -A
     */
    public const DEFAULT_WIDGET_INTEGRITY =
        'sha384-8I1KL049hNSwGKuCu/6NlGM1rfkVTfw/5bVzUFNvxO3XLV3isCJR1s5pTyuE2Zuo';

    /**
     * Widget bundle URL actually emitted into the interstitial.
     */
    private readonly string $widgetSrc;

    /**
     * SRI digest emitted alongside the bundle, or '' to emit none.
     */
    private readonly string $widgetIntegrity;

    /**
     * Constructs a new AltchaChallengeProvider object.
     *
     * @param TokenManager $tokenManager
     *   Shared HMAC manager. Signs the per-challenge value embedded in the
     *   widget, which is what keeps this provider stateless — the expected
     *   challenge never has to be stored server-side.
     * @param array<string, mixed> $options
     *   Provider options from `challenge.provider_options`:
     *     - widget_src:       URL of the ALTCHA widget bundle. Override to
     *                         self-host the script or to serve it from a
     *                         CDN your CSP already allows.
     *     - widget_integrity: SRI digest for that bundle. Defaults to the
     *                         digest of the pinned default; overriding
     *                         `widget_src` without also supplying this
     *                         emits no `integrity` attribute, because a
     *                         stale digest would block the script outright.
     */
    public function __construct(private readonly TokenManager $tokenManager, array $options = [])
    {
        $src = trim((string) ($options['widget_src'] ?? ''));
        $integrity = trim((string) ($options['widget_integrity'] ?? ''));

        $this->widgetSrc = $src !== '' ? $src : self::DEFAULT_WIDGET_SRC;

        if ($integrity !== '') {
            $this->widgetIntegrity = $integrity;
        } else {
            // Only the pinned default has a digest we can vouch for.
            $this->widgetIntegrity = $src === '' ? self::DEFAULT_WIDGET_INTEGRITY : '';
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'altcha';
    }

    /**
     * {@inheritdoc}
     */
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

        $challengeAttr = InterstitialRenderer::escapeHtml($challengeJson);
        $payloadField = InterstitialRenderer::escapeHtml(self::PAYLOAD_FIELD);
        $widgetSrc = InterstitialRenderer::escapeHtml($this->widgetSrc);

        // SRI only means anything alongside a CORS request, hence
        // crossorigin — without it the browser cannot verify the digest.
        $integrityAttr = '';
        if ($this->widgetIntegrity !== '') {
            $integrityAttr = sprintf(
                ' integrity="%s" crossorigin="anonymous"',
                InterstitialRenderer::escapeHtml($this->widgetIntegrity)
            );
        }

        return InterstitialRenderer::render([
            'intro' => 'Please complete the check below to continue.',
            'extra_styles' => '    altcha-widget { display: block; margin-bottom: 1rem; }'
                . "\n" . '    button:disabled { background: #9bb8e6; cursor: not-allowed; }',
            // The official ALTCHA distribution is an ES module — a classic
            // <script> tag fails with "Unexpected token 'export'".
            'extra_head' => sprintf('  <script type="module" src="%s"%s async defer></script>', $widgetSrc, $integrityAttr),
            'form_fields' => <<<FIELDS
      <altcha-widget challengejson="{$challengeAttr}" auto="onload" hidefooter></altcha-widget>
FIELDS,
            // The widget enables the button once it has solved the proof of
            // work, so the visitor cannot submit an empty payload.
            'submit_disabled' => true,
            'error_message' => 'Verification failed. Please try again.',
            'submit_guard' => <<<GUARD
        if (!data.get('{$payloadField}')) {
          err.classList.add('visible');
          return;
        }

GUARD,
            // A solved ALTCHA challenge is spent by the attempt that posts
            // it: `SingleUseSolutionInterface` has the firewall record it,
            // and every later submission carrying it is refused. So without
            // this, clicking Continue again re-posts the same dead payload
            // and can never succeed — one failure locks the visitor out of
            // the page until they think to reload it.
            //
            // Turnstile recovers by resetting its widget, which fetches a
            // fresh token from Cloudflare. That does not work here: this
            // provider embeds the challenge in the page as `challengejson`
            // precisely to avoid a round trip for one, so a reset re-solves
            // the *same* challenge and produces the same spent payload. A
            // new challenge only exists in a new render, which means going
            // back for the page.
            //
            // `redirectTo` is where the visitor was heading, already
            // sanitized by Firewall::sanitizeRedirect(). Navigating there
            // trips the same challenge plugin and serves a fresh
            // interstitial. `replace()` rather than `reload()`: reload would
            // re-submit the original request if it was a POST, and replace
            // keeps the dead page out of the back button. The pause is there
            // so the message below can actually be read.
            'submit_failure' => <<<'FAILURE'
        submit.disabled = true;
        err.textContent = 'That verification could not be used. Fetching a new one…';
        window.setTimeout(function () { window.location.replace(redirectTo); }, 2000);
FAILURE,
            'extra_script' => <<<'SCRIPT'
      var widget = document.querySelector('altcha-widget');
      if (widget) {
        widget.addEventListener('verified', function () { submit.disabled = false; });
        widget.addEventListener('expired', function () { submit.disabled = true; });
      }

SCRIPT,
            'submit_url' => $context['submit_url'] ?? '',
            'redirect_to' => $context['redirect_to'] ?? '/',
            'ttl' => $context['ttl'] ?? '3600',
            'header_name' => $context['header_name'] ?? '',
            'redirect_field' => self::REDIRECT_FIELD,
            'ttl_field' => self::TTL_FIELD,
            'provider_field' => self::PROVIDER_FIELD,
            'provider_token' => $context['provider_token'] ?? '',
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function verifySolution(Request $request): bool
    {
        return $this->validate($request) !== null;
    }

    /**
     * {@inheritdoc}
     *
     * The `challenge` value is the identifier: it is a SHA-256 over the
     * per-render salt, so it is unique to one issued challenge, and it is
     * the exact value covered by the HMAC signature — an attacker cannot
     * vary it to dodge the consumed-solution record without invalidating
     * the signature.
     */
    public function getSolutionReceipt(Request $request): ?array
    {
        $validated = $this->validate($request);
        if ($validated === null) {
            return null;
        }

        return ['id' => $validated['challenge'], 'expires' => $validated['expires']];
    }

    /**
     * Decode and fully validate the posted solution.
     *
     * Shared by verifySolution() and getSolutionReceipt() so the two can
     * never disagree about whether a payload is acceptable.
     *
     * @return array{challenge: string, expires: int}|null
     *   The verified challenge value and its expiry, or NULL if the
     *   payload is malformed, stale, unsigned, or does not solve the
     *   proof of work.
     */
    private function validate(Request $request): ?array
    {
        // Read through the raw bag: an array-valued `altcha` field would make
        // InputBag::get() throw, and neither caller may (#130).
        $encoded = $this->postedString($request, self::PAYLOAD_FIELD);
        if ($encoded === '') {
            return null;
        }

        $json = base64_decode($encoded, true);
        if ($json === false) {
            return null;
        }

        $payload = json_decode($json, true);
        if (!is_array($payload)) {
            return null;
        }

        foreach (['algorithm', 'challenge', 'number', 'salt', 'signature'] as $key) {
            if (!isset($payload[$key]) || !is_scalar($payload[$key])) {
                return null;
            }
        }

        if ($payload['algorithm'] !== self::ALGORITHM) {
            return null;
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
            return null;
        }

        $expires = $this->parseExpires($salt);
        if ($expires === null || $expires <= time()) {
            return null;
        }

        if (!hash_equals($challenge, hash('sha256', $salt . $number))) {
            return null;
        }

        if (!$this->tokenManager->verifySignature($challenge, $signature)) {
            return null;
        }

        return ['challenge' => $challenge, 'expires' => $expires];
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
}
