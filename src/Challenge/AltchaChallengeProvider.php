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
}
