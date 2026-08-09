<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Challenge;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Traits\RequestFieldTrait;
use Symfony\Component\HttpFoundation\Request;

/**
 * Built-in Cloudflare Turnstile challenge.
 *
 * Renders the Turnstile widget, then verifies the token it produces against
 * Cloudflare's siteverify API.
 *
 * Unlike the other built-in providers this one is **not** self-contained.
 * `MathChallengeProvider` re-checks an HMAC it signed itself and
 * `AltchaChallengeProvider` re-runs a hash locally, so both decide validity
 * with nothing but the posted payload and the shared secret. A
 * `cf-turnstile-response` token is an opaque artifact minted by Cloudflare;
 * there is no published format or key that would let it be verified offline.
 * Deciding whether it is genuine therefore costs one server-to-server round
 * trip on the challenge POST — not on ordinary requests, which never reach
 * this class.
 *
 * Wire format (per https://developers.cloudflare.com/turnstile/):
 *   server → client: the widget script plus a `data-sitekey` element.
 *   client → server: the widget writes an opaque token into the
 *                    `cf-turnstile-response` form field.
 *   server → Cloudflare: POST {secret, response, remoteip?} to siteverify.
 *   Cloudflare → server: {success, challenge_ts, hostname, error-codes}.
 *
 * Replay is handled at the source: Cloudflare returns `timeout-or-duplicate`
 * for a token that has already been validated, so a solve cannot be
 * redistributed to other clients. That is why this provider — unlike
 * `AltchaChallengeProvider` — does not need `SingleUseSolutionInterface` or
 * any storage-backed record of consumed solutions.
 *
 * Trade-offs worth knowing before choosing this provider over `math` or
 * `altcha`:
 *
 *   - It depends on a third party being reachable from both the visitor's
 *     browser and this server. A visitor whose network blocks
 *     `challenges.cloudflare.com` cannot pass, and when siteverify is
 *     unreachable this provider fails closed by default (see `on_error`).
 *   - No Subresource Integrity. Cloudflare serves the widget from an
 *     unversioned, mutable URL, so a pinned digest would break on their
 *     next deploy — `AltchaChallengeProvider` can pin an exact version and
 *     an SRI hash, this cannot.
 *   - Operators need a Content-Security-Policy that permits
 *     `https://challenges.cloudflare.com` in both `script-src` and
 *     `frame-src`.
 */
final class TurnstileChallengeProvider implements ChallengeProviderInterface
{
    use RequestFieldTrait;

    /**
     * Form field carrying the widget's token.
     *
     * Fixed by Turnstile's implicit rendering mode, which injects a hidden
     * input under this name into the enclosing form.
     */
    public const PAYLOAD_FIELD = 'cf-turnstile-response';

    /**
     * Cloudflare's server-side verification endpoint.
     */
    public const SITEVERIFY_ENDPOINT = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

    /**
     * Widget bundle emitted into the interstitial by default.
     *
     * Deliberately unversioned: Cloudflare publishes no pinned URL, and the
     * unpinned one is what they support. See the class docblock on why that
     * rules out Subresource Integrity here.
     */
    public const DEFAULT_WIDGET_SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js';

    /**
     * Seconds to wait on siteverify before giving up.
     *
     * Short by design — this runs inside a request the visitor is waiting
     * on, and a slow answer is worth less than a fast failure handled by
     * `on_error`.
     */
    private const DEFAULT_TIMEOUT = 2;

    /**
     * Ceiling for the configurable timeout.
     */
    private const MAX_TIMEOUT = 10;

    /**
     * Longest token accepted before the request is refused unsent.
     *
     * Cloudflare documents tokens as up to 2048 bytes; anything longer did
     * not come from the widget, so there is nothing to be gained by paying
     * a round trip to be told so.
     */
    private const MAX_TOKEN_LENGTH = 2048;

    /**
     * Widget colour themes Turnstile accepts.
     *
     * @var array<int, string>
     */
    private const THEMES = ['auto', 'light', 'dark'];

    /**
     * Error codes that mean this firewall is misconfigured, not that the
     * visitor failed. Logged at `error` because every visitor will fail
     * until an operator fixes the configuration.
     *
     * @var array<int, string>
     */
    private const CONFIG_ERROR_CODES = ['missing-input-secret', 'invalid-input-secret', 'bad-request'];

    /**
     * Error codes Cloudflare documents as retryable. Treated as a transport
     * failure so `on_error` decides, rather than as a verdict on the token.
     *
     * @var array<int, string>
     */
    private const RETRYABLE_ERROR_CODES = ['internal-error'];

    /**
     * Public key rendered into the widget.
     */
    private readonly string $siteKey;

    /**
     * Private key sent to siteverify. Never rendered, never logged.
     */
    private readonly string $secretKey;

    /**
     * Widget bundle URL actually emitted.
     */
    private readonly string $widgetSrc;

    /**
     * Widget colour theme.
     */
    private readonly string $theme;

    /**
     * siteverify timeout in seconds.
     */
    private readonly int $timeout;

    /**
     * Whether an unreachable siteverify lets the visitor through.
     */
    private readonly bool $allowOnError;

    /**
     * Whether the visitor's IP is forwarded to Cloudflare.
     */
    private readonly bool $sendRemoteIp;

    /**
     * Constructs a new TurnstileChallengeProvider object.
     *
     * Takes no `TokenManager`, unlike the other built-in providers: there is
     * no per-challenge state of ours to sign, because the only thing that
     * has to survive from render to verify is Cloudflare's own token.
     * `ChallengeProviderFactory` matches constructor parameters by declared
     * type, so declining it is enough to not be handed one.
     *
     * @param array<string, mixed> $options
     *   Provider options from `challenge.provider_options`:
     *     - site_key:      REQUIRED. Turnstile site key (public).
     *     - secret_key:    REQUIRED. Turnstile secret key (private).
     *     - widget_src:    Override the widget bundle URL, e.g. to serve it
     *                      through a first-party proxy your CSP allows.
     *     - theme:         `auto` (default), `light` or `dark`.
     *     - timeout:       siteverify timeout in seconds, 1-10, default 2.
     *     - on_error:      `block` (default) or `allow` — what happens when
     *                      siteverify cannot be reached. See verifySolution().
     *     - send_remoteip: Forward the client IP to Cloudflare. Default
     *                      FALSE; see fetch() for why that is not the
     *                      obvious choice it looks like.
     *
     * @throws ConfigurationException
     *   When `site_key` or `secret_key` is missing or empty. Failing at
     *   startup is the point: the alternative is a firewall that renders a
     *   widget every visitor is guaranteed to fail.
     */
    public function __construct(array $options = [])
    {
        $this->siteKey = $this->requireOption($options, 'site_key');
        $this->secretKey = $this->requireOption($options, 'secret_key');

        $widgetSrc = trim((string) ($options['widget_src'] ?? ''));
        $this->widgetSrc = $widgetSrc !== '' ? $widgetSrc : self::DEFAULT_WIDGET_SRC;

        $theme = strtolower(trim((string) ($options['theme'] ?? '')));
        $this->theme = in_array($theme, self::THEMES, true) ? $theme : 'auto';

        $timeout = (int) ($options['timeout'] ?? self::DEFAULT_TIMEOUT);
        $this->timeout = max(1, min(self::MAX_TIMEOUT, $timeout));

        $this->allowOnError = strtolower(trim((string) ($options['on_error'] ?? 'block'))) === 'allow';
        $this->sendRemoteIp = ($options['send_remoteip'] ?? false) === true;
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'turnstile';
    }

    /**
     * {@inheritdoc}
     */
    public function renderInterstitial(Request $request, array $context): string
    {
        $siteKey = InterstitialRenderer::escapeHtml($this->siteKey);
        $theme = InterstitialRenderer::escapeHtml($this->theme);
        $widgetSrc = InterstitialRenderer::escapeHtml($this->widgetSrc);
        $payloadField = InterstitialRenderer::escapeHtml(self::PAYLOAD_FIELD);

        return InterstitialRenderer::render([
            'intro' => 'Please complete the check below to continue.',
            'extra_styles' => '    .cf-turnstile { display: block; margin-bottom: 1rem; min-height: 65px; }'
                . "\n" . '    button:disabled { background: #9bb8e6; cursor: not-allowed; }',
            // The widget callbacks are declared here, ahead of the async
            // bundle, and resolve the button lazily. Declaring them in the
            // document-bottom script instead would be a race: the widget
            // can finish and call back before that script has run, and a
            // missing callback leaves the button disabled for good.
            'extra_head' => <<<HEAD
  <script>
    window.fwTurnstileVerified = function () {
      var b = document.getElementById('submit');
      if (b) { b.disabled = false; }
    };
    window.fwTurnstileReset = function () {
      var b = document.getElementById('submit');
      if (b) { b.disabled = true; }
    };
  </script>
  <script src="{$widgetSrc}" async defer></script>
HEAD,
            'form_fields' => <<<FIELDS
      <div class="cf-turnstile" data-sitekey="{$siteKey}" data-theme="{$theme}"
           data-callback="fwTurnstileVerified"
           data-expired-callback="fwTurnstileReset"
           data-error-callback="fwTurnstileReset"></div>
FIELDS,
            // Enabled by the widget's success callback, so the visitor
            // cannot post an empty token.
            'submit_disabled' => true,
            'error_message' => 'Verification failed. Please try again.',
            'submit_guard' => <<<GUARD
        if (!data.get('{$payloadField}')) {
          err.classList.add('visible');
          return;
        }

GUARD,
            // A refused submission has spent its token — Cloudflare answers
            // `timeout-or-duplicate` to any further use of it — so recycle
            // the widget rather than leaving the visitor to click Continue
            // on a token that can no longer succeed.
            'submit_failure' => <<<'FAILURE'
        window.fwTurnstileReset();
        if (window.turnstile && typeof window.turnstile.reset === 'function') {
          window.turnstile.reset();
        }
FAILURE,
            'extra_script' => '',
            'submit_url' => $context['submit_url'] ?? '',
            'redirect_to' => $context['redirect_to'] ?? '/',
            'ttl' => $context['ttl'] ?? '3600',
            'header_name' => $context['header_name'] ?? '',
            'redirect_field' => self::REDIRECT_FIELD,
            'ttl_field' => self::TTL_FIELD,
        ]);
    }

    /**
     * {@inheritdoc}
     *
     * Three outcomes, deliberately kept distinct:
     *
     *   - Cloudflare says the token is good → TRUE.
     *   - Cloudflare says it is not → FALSE. This covers replay
     *     (`timeout-or-duplicate`), so a solve cannot be shared around.
     *   - Cloudflare could not be asked → the `on_error` option decides,
     *     defaulting to FALSE.
     *
     * That last case is the one worth being deliberate about. Failing open
     * turns any disruption of siteverify — an outage, a DNS failure, egress
     * filtering on this host — into a bypass for every challenged route,
     * and an attacker who can cause it gets the bypass on demand. Failing
     * closed instead makes those routes impassable for the duration, which
     * is visible and self-correcting. Operators who would rather absorb the
     * risk than lock visitors out can set `on_error: allow`.
     */
    public function verifySolution(Request $request): bool
    {
        $token = $this->postedToken($request);

        // No round trip for a request that cannot carry a valid token.
        if ($token === '' || strlen($token) > self::MAX_TOKEN_LENGTH) {
            return false;
        }

        $result = $this->fetch($token, $request);

        if ($result['transport_error'] !== null) {
            LoggingFactory::logMessage('error', 'Turnstile verification could not be completed', [
                'provider' => $this->getName(),
                'error' => $result['transport_error'],
                'on_error' => $this->allowOnError ? 'allow' : 'block',
            ]);

            return $this->allowOnError;
        }

        if (!$result['verified']) {
            // Configuration faults are indistinguishable from a failed
            // visitor in the return value, so separate them in the log —
            // otherwise a wrong secret key looks like a wave of bots.
            $misconfigured = array_intersect($result['error_codes'], self::CONFIG_ERROR_CODES) !== [];

            LoggingFactory::logMessage($misconfigured ? 'error' : 'info', $misconfigured
                ? 'Turnstile rejected the request because this firewall is misconfigured'
                : 'Turnstile verification failed', [
                    'provider' => $this->getName(),
                    'error_codes' => $result['error_codes'],
                ]);

            return false;
        }

        return true;
    }

    /**
     * Ask Cloudflare whether a token is genuine.
     *
     * Uses the stream wrapper rather than an HTTP client library, matching
     * `AbuseIpdb::fetch()` and `Config::fileGetContents()` — the two other
     * places this package talks to the network — so a security library's
     * dependency surface stays unchanged. `ignore_errors` is on so an error
     * body can be read rather than surfacing as an opaque failure.
     *
     * On `send_remoteip`: forwarding the client IP sharpens Cloudflare's
     * signal, but `$request->getClientIp()` is only trustworthy when
     * `global.require_trusted_proxies` is configured. Behind an
     * unconfigured proxy it returns whatever `X-Forwarded-For` claimed,
     * which means a spoofed header sends Cloudflare an IP unrelated to the
     * visitor and can fail verification for legitimate people. A provider
     * cannot see that global, so this defaults off rather than guessing.
     *
     * @param string $token
     *   The token posted by the widget. Already length-checked.
     * @param Request $request
     *   The submission, used only for the optional client IP.
     *
     * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null}
     *   `transport_error` is non-null only when Cloudflare's verdict could
     *   not be obtained at all, which is the case `on_error` governs.
     */
    protected function fetch(string $token, Request $request): array
    {
        $body = $this->buildRequestBody($token, $request);

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'timeout' => $this->timeout,
                'ignore_errors' => true,
                'header' => [
                    'Content-Type: application/x-www-form-urlencoded',
                    'Content-Length: ' . strlen($body),
                    'Accept: application/json',
                ],
                'content' => $body,
            ],
        ]);

        $handle = @fopen(self::SITEVERIFY_ENDPOINT, 'r', false, $context);
        if ($handle === false) {
            return $this->transportFailure('could not reach the Turnstile siteverify API');
        }

        $metadata = stream_get_meta_data($handle);
        $payload = stream_get_contents($handle);
        fclose($handle);

        /** @var array<int, string> $headers */
        $headers = is_array($metadata['wrapper_data'] ?? null) ? $metadata['wrapper_data'] : [];

        return $this->interpretResponse($this->statusFromHeaders($headers), $payload);
    }

    /**
     * Build the urlencoded siteverify request body.
     *
     * Separate from the transport so tests can assert what would be sent to
     * Cloudflare — in particular that the client IP is absent unless it was
     * explicitly opted into — without a network call.
     *
     * @param string $token
     *   The token posted by the widget.
     * @param Request $request
     *   The submission, used only for the optional client IP.
     */
    protected function buildRequestBody(string $token, Request $request): string
    {
        $fields = [
            'secret' => $this->secretKey,
            'response' => $token,
        ];

        if ($this->sendRemoteIp) {
            $ip = (string) $request->getClientIp();
            if ($ip !== '') {
                $fields['remoteip'] = $ip;
            }
        }

        return http_build_query($fields);
    }

    /**
     * Turn a siteverify HTTP response into a verdict.
     *
     * Separate from the transport because every interesting case here is a
     * malformed or unhappy response, and reproducing those against the real
     * endpoint is neither reliable nor fast.
     *
     * @param int|null $status
     *   HTTP status, or NULL when none could be parsed.
     * @param string|false $body
     *   Raw response body as read from the stream.
     *
     * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null}
     */
    protected function interpretResponse(?int $status, string|false $body): array
    {
        // Cloudflare answers 200 even when it rejects a token, so a non-200
        // is an infrastructure problem rather than a verdict.
        if ($status !== 200) {
            return $this->transportFailure(sprintf(
                'the Turnstile siteverify API returned HTTP %s',
                $status ?? 'an unreadable status'
            ));
        }

        if ($body === false || $body === '') {
            return $this->transportFailure('the Turnstile siteverify API returned an empty body');
        }

        $decoded = json_decode($body, true);
        if (!is_array($decoded) || !isset($decoded['success'])) {
            return $this->transportFailure(
                'the Turnstile siteverify API returned a body that is not a verification result'
            );
        }

        $errorCodes = $this->normalizeErrorCodes($decoded['error-codes'] ?? []);

        // "Retry this" is not the same as "this token is bad", so an
        // internal error is handed to `on_error` rather than being counted
        // as a failed visitor.
        if ($decoded['success'] !== true && array_intersect($errorCodes, self::RETRYABLE_ERROR_CODES) !== []) {
            return $this->transportFailure('the Turnstile siteverify API reported an internal error');
        }

        return [
            'verified' => $decoded['success'] === true,
            'error_codes' => $errorCodes,
            'transport_error' => null,
        ];
    }

    /**
     * Read the posted token without ever throwing.
     *
     * `InputBag::get()` raises `BadRequestException` when the value is an
     * array, so reading `cf-turnstile-response[]=x` through it would turn
     * attacker-controlled input into a 500. `verifySolution()` is
     * contractually forbidden from throwing, so the raw bag is inspected
     * instead and anything that is not a string is simply not a token.
     */
    private function postedToken(Request $request): string
    {
        return $this->postedString($request, self::PAYLOAD_FIELD);
    }

    /**
     * Pull a required, non-empty string option or fail startup.
     *
     * @param array<string, mixed> $options
     *   The provider options as configured.
     * @param string $key
     *   Option name to read.
     *
     * @throws ConfigurationException
     *   When the option is absent or empty.
     */
    private function requireOption(array $options, string $key): string
    {
        $value = $options[$key] ?? null;
        $value = is_scalar($value) ? trim((string) $value) : '';

        if ($value === '') {
            throw new ConfigurationException(sprintf(
                'Turnstile provider requires `challenge.provider_options.%s`. Get one from the '
                . 'Turnstile section of the Cloudflare dashboard, and inject it with %%env(VAR)%%.',
                $key
            ));
        }

        return $value;
    }

    /**
     * Coerce Cloudflare's `error-codes` into a list of strings.
     *
     * @param mixed $codes
     *   Whatever occupied the `error-codes` key.
     *
     * @return array<int, string>
     *   Only the string entries, re-indexed.
     */
    private function normalizeErrorCodes(mixed $codes): array
    {
        if (!is_array($codes)) {
            return [];
        }

        return array_values(array_filter($codes, is_string(...)));
    }

    /**
     * Read the HTTP status out of the stream wrapper's response headers.
     *
     * @param array<int, string> $headers
     *   `wrapper_data` as reported by `stream_get_meta_data()`.
     *
     * @return int|null
     *   The status code, or NULL when no status line could be parsed.
     */
    protected function statusFromHeaders(array $headers): ?int
    {
        $status = null;

        // Every header line is scanned rather than stopping at the first
        // match: a redirect chain leaves several status lines here, and the
        // one that actually answered is the last.
        foreach ($headers as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $matches) === 1) {
                $status = (int) $matches[1];
            }
        }

        return $status;
    }

    /**
     * Build a "could not get a verdict" result.
     *
     * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null}
     */
    private function transportFailure(string $reason): array
    {
        return ['verified' => false, 'error_codes' => [], 'transport_error' => $reason];
    }
}
