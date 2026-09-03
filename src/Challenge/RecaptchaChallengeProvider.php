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
 * Built-in Google reCAPTCHA challenge.
 *
 * Renders a reCAPTCHA widget, then verifies the token it produces against
 * Google's siteverify API. Shares its shape with
 * `TurnstileChallengeProvider` — an opaque third-party token, one
 * server-to-server round trip on the challenge POST, no local verification
 * possible — and differs from it in the two places reCAPTCHA genuinely
 * differs: it offers two incompatible versions, and one of them returns a
 * score rather than a verdict.
 *
 * Wire format (per https://developers.google.com/recaptcha/):
 *   server → client: the api.js bundle plus either a `g-recaptcha` element
 *                    (v2) or a `grecaptcha.execute()` call (v3).
 *   client → server: an opaque token in a form field.
 *   server → Google: POST {secret, response, remoteip?} to siteverify.
 *   Google → server: {success, challenge_ts, hostname, error-codes} plus
 *                    {score, action} on v3.
 *
 * ## The two versions
 *
 * `version: v2` (the default) is the "I'm not a robot" checkbox. The visitor
 * does something, the widget mints a token, and Google answers a plain
 * yes/no. It is the closer analogue to Turnstile and the safer default: a
 * visitor who fails can try again.
 *
 * `version: v3` is invisible and scores the visitor from 0.0 to 1.0 instead
 * of judging them. `success: true` on v3 only means the token was
 * well-formed and unspent — the actual decision is this provider's, made by
 * comparing `score` against `min_score`. That difference has a sharp edge
 * worth stating plainly: **a human whose score sits below the threshold has
 * no way to pass.** There is no puzzle to solve and no retry that helps, so
 * a v3 challenge on a route real people need is a lockout waiting to happen.
 * Prefer v2 unless you have a reason not to, and pick `min_score` from
 * observed traffic rather than from the 0.5 in the documentation.
 *
 * ## Why v3 binds the action
 *
 * A v3 token is minted by the site key, not by any particular page, and
 * carries only the `action` string the caller asked for. If this provider
 * checked `success` and `score` alone, a token produced by *any other*
 * reCAPTCHA v3 call on the same site — a newsletter signup, a search box,
 * anything an attacker can trigger without friction — would satisfy the
 * firewall challenge too. `verifySolution()` therefore requires the
 * returned `action` to equal the configured one, which is the only part of
 * the response that ties the token to this challenge.
 *
 * ## Replay
 *
 * Handled at the source on both versions: Google answers
 * `timeout-or-duplicate` to a token that has already been redeemed or has
 * aged out. That is why this provider — like `TurnstileChallengeProvider`
 * and unlike `AltchaChallengeProvider` — needs no
 * `SingleUseSolutionInterface` and touches no storage.
 *
 * Tokens also expire about two minutes after they are minted, which the
 * interstitial has to handle rather than the server: see
 * `renderInterstitial()` for the v2 expiry callback and the v3 refresh.
 *
 * ## Trade-offs against the other built-ins
 *
 *   - It depends on a third party being reachable from both the visitor's
 *     browser and this server. When siteverify is unreachable this provider
 *     fails closed by default (see `on_error`).
 *   - No Subresource Integrity. api.js is served from an unversioned,
 *     mutable URL and bootstraps further scripts, so a pinned digest would
 *     break on Google's next deploy.
 *   - Operators need a Content-Security-Policy that permits the reCAPTCHA
 *     host in both `script-src` and `frame-src`, plus `www.gstatic.com` in
 *     `script-src` for the bundle api.js pulls in.
 *   - Where google.com is unreachable, `use_recaptcha_net` moves both the
 *     widget and siteverify to Google's alternate domain.
 */
final class RecaptchaChallengeProvider implements ChallengeProviderInterface
{
    use RequestFieldTrait;

    /**
     * Form field carrying a v2 widget's token.
     *
     * Fixed by reCAPTCHA v2's automatic rendering, which injects a hidden
     * textarea under this name into the enclosing form.
     */
    public const PAYLOAD_FIELD = 'g-recaptcha-response';

    /**
     * Form field carrying a v3 token.
     *
     * Deliberately *not* `g-recaptcha-response`. On v3 the token arrives in
     * a promise and has to be parked in a field of our own making, and
     * api.js also injects hidden textareas of its own under the v2 name.
     * Two same-named fields in one form make `FormData` carry both values,
     * and which one `get()` returns is not something to stake a security
     * check on. Using a name Google never writes to removes the question.
     */
    public const V3_PAYLOAD_FIELD = 'firewall-recaptcha-token';

    /**
     * Checkbox reCAPTCHA. The default.
     */
    public const VERSION_V2 = 'v2';

    /**
     * Invisible, score-based reCAPTCHA.
     */
    public const VERSION_V3 = 'v3';

    /**
     * Google's primary reCAPTCHA host.
     */
    public const GOOGLE_HOST = 'https://www.google.com';

    /**
     * Google's alternate host, for networks where google.com is blocked.
     *
     * Documented by Google as a drop-in replacement serving both the widget
     * and siteverify. Selected by `use_recaptcha_net`, not by a free-form
     * URL option: an operator-supplied verification endpoint would be an
     * inviting place to point a firewall at something that always says yes.
     */
    public const RECAPTCHA_NET_HOST = 'https://www.recaptcha.net';

    /**
     * Path of the server-side verification endpoint, under either host.
     */
    public const SITEVERIFY_PATH = '/recaptcha/api/siteverify';

    /**
     * Path of the widget bundle, under either host.
     */
    public const WIDGET_PATH = '/recaptcha/api.js';

    /**
     * Default score a v3 visitor must reach.
     *
     * Google's own suggested starting point. It is a starting point and not
     * a recommendation — see the class docblock.
     */
    public const DEFAULT_MIN_SCORE = 0.5;

    /**
     * Default v3 action name.
     *
     * Sent by the interstitial and required back from Google unchanged.
     */
    public const DEFAULT_ACTION = 'firewall';

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
     * Unlike Cloudflare, Google publishes no maximum token length, so this
     * is a sanity bound rather than a specification: generous enough that no
     * genuine token approaches it, small enough that a multi-megabyte POST
     * is not forwarded to Google to be told it is nonsense.
     */
    private const MAX_TOKEN_LENGTH = 8192;

    /**
     * Widget colour themes reCAPTCHA v2 accepts.
     *
     * No `auto`, unlike Turnstile — reCAPTCHA has no such value, so offering
     * one would mean silently rendering something else.
     *
     * @var array<int, string>
     */
    private const THEMES = ['light', 'dark'];

    /**
     * Widget sizes reCAPTCHA v2 accepts here.
     *
     * `invisible` is a documented v2 size but a different flow — no visible
     * control, and the token is minted by an explicit `execute()` bound to
     * the submit button. It is excluded rather than silently mishandled;
     * `version: v3` covers the "no visitor interaction" case.
     *
     * @var array<int, string>
     */
    private const SIZES = ['normal', 'compact'];

    /**
     * Error codes that mean this firewall is misconfigured, not that the
     * visitor failed. Logged at `error` because every visitor will fail
     * until an operator fixes the configuration.
     *
     * @var array<int, string>
     */
    private const CONFIG_ERROR_CODES = ['missing-input-secret', 'invalid-input-secret', 'bad-request'];

    /**
     * reCAPTCHA version in use.
     */
    private readonly string $version;

    /**
     * Public key rendered into the widget.
     */
    private readonly string $siteKey;

    /**
     * Private key sent to siteverify. Never rendered, never logged.
     */
    private readonly string $secretKey;

    /**
     * Host serving both the widget and siteverify.
     */
    private readonly string $host;

    /**
     * Widget bundle URL actually emitted.
     */
    private readonly string $widgetSrc;

    /**
     * Widget colour theme. v2 only.
     */
    private readonly string $theme;

    /**
     * Widget size. v2 only.
     */
    private readonly string $size;

    /**
     * Lowest score accepted from v3.
     */
    private readonly float $minScore;

    /**
     * Action name the interstitial requests and siteverify must echo back.
     */
    private readonly string $action;

    /**
     * siteverify timeout in seconds.
     */
    private readonly int $timeout;

    /**
     * Whether an unreachable siteverify lets the visitor through.
     */
    private readonly bool $allowOnError;

    /**
     * Whether the visitor's IP is forwarded to Google.
     */
    private readonly bool $sendRemoteIp;

    /**
     * Constructs a new RecaptchaChallengeProvider object.
     *
     * Takes no `TokenManager`: there is no per-challenge state of ours to
     * sign, because the only thing that has to survive from render to verify
     * is Google's own token. `ChallengeProviderFactory` matches constructor
     * parameters by declared type, so declining it is enough to not be
     * handed one.
     *
     * @param array<string, mixed> $options
     *   Provider options from `challenge.provider_options`:
     *     - site_key:          REQUIRED. reCAPTCHA site key (public).
     *     - secret_key:        REQUIRED. reCAPTCHA secret key (private).
     *     - version:           `v2` (default) or `v3`. See the class
     *                          docblock before choosing `v3`.
     *     - theme:             v2 only. `light` (default) or `dark`.
     *     - size:              v2 only. `normal` (default) or `compact`.
     *     - min_score:         v3 only. 0.0-1.0, default 0.5.
     *     - action:            v3 only. Action name to mint and require
     *                          back, default `firewall`.
     *     - timeout:           siteverify timeout in seconds, 1-10,
     *                          default 2.
     *     - on_error:          `block` (default) or `allow` — what happens
     *                          when siteverify cannot be reached. See
     *                          verifySolution().
     *     - send_remoteip:     Forward the client IP to Google. Default
     *                          FALSE; see fetch() for why that is not the
     *                          obvious choice it looks like.
     *     - use_recaptcha_net: Serve the widget from and verify against
     *                          www.recaptcha.net instead of www.google.com.
     *     - widget_src:        Override the widget bundle URL, e.g. to serve
     *                          it through a first-party proxy your CSP
     *                          allows. On v3 the `render` parameter is
     *                          appended unless the URL already carries one.
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

        $version = strtolower(trim((string) ($options['version'] ?? '')));
        $this->version = $version === self::VERSION_V3 ? self::VERSION_V3 : self::VERSION_V2;

        $this->host = ($options['use_recaptcha_net'] ?? false) === true
            ? self::RECAPTCHA_NET_HOST
            : self::GOOGLE_HOST;

        $theme = strtolower(trim((string) ($options['theme'] ?? '')));
        $this->theme = in_array($theme, self::THEMES, true) ? $theme : 'light';

        $size = strtolower(trim((string) ($options['size'] ?? '')));
        $this->size = in_array($size, self::SIZES, true) ? $size : 'normal';

        $this->minScore = $this->readMinScore($options);
        $this->action = $this->readAction($options);

        $timeout = (int) ($options['timeout'] ?? self::DEFAULT_TIMEOUT);
        $this->timeout = max(1, min(self::MAX_TIMEOUT, $timeout));

        $this->allowOnError = strtolower(trim((string) ($options['on_error'] ?? 'block'))) === 'allow';
        $this->sendRemoteIp = ($options['send_remoteip'] ?? false) === true;

        $widgetSrc = trim((string) ($options['widget_src'] ?? ''));
        $this->widgetSrc = $this->buildWidgetSrc($widgetSrc);
    }

    /**
     * {@inheritdoc}
     *
     * Version-scoped so logs say which mode made a decision: a v3 refusal is
     * this provider's own score threshold talking, a v2 refusal is Google's,
     * and telling them apart is most of diagnosing a challenge nobody can
     * pass.
     *
     * It does **not** scope pass tokens, which is worth knowing because it
     * looks like it should. `Firewall` builds the `aud` claim from the
     * `challenge.provider` config string — necessarily, since the
     * `TokenManager` is constructed and handed to the factory before any
     * provider exists — so a v2 and a v3 instance both configured as
     * `recaptcha` share an audience and will honour each other's tokens. A
     * v3 pass is the weaker claim of the two: the visitor cleared a score
     * rather than doing anything. Deployments running both against one
     * `challenge.secret` must therefore set `challenge.audience` explicitly
     * on at least one of them.
     */
    public function getName(): string
    {
        return $this->version === self::VERSION_V3 ? 'recaptcha-v3' : 'recaptcha';
    }

    /**
     * Form field this provider reads its token from.
     *
     * Differs by version; see V3_PAYLOAD_FIELD for why.
     */
    public function getPayloadField(): string
    {
        return $this->version === self::VERSION_V3 ? self::V3_PAYLOAD_FIELD : self::PAYLOAD_FIELD;
    }

    /**
     * {@inheritdoc}
     */
    public function renderInterstitial(Request $request, array $context): string
    {
        $parts = $this->version === self::VERSION_V3 ? $this->v3Parts() : $this->v2Parts();

        return InterstitialRenderer::render([
            'intro' => $parts['intro'],
            'extra_styles' => $parts['extra_styles'],
            'extra_head' => $parts['extra_head'],
            'form_fields' => $parts['form_fields'],
            'submit_guard' => $parts['submit_guard'],
            'submit_failure' => $parts['submit_failure'],
            'extra_script' => $parts['extra_script'],
            'error_message' => 'Verification failed. Please try again.',
            // Enabled only once a token exists, so the visitor cannot post
            // an empty one.
            'submit_disabled' => true,
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
     *
     * Outcomes, deliberately kept distinct:
     *
     *   - Google says the token is good, and on v3 it also clears the score
     *     and action gates → TRUE.
     *   - Google says it is not → FALSE. This covers replay
     *     (`timeout-or-duplicate`), so a solve cannot be shared around.
     *   - Google said yes but the v3 gates refuse it → FALSE, logged
     *     separately so a threshold that is too high does not look like a
     *     wave of bots.
     *   - Google could not be asked → the `on_error` option decides,
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
            LoggingFactory::logMessage('error', 'reCAPTCHA verification could not be completed', [
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
                ? 'reCAPTCHA rejected the request because this firewall is misconfigured'
                : 'reCAPTCHA verification failed', [
                    'provider' => $this->getName(),
                    'error_codes' => $result['error_codes'],
                ]);

            return false;
        }

        // On v2 Google's yes is the whole answer. On v3 it only means the
        // token was well-formed and unspent.
        return $this->version !== self::VERSION_V3 || $this->passesScoreGate($result);
    }

    /**
     * Ask Google whether a token is genuine.
     *
     * Uses the stream wrapper rather than an HTTP client library, matching
     * `TurnstileChallengeProvider::fetch()` and `AbuseIpdb::fetch()` — the
     * other places this package talks to the network — so a security
     * library's dependency surface stays unchanged. `ignore_errors` is on so
     * an error body can be read rather than surfacing as an opaque failure.
     *
     * On `send_remoteip`: forwarding the client IP sharpens Google's signal,
     * but `$request->getClientIp()` is only trustworthy when
     * `global.require_trusted_proxies` is configured. Behind an unconfigured
     * proxy it returns whatever `X-Forwarded-For` claimed, which means a
     * spoofed header sends Google an IP unrelated to the visitor and can
     * fail verification for legitimate people. A provider cannot see that
     * global, so this defaults off rather than guessing.
     *
     * @param string $token
     *   The token posted by the widget. Already length-checked.
     * @param Request $request
     *   The submission, used only for the optional client IP.
     *
     * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null, score: float|null, action: string|null}
     *   `transport_error` is non-null only when Google's verdict could not
     *   be obtained at all, which is the case `on_error` governs.
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

        $handle = @fopen($this->getSiteverifyEndpoint(), 'r', false, $context);
        if ($handle === false) {
            return $this->transportFailure('could not reach the reCAPTCHA siteverify API');
        }

        $metadata = stream_get_meta_data($handle);
        $payload = stream_get_contents($handle);
        fclose($handle);

        /** @var array<int, string> $headers */
        $headers = is_array($metadata['wrapper_data'] ?? null) ? $metadata['wrapper_data'] : [];

        return $this->interpretResponse($this->statusFromHeaders($headers), $payload);
    }

    /**
     * The siteverify URL this provider will call.
     */
    public function getSiteverifyEndpoint(): string
    {
        return $this->host . self::SITEVERIFY_PATH;
    }

    /**
     * Build the urlencoded siteverify request body.
     *
     * Separate from the transport so tests can assert what would be sent to
     * Google — in particular that the client IP is absent unless it was
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
     * Unlike Cloudflare, Google documents no retryable error code, so any
     * well-formed `success: false` is taken as a verdict on the token rather
     * than handed to `on_error`.
     *
     * @param int|null $status
     *   HTTP status, or NULL when none could be parsed.
     * @param string|false $body
     *   Raw response body as read from the stream.
     *
     * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null, score: float|null, action: string|null}
     */
    protected function interpretResponse(?int $status, string|false $body): array
    {
        // Google answers 200 even when it rejects a token, so a non-200 is
        // an infrastructure problem rather than a verdict.
        if ($status !== 200) {
            return $this->transportFailure(sprintf(
                'the reCAPTCHA siteverify API returned HTTP %s',
                $status ?? 'an unreadable status'
            ));
        }

        if ($body === false || $body === '') {
            return $this->transportFailure('the reCAPTCHA siteverify API returned an empty body');
        }

        $decoded = json_decode($body, true);
        if (!is_array($decoded) || !isset($decoded['success'])) {
            return $this->transportFailure(
                'the reCAPTCHA siteverify API returned a body that is not a verification result'
            );
        }

        return [
            'verified' => $decoded['success'] === true,
            'error_codes' => $this->normalizeErrorCodes($decoded['error-codes'] ?? []),
            'transport_error' => null,
            // Absent on v2, and absent on a v3 response only if the keys are
            // not the v3 pair they were configured as. NULL keeps those two
            // apart from a genuine 0.0, which is the worst possible score
            // and must never be read as "no score reported".
            'score' => is_numeric($decoded['score'] ?? null) ? (float) $decoded['score'] : null,
            'action' => is_string($decoded['action'] ?? null) ? $decoded['action'] : null,
        ];
    }

    /**
     * Apply the v3 gates Google's `success` does not cover.
     *
     * Order matters for the logs, not the outcome: a missing score means the
     * configured keys are not a v3 pair, which an operator has to fix, and
     * reporting it as a low score instead would send them tuning a threshold
     * that was never consulted.
     *
     * @param array{verified: bool, error_codes: array<int, string>, transport_error: string|null, score: float|null, action: string|null} $result
     *   An interpreted siteverify response Google already said yes to.
     */
    private function passesScoreGate(array $result): bool
    {
        if ($result['score'] === null) {
            LoggingFactory::logMessage('error', 'reCAPTCHA returned no score for a v3 verification', [
                'provider' => $this->getName(),
                'hint' => 'The configured keys are probably a v2 pair; v2 keys never return a score.',
            ]);

            return false;
        }

        // The token is only evidence about *this* challenge if it was minted
        // for this action. See the class docblock.
        if ($result['action'] !== $this->action) {
            LoggingFactory::logMessage('warning', 'reCAPTCHA token was minted for a different action', [
                'provider' => $this->getName(),
                'expected' => $this->action,
                'received' => $result['action'],
            ]);

            return false;
        }

        if ($result['score'] < $this->minScore) {
            LoggingFactory::logMessage('info', 'reCAPTCHA score was below the configured threshold', [
                'provider' => $this->getName(),
                'score' => $result['score'],
                'min_score' => $this->minScore,
            ]);

            return false;
        }

        return true;
    }

    /**
     * Interstitial pieces for the v2 checkbox.
     *
     * @return array{intro: string, extra_styles: string, extra_head: string, form_fields: string, submit_guard: string, submit_failure: string, extra_script: string}
     */
    private function v2Parts(): array
    {
        $siteKey = InterstitialRenderer::escapeHtml($this->siteKey);
        $theme = InterstitialRenderer::escapeHtml($this->theme);
        $size = InterstitialRenderer::escapeHtml($this->size);
        $widgetSrc = InterstitialRenderer::escapeHtml($this->widgetSrc);
        $payloadField = InterstitialRenderer::escapeHtml(self::PAYLOAD_FIELD);

        return [
            'intro' => 'Please complete the check below to continue.',
            'extra_styles' => '    .g-recaptcha { display: block; margin-bottom: 1rem; min-height: 78px; }'
                . "\n" . '    button:disabled { background: #9bb8e6; cursor: not-allowed; }',
            // The widget callbacks are declared here, ahead of the async
            // bundle, and resolve the button lazily. Declaring them in the
            // document-bottom script instead would be a race: the widget can
            // finish and call back before that script has run, and a missing
            // callback leaves the button disabled for good.
            'extra_head' => <<<HEAD
  <script>
    window.fwRecaptchaVerified = function () {
      var b = document.getElementById('submit');
      if (b) { b.disabled = false; }
    };
    window.fwRecaptchaReset = function () {
      var b = document.getElementById('submit');
      if (b) { b.disabled = true; }
    };
  </script>
  <script src="{$widgetSrc}" async defer></script>
HEAD,
            // `data-expired-callback` matters more here than it looks: v2
            // tokens go stale about two minutes after the checkbox is
            // ticked, and without it a visitor who reads the page first
            // would post a token Google answers `timeout-or-duplicate` to.
            'form_fields' => <<<FIELDS
      <div class="g-recaptcha" data-sitekey="{$siteKey}" data-theme="{$theme}" data-size="{$size}"
           data-callback="fwRecaptchaVerified"
           data-expired-callback="fwRecaptchaReset"
           data-error-callback="fwRecaptchaReset"></div>
FIELDS,
            'submit_guard' => <<<GUARD
        if (!data.get('{$payloadField}')) {
          err.classList.add('visible');
          return;
        }

GUARD,
            // A refused submission has spent its token — Google answers
            // `timeout-or-duplicate` to any further use of it — so recycle
            // the widget rather than leaving the visitor to click Continue
            // on a token that can no longer succeed.
            'submit_failure' => <<<'FAILURE'
        window.fwRecaptchaReset();
        if (window.grecaptcha && typeof window.grecaptcha.reset === 'function') {
          window.grecaptcha.reset();
        }
FAILURE,
            // v2 needs nothing at the document bottom — the widget drives
            // the button through its callback attributes.
            'extra_script' => '',
        ];
    }

    /**
     * Interstitial pieces for the v3 invisible check.
     *
     * @return array{intro: string, extra_styles: string, extra_head: string, form_fields: string, submit_guard: string, submit_failure: string, extra_script: string}
     */
    private function v3Parts(): array
    {
        $widgetSrc = InterstitialRenderer::escapeHtml($this->widgetSrc);
        $payloadField = InterstitialRenderer::escapeHtml(self::V3_PAYLOAD_FIELD);

        // Script context, so JS literal encoding — HTML entities are not
        // decoded inside <script> and a stray backslash would break out of
        // the string.
        $siteKeyJs = InterstitialRenderer::escapeJs($this->siteKey);
        $actionJs = InterstitialRenderer::escapeJs($this->action);
        $fieldJs = InterstitialRenderer::escapeJs(self::V3_PAYLOAD_FIELD);

        return [
            'intro' => 'Verifying your browser. This only takes a moment.',
            'extra_styles' => '    button:disabled { background: #9bb8e6; cursor: not-allowed; }',
            'extra_head' => <<<HEAD
  <script src="{$widgetSrc}" async defer></script>
HEAD,
            'form_fields' => <<<FIELDS
      <input type="hidden" id="fw-recaptcha-token" name="{$payloadField}" value="">
FIELDS,
            // Runs at the document bottom, inside the shared IIFE, so
            // `submit` and `err` are already bound and the hidden field
            // exists.
            'extra_script' => <<<SCRIPT

      var fwField = document.getElementById('fw-recaptcha-token');
      var fwSiteKey = {$siteKeyJs};
      var fwAction = {$actionJs};

      // api.js is loaded async and bootstraps further scripts of its own,
      // so `grecaptcha` may not exist yet when this runs — and unlike v2
      // there is no callback attribute to hang this off. Polling is the
      // defensive read: no assumption about load order, and a bundle that
      // never arrives simply leaves the button disabled.
      function fwRecaptchaExecute() {
        if (!window.grecaptcha || typeof window.grecaptcha.ready !== 'function') {
          window.setTimeout(fwRecaptchaExecute, 100);
          return;
        }

        window.grecaptcha.ready(function () {
          window.grecaptcha.execute(fwSiteKey, { action: fwAction }).then(function (token) {
            fwField.value = token;
            submit.disabled = false;
          }, function () {
            fwField.value = '';
            submit.disabled = true;
            err.classList.add('visible');
          });
        });
      }

      fwRecaptchaExecute();

      // v3 tokens expire about two minutes after they are minted. A visitor
      // who leaves the tab open would otherwise come back to a token Google
      // answers `timeout-or-duplicate` to, with nothing on screen to retry.
      window.setInterval(fwRecaptchaExecute, 90000);
      window.fwRecaptchaRefresh = fwRecaptchaExecute;
SCRIPT,
            'submit_guard' => <<<GUARD
        if (!data.get({$fieldJs})) {
          err.classList.add('visible');
          return;
        }

GUARD,
            // The attempt spent the token, so mint a fresh one rather than
            // leaving Continue wired to something already redeemed. The
            // button goes down first: minting is asynchronous, and until it
            // resolves a second click would re-post the spent token.
            'submit_failure' => <<<'FAILURE'
        submit.disabled = true;
        if (typeof window.fwRecaptchaRefresh === 'function') {
          window.fwRecaptchaRefresh();
        }
FAILURE,
        ];
    }

    /**
     * Resolve the widget bundle URL, including v3's `render` parameter.
     *
     * v3 mints tokens through `grecaptcha.execute()`, which only exists when
     * api.js was loaded with `render=<site key>`. An operator overriding
     * `widget_src` to proxy the bundle should not have to know that, so the
     * parameter is appended for them — unless the URL already carries one,
     * in which case they meant it.
     *
     * @param string $configured
     *   The `widget_src` option, already trimmed. Empty for the default.
     */
    private function buildWidgetSrc(string $configured): string
    {
        $src = $configured !== '' ? $configured : $this->host . self::WIDGET_PATH;

        if ($this->version !== self::VERSION_V3 || str_contains($src, 'render=')) {
            return $src;
        }

        return $src . (str_contains($src, '?') ? '&' : '?') . 'render=' . rawurlencode($this->siteKey);
    }

    /**
     * Read and clamp the v3 score threshold.
     *
     * Clamped rather than rejected: `min_score: 5` is a plausible mistake
     * from someone thinking in percentages, and a threshold above 1.0 would
     * silently reject every visitor forever.
     *
     * @param array<string, mixed> $options
     *   The provider options as configured.
     */
    private function readMinScore(array $options): float
    {
        $configured = $options['min_score'] ?? null;

        if (!is_numeric($configured)) {
            return self::DEFAULT_MIN_SCORE;
        }

        return max(0.0, min(1.0, (float) $configured));
    }

    /**
     * Read the v3 action name.
     *
     * Google restricts action names to alphanumerics, slashes and
     * underscores, and silently drops anything else server-side. Filtering
     * here rather than passing it through means the value this provider
     * compares against is the value Google will actually echo back —
     * otherwise a stray character would fail every verification with a
     * mismatch that looks like an attack.
     *
     * @param array<string, mixed> $options
     *   The provider options as configured.
     */
    private function readAction(array $options): string
    {
        $configured = $options['action'] ?? null;
        $configured = is_scalar($configured) ? trim((string) $configured) : '';

        $filtered = preg_replace('#[^A-Za-z0-9/_]#', '', $configured) ?? '';

        return $filtered !== '' ? $filtered : self::DEFAULT_ACTION;
    }

    /**
     * Read the posted token without ever throwing.
     *
     * `InputBag::get()` raises `BadRequestException` when the value is an
     * array, so reading `g-recaptcha-response[]=x` through it would turn
     * attacker-controlled input into a 500. `verifySolution()` is
     * contractually forbidden from throwing, so the raw bag is inspected
     * instead and anything that is not a string is simply not a token.
     */
    private function postedToken(Request $request): string
    {
        return $this->postedString($request, $this->getPayloadField());
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
                'reCAPTCHA provider requires `challenge.provider_options.%s`. Register a site at '
                . 'https://www.google.com/recaptcha/admin, and inject the key with %%env(VAR)%%.',
                $key
            ));
        }

        return $value;
    }

    /**
     * Coerce Google's `error-codes` into a list of strings.
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
     * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null, score: float|null, action: string|null}
     */
    private function transportFailure(string $reason): array
    {
        return [
            'verified' => false,
            'error_codes' => [],
            'transport_error' => $reason,
            'score' => null,
            'action' => null,
        ];
    }
}
