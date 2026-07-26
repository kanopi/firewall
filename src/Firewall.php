<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall;

use Kanopi\Firewall\Challenge\ChallengeProviderFactory;
use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Logging\LoggingTrait;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Storage\StorageFactory;
use Kanopi\Firewall\Storage\StorageInterface;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\PluginConfigNormalizer;
use Symfony\Component\HttpFoundation\Request;

/**
 * Firewall class that creates and evaluates requests.
 */
final class Firewall
{
    use LoggingTrait;

    /**
     * Firewall Mode.
     */
    private FirewallMode $firewallMode;

    /**
     * Create a new Firewall Object.
     *
     * @param StorageInterface $storage
     *   Storage to write data to.
     * @param PluginManager $blockingPluginManager
     *   Plugin manager for Blocking Plugins.
     * @param PluginManager $bypassPluginManager
     *   Plugin manager for Bypass Plugins.
     * @param PluginManager $challengePluginManager
     *   Plugin manager for Challenge Plugins.
     * @param array $config
     *   Global configuration that can be set as defaults.
     * @param ChallengeProviderInterface|null $challengeProvider
     *   Provider that renders + verifies challenges. Required iff at
     *   least one challenge plugin is configured.
     * @param TokenManager|null $tokenManager
     *   Mints / verifies the pass token issued after a challenge is
     *   solved. Required iff $challengeProvider is set.
     * @param array<string, mixed> $challengeConfig
     *   Subset of config relevant to the challenge flow: path,
     *   cookie_name, header_name.
     */
    protected function __construct(
        private StorageInterface $storage,
        private PluginManager $blockingPluginManager,
        private PluginManager $bypassPluginManager,
        private PluginManager $challengePluginManager,
        private array $config,
        private ?ChallengeProviderInterface $challengeProvider = null,
        private ?TokenManager $tokenManager = null,
        private array $challengeConfig = []
    ) {
        $this->firewallMode = FirewallMode::tryFrom($config['mode'] ?? 'block') ?? FirewallMode::Block;

        $this->getLogger()->debug('Firewall instance created', [
            'storage_type' => $storage::class,
            'blocking_plugins_count' => count($blockingPluginManager->getPlugins()),
            'bypass_plugins_count' => count($bypassPluginManager->getPlugins()),
            'challenge_plugins_count' => count($challengePluginManager->getPlugins()),
            'config_keys' => array_keys($config), // Log keys instead of full config to avoid sensitive data
            'mode' => $this->firewallMode->value,
            'challenge_enabled' => $challengeProvider instanceof \Kanopi\Firewall\Challenge\ChallengeProviderInterface,
        ]);
        $this->storage->expire();
    }

    /**
     * Creates a new instance of the class with a merged configuration.
     *
     * This method accepts zero or more configuration inputs. Each input can be:
     * - A string representing a path to a YAML configuration file, which will be parsed.
     * - An array containing configuration data.
     * - Null, which will be treated as an empty configuration.
     *
     * All configurations are merged in the order they are passed, layered on top of
     * the default configuration loaded from `config.yml`.
     *
     * @param array<int, string|array<string, mixed>|null> $configs
     *   Zero or more configurations to merge.
     *   Each can be a YAML file path (string), a config array, or null.
     * @param array<string, mixed> $overrides
     *   Override values of the configs.
     *
     * @return self
     *   A new instance of the class initialized with the merged config.
     *
     * @throws FirewallBlockedException
     *   If a string argument does not reference an existing file,
     *   or if an argument is not string, array, or null.
     */
    public static function create(array $configs = [], array $overrides = []): self
    {
        // Load default config first
        $config = Config::load(array_merge([__DIR__ . '/../config/config.yml'], $configs), $overrides);

        // Set the default values.
        $config['logger'] = isset($config['logger']) && is_array($config['logger']) ? array_filter($config['logger']) : [];
        $config['storage'] = isset($config['storage']) && is_array($config['storage']) ? array_filter($config['storage']) : [];
        $config['global'] = isset($config['global']) && is_array($config['global']) ? array_filter($config['global']) : [];
        $config['challenge'] = isset($config['challenge']) && is_array($config['challenge']) ? $config['challenge'] : [];

        LoggingFactory::setLogger(LoggingFactory::create($config['logger']));

        // Every plugin reads `$request->getClientIp()`. Symfony only honors
        // proxy headers (X-Forwarded-For, Forwarded, X-Real-IP, …) when the
        // integrator has called `Request::setTrustedProxies(...)`. If trusted
        // proxies aren't configured but the application sits behind a proxy
        // anyway, attackers can spoof their source IP via X-Forwarded-For
        // and trivially bypass IP/CIDR allowlists and per-IP rate limits.
        //
        // We can't detect "is there actually a proxy in front of me?" — that's
        // deployment-specific. What we can do is surface that the firewall is
        // currently trusting whatever Symfony does by default. Operators who
        // know they're not behind a proxy can silence the warning with
        // `global.require_trusted_proxies: false` (the default). Operators
        // who know they *are* behind a proxy should set it to `true` and
        // configure `Request::setTrustedProxies(...)` — startup will then
        // throw a clear error if the wiring is missing.
        self::checkTrustedProxiesPosture($config['global']);

        // Normalize configuration to the new plugins: array format.
        $config = PluginConfigNormalizer::normalize($config);

        // Partition plugins by response type and sort by weight.
        $partitioned = PluginConfigNormalizer::partitionAndSort($config['plugins'] ?? []);

        LoggingFactory::logger()->debug('Starting Firewall', [
            'logger_config_keys' => array_keys($config['logger']),
            'storage_config_keys' => array_keys($config['storage']),
            'allow_plugins_count' => count($partitioned['allow']),
            'block_plugins_count' => count($partitioned['block']),
            'challenge_plugins_count' => count($partitioned['challenge']),
            'global_config_keys' => array_keys($config['global']),
        ]);

        [$challengeProvider, $tokenManager, $challengeConfig] = self::createChallengePieces(
            $config['challenge'],
            $partitioned['challenge'] !== []
        );

        $firewall = new self(
            StorageFactory::create($config['storage']),
            PluginManager::createFromPluginsArray($partitioned['block']),
            PluginManager::createFromPluginsArray($partitioned['allow']),
            PluginManager::createFromPluginsArray($partitioned['challenge']),
            $config['global'],
            $challengeProvider,
            $tokenManager,
            $challengeConfig
        );

        LoggingFactory::logger()->debug('Firewall initialized', [
            'logger_config_keys' => array_keys($config['logger']),
            'storage_config_keys' => array_keys($config['storage']),
            'allow_plugins_count' => count($partitioned['allow']),
            'block_plugins_count' => count($partitioned['block']),
            'challenge_plugins_count' => count($partitioned['challenge']),
            'global_config_keys' => array_keys($config['global']),
        ]);

        return $firewall;
    }

    /**
     * Build the challenge collaborators (or skip if not needed).
     *
     * Returns `[provider|null, tokenManager|null, normalizedChallengeConfig]`.
     * When no challenge plugins are present and no challenge block was
     * declared, all three slots are empty/null and the firewall acts as
     * if the feature did not exist.
     *
     * Failing here (rather than at first request) keeps a missing secret
     * from looking like a 500 deep in the request lifecycle.
     *
     * @param array<string, mixed> $challengeConfig
     *   The `challenge:` section from the loaded YAML.
     * @param bool $hasChallengePlugins
     *   Whether any plugin partitioned into the challenge bucket.
     *
     * @return array{0: ?ChallengeProviderInterface, 1: ?TokenManager, 2: array<string, mixed>}
     *
     * @throws ConfigurationException
     *   When challenge plugins exist but no secret is configured, or
     *   when the configured provider cannot be resolved.
     */
    private static function createChallengePieces(array $challengeConfig, bool $hasChallengePlugins): array
    {
        $defaults = [
            'provider' => 'math',
            'secret' => '',
            'cookie_name' => 'fw_challenge_pass',
            'header_name' => 'X-Firewall-Challenge',
            'path' => '/_firewall/challenge',
            'provider_options' => [],
        ];

        $challengeConfig = array_replace($defaults, $challengeConfig);

        if (!$hasChallengePlugins) {
            return [null, null, $challengeConfig];
        }

        $secret = (string) ($challengeConfig['secret'] ?? '');
        if ($secret === '') {
            throw new ConfigurationException(
                'response: challenge plugins are configured but `challenge.secret` is '
                . 'empty. Set a long, random secret (typically from an env var) so '
                . 'pass tokens can be HMAC-signed.'
            );
        }

        $providerOptions = $challengeConfig['provider_options'] ?? [];

        $tokenManager = new TokenManager($secret);
        $challengeProvider = ChallengeProviderFactory::create(
            (string) $challengeConfig['provider'],
            $tokenManager,
            is_array($providerOptions) ? $providerOptions : []
        );

        return [$challengeProvider, $tokenManager, $challengeConfig];
    }

    /**
     * Detect and warn (or fail) on a missing trusted-proxies posture.
     *
     * If `Request::getTrustedProxies()` returns an empty list, the firewall
     * is trusting whatever Symfony's defaults dictate for the proxy
     * headers — which on every Symfony version since 4.4 means
     * `X-Forwarded-For` does NOT influence `getClientIp()` unless trusted
     * proxies are set, but a custom `Request` subclass or future Symfony
     * default could change that. Log a warning so operators behind a proxy
     * see the misconfiguration in their normal log channel.
     *
     * Behaviour switches on `global.require_trusted_proxies`:
     *   * `false` / unset (default) — warn only.
     *   * `true` — throw `ConfigurationException` at startup so a missing
     *     trusted-proxies setup is a hard failure in production.
     *
     * @param array<string, mixed> $globalConfig
     *   The `global` config section.
     *
     * @throws ConfigurationException
     *   When `require_trusted_proxies` is true and no trusted proxies
     *   have been configured before `Firewall::create()` runs.
     */
    protected static function checkTrustedProxiesPosture(array $globalConfig): void
    {
        if (Request::getTrustedProxies() !== []) {
            return;
        }

        $require = !empty($globalConfig['require_trusted_proxies']);
        $message = 'Symfony Request::getTrustedProxies() is empty. If this '
            . 'application sits behind a proxy / load balancer, the firewall '
            . 'cannot trust the client IP and IP-based block / allow / rate-'
            . 'limit rules can be bypassed via X-Forwarded-For. Call '
            . 'Request::setTrustedProxies(...) before Firewall::create() with '
            . 'the proxy CIDRs and the header bitmask you trust. Set '
            . 'global.require_trusted_proxies=true to make this a fatal '
            . 'startup error.';

        if ($require) {
            LoggingFactory::logger()->error($message);
            throw new ConfigurationException($message);
        }

        LoggingFactory::logger()->warning($message);
    }

    /**
     * Evaluate the current request to see if valid and can pass the firewall.
     *
     * @param \Symfony\Component\HttpFoundation\Request|null $request
     *   Request to evaluate.
     *
     * @return bool
     *   Return TRUE if allowed to pass. FALSE
     * @throws FirewallBlockedException
     */
    public function evaluate(?Request $request = null): bool
    {
        // Skip in CLI (Drush, cron, WP-CLI) unless mode is 'exception' (PHPUnit/framework use).
        // @codeCoverageIgnoreStart
        if (PHP_SAPI === 'cli' && $this->firewallMode !== FirewallMode::Exception) {
            $this->getLogger()->debug('CLI mode detected, bypassing firewall');
            return true;
        }

        // @codeCoverageIgnoreEnd

        if ($this->firewallMode === FirewallMode::Disabled) {
            $this->getLogger()->debug('Firewall disabled, skipping evaluation');
            return true;
        }

        if (is_null($request)) {
            $request = Request::createFromGlobals();
        }

        if (!$request->attributes->has('x-request-id')) {
            $requestId = $this->generateId($request);
            $request->attributes->set('x-request-id', $requestId);
            $this->getLogger()->debug('Request evaluation started', $this->getContext($request));
        }

        // Intercept challenge solutions before any plugin evaluation so a
        // POST to the magic path can never be blocked by an unrelated rule
        // (e.g. a URL plugin matching the magic path itself).
        if ($this->isChallengeSubmission($request)) {
            $this->handleChallengeSubmission($request);
            return true;
        }

        if (($plugin = $this->bypassPluginManager->evaluate($request)) !== false) {
            $this->getLogger()->info('Request bypassed', $this->getContext($request, [
                'plugin_name' => $plugin->getName(),
                'plugin_type' => $plugin::class,
            ]));
            return true;
        }

        if (($data = $this->storage->isBlocked($this->storage->getKey($request))) !== false) {
            if (array_key_exists('event_id', $data)) {
                $request->attributes->set('x-request-id', $data['event_id']);
            }

            $this->repeatOffender($request);
            $this->sendBlockingResponse($request, intval($this->config['repeat_offender_status'] ?? 0));
        }

        // A held pass token short-circuits the challenge bucket. Block
        // plugins still run — the token only attests "I am human", not
        // "I am allowed everywhere".
        $hasValidToken = $this->hasValidChallengeToken($request);

        if (!$hasValidToken && ($plugin = $this->challengePluginManager->evaluate($request)) !== false) {
            if ($this->firewallMode === FirewallMode::Log) {
                $this->getLogger()->warning('Request would be challenged (log mode)', $this->getContext($request, [
                    'mode' => 'log',
                    'plugin_name' => $plugin->getName(),
                    'plugin_type' => $plugin::class,
                ]));
                return true;
            }

            $this->sendChallengeResponse($request, $plugin);
        }

        if (($plugin = $this->blockingPluginManager->evaluate($request)) !== false) {
            if ($this->firewallMode === FirewallMode::Log) {
                $this->getLogger()->warning('Request would be blocked (log mode)', $this->getContext($request, [
                    'mode' => 'log',
                    'plugin_name' => $plugin->getName(),
                    'plugin_type' => $plugin::class,
                ]));
                return true;
            }

            $this->block($request, $plugin);
            $this->sendBlockingResponse($request, $plugin->getStatusCode($request));
        }

        $this->getLogger()->debug('Request allowed', $this->getContext($request));

        return true;
    }

    /**
     * Is this request a POST to the configured challenge submission path?
     *
     * Only matches when challenge support is actually wired up — a host
     * app without challenge plugins won't accidentally intercept POSTs to
     * the default magic path.
     */
    protected function isChallengeSubmission(Request $request): bool
    {
        if (!$this->challengeProvider instanceof \Kanopi\Firewall\Challenge\ChallengeProviderInterface || !$this->tokenManager instanceof \Kanopi\Firewall\Challenge\TokenManager) {
            return false;
        }

        if ($request->getMethod() !== 'POST') {
            return false;
        }

        $path = (string) ($this->challengeConfig['path'] ?? '');
        return $path !== '' && $request->getPathInfo() === $path;
    }

    /**
     * Verify a posted challenge solution and mint a pass token on success.
     *
     * Always terminates the request — either with `exit()` in production
     * (cookie + JSON/303 body) or by throwing in Exception mode.
     *
     * @throws ChallengeSolvedException
     *   In Exception mode when the solution is valid. Carries the minted
     *   token and the redirect target so tests can assert both.
     * @throws ChallengeRequiredException
     *   In Exception mode when the solution is invalid.
     */
    protected function handleChallengeSubmission(Request $request): void
    {
        if (!$this->challengeProvider instanceof \Kanopi\Firewall\Challenge\ChallengeProviderInterface || !$this->tokenManager instanceof \Kanopi\Firewall\Challenge\TokenManager) {
            // Defensive — isChallengeSubmission() already gated this.
            return;
        }

        $valid = $this->challengeProvider->verifySolution($request);

        if (!$valid) {
            $this->getLogger()->info('Challenge solution rejected', $this->getContext($request, [
                'provider' => $this->challengeProvider->getName(),
            ]));

            if ($this->firewallMode === FirewallMode::Exception) {
                throw new ChallengeRequiredException('Invalid challenge solution');
            }

            // @codeCoverageIgnoreStart
            http_response_code(400);
            if (!headers_sent()) {
                header('Content-Type: application/json; charset=utf-8');
            }

            exit((string) json_encode(['error' => 'invalid_solution']));
            // @codeCoverageIgnoreEnd
        }

        $ttl = max(0, (int) $request->request->get(ChallengeProviderInterface::TTL_FIELD, 3600));
        $token = $this->tokenManager->mint($request, $ttl);
        $redirect = $this->sanitizeRedirect(
            (string) $request->request->get(ChallengeProviderInterface::REDIRECT_FIELD, '/')
        );

        $this->getLogger()->info('Challenge solution accepted', $this->getContext($request, [
            'provider' => $this->challengeProvider->getName(),
            'ttl' => $ttl,
        ]));

        if ($this->firewallMode === FirewallMode::Exception) {
            throw new ChallengeSolvedException($token, $redirect);
        }

        // @codeCoverageIgnoreStart
        $this->setPassTokenCookie($token, $ttl);

        if (!headers_sent()) {
            header('Content-Type: application/json; charset=utf-8');
        }

        exit((string) json_encode(['token' => $token, 'redirect' => $redirect]));
        // @codeCoverageIgnoreEnd
    }

    /**
     * Render the challenge interstitial for the matched plugin.
     *
     * @throws ChallengeRequiredException
     *   In Exception mode.
     */
    protected function sendChallengeResponse(Request $request, PluginInterface $plugin): void
    {
        if (!$this->challengeProvider instanceof \Kanopi\Firewall\Challenge\ChallengeProviderInterface) {
            // Should be impossible — partitioning would have routed this
            // request to the block path instead — but guard anyway so a
            // misconfigured firewall fails loud rather than serving an
            // empty page.
            throw new ConfigurationException(
                'A challenge plugin matched but no ChallengeProviderInterface is configured.'
            );
        }

        $ttl = $plugin->getExpirationTime($request);
        if ($ttl <= 0) {
            $ttl = 3600;
        }

        $this->getLogger()->notice('Sending challenge response', $this->getContext($request, [
            'plugin_name' => $plugin->getName(),
            'plugin_type' => $plugin::class,
            'provider' => $this->challengeProvider->getName(),
            'ttl' => $ttl,
        ]));

        if ($this->firewallMode === FirewallMode::Exception) {
            throw new ChallengeRequiredException(sprintf(
                'Challenge required by plugin: %s',
                $plugin->getName()
            ));
        }

        // @codeCoverageIgnoreStart
        $body = $this->challengeProvider->renderInterstitial($request, [
            'submit_url' => (string) ($this->challengeConfig['path'] ?? '/_firewall/challenge'),
            'redirect_to' => $this->sanitizeRedirect($request->getRequestUri()),
            'ttl' => (string) $ttl,
            'cookie_name' => (string) ($this->challengeConfig['cookie_name'] ?? ''),
            'header_name' => (string) ($this->challengeConfig['header_name'] ?? ''),
        ]);

        http_response_code(200);
        if (!headers_sent()) {
            header('Content-Type: text/html; charset=utf-8');
            header('Cache-Control: no-store');
        }

        exit($body);
        // @codeCoverageIgnoreEnd
    }

    /**
     * Does the request carry a pass token that verifies for this client?
     *
     * Looks first in the cookie, then in the configured custom header
     * (the localStorage delivery path used by SPA callers whose XHRs
     * cannot rely on cookies).
     */
    protected function hasValidChallengeToken(Request $request): bool
    {
        if (!$this->tokenManager instanceof \Kanopi\Firewall\Challenge\TokenManager) {
            return false;
        }

        $cookieName = (string) ($this->challengeConfig['cookie_name'] ?? '');
        $headerName = (string) ($this->challengeConfig['header_name'] ?? '');

        $token = '';
        if ($cookieName !== '' && $request->cookies->has($cookieName)) {
            $token = (string) $request->cookies->get($cookieName);
        }

        if ($token === '' && $headerName !== '' && $request->headers->has($headerName)) {
            $token = (string) $request->headers->get($headerName);
        }

        if ($token === '') {
            return false;
        }

        return $this->tokenManager->verify($token, $request);
    }

    /**
     * Sanitize a redirect target so the interstitial can't be turned into
     * an open redirect by attacker-controlled hidden form values.
     *
     * Accepts only same-origin paths (must start with `/` and must NOT
     * start with `//` or `/\`). Falls back to "/" otherwise.
     */
    protected function sanitizeRedirect(string $target): string
    {
        if ($target === '' || $target[0] !== '/') {
            return '/';
        }

        if (str_starts_with($target, '//') || str_starts_with($target, '/\\')) {
            return '/';
        }

        return $target;
    }

    /**
     * Set the pass-token cookie with conservative defaults.
     *
     * @codeCoverageIgnore
     */
    protected function setPassTokenCookie(string $token, int $ttl): void
    {
        $cookieName = (string) ($this->challengeConfig['cookie_name'] ?? '');
        if ($cookieName === '' || headers_sent()) {
            return;
        }

        setcookie($cookieName, $token, [
            'expires' => time() + $ttl,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }

    /**
     * Action to acknowledge someone who has already been blocked.
     *
     * @param Request $request
     *   Request to evaluate.
     */
    protected function repeatOffender(Request $request): void
    {
        $addToExpire = intval($this->config['add_to_expire'] ?? 3600);
        if ($addToExpire > 0) {
            $this->storage->addToExpire($this->storage->getKey($request), $addToExpire);
        }

        $this->storage->recordOffense($this->storage->getKey($request));

        $this->getLogger()->debug('Repeat Offender', $this->getContext($request));
    }

    /**
     * Generate an ID for the following Request.
     *
     * Pre-fix this returned `strtoupper(md5($clientIp . time()))`, which
     * is predictable per-IP at 1-second resolution. The ID is reflected
     * to clients via `{{request.id}}` in the default banning message and
     * shipped to downstream logs, so a predictable ID lets an attacker
     * brute-force IDs for nearby timestamps on a shared proxy IP and
     * stitch log lines together. 128 bits from a CSPRNG removes both.
     *
     * The `$request` parameter is retained (unused) so callers and
     * subclasses that depend on the signature don't break.
     *
     * @param Request $request
     *   Request to get information from (unused — kept for backwards
     *   compatibility with subclasses overriding this method).
     *
     * @return string
     *   Return the ID associated with the request: 32 uppercase hex
     *   characters from `bin2hex(random_bytes(16))`.
     */
    protected function generateId(Request $request): string
    {
        // The Request is no longer used — the previous predictable ID was
        // derived from $request->getClientIp() and time(). Kept on the
        // signature so subclasses overriding this method still satisfy the
        // contract.
        return strtoupper(bin2hex(random_bytes(16)));
    }

    /**
     * Block the request and status code.
     *
     * @param Request $request
     *   Request to evaluate.
     * @param int $statusCode
     *   Status code to return for the request.
     *
     * @throws FirewallBlockedException
     *   When env variable is used for testing.
     */
    protected function sendBlockingResponse(Request $request, int $statusCode = 0): void
    {
        // Check to see if status code is 0 and a global config is set.
        if ($statusCode === 0 && array_key_exists('banning_status_code', $this->config) && is_int($this->config['banning_status_code'])) {
            $statusCode = intval($this->config['banning_status_code']);
        }

        // Fallback to setting status code to 400 if nothing is set.
        if ($statusCode === 0) {
            $statusCode = 400;
        }

        $this->getLogger()->notice('Sending blocking response', $this->getContext($request, [
            'status_code' => $statusCode,
        ]));

        // Replace variables in the custom message.
        $banningMessage = $this->interpolateTemplate(
            (
                (
                    array_key_exists('banning_message', $this->config) &&
                    is_string($this->config['banning_message'])
                ) ?
                $this->config['banning_message'] :
                "{{request.id}} Request Banned"
            ),
            $request
        );

        if ($this->firewallMode === FirewallMode::Exception) {
            throw new FirewallBlockedException($banningMessage, $statusCode);
        }

        // @codeCoverageIgnoreStart
        http_response_code($statusCode);
        // Force a non-HTML content type so any escaped placeholders that
        // still slip into the body (e.g. attacker-supplied bytes inside a
        // {{request.*}} substitution) cannot render as markup in the
        // victim's browser. Belt-and-braces alongside the htmlspecialchars
        // in interpolateTemplate().
        if (!headers_sent()) {
            header('Content-Type: text/plain; charset=utf-8');
            header('X-Content-Type-Options: nosniff');
        }

        exit($banningMessage);
        // @codeCoverageIgnoreEnd
    }

    /**
     * Replace placeholders in a template string with values taken from a Symfony Request
     * and/or an additional context array.
     *
     * Supported placeholders (case-insensitive):
     *   • {{ request.method }}          →  GET / POST / …
     *   • {{ request.scheme }}          →  http / https
     *   • {{ request.host }}            →  example.com
     *   • {{ request.path }}            →  /search
     *   • {{ request.ip }}              →  client IP (trusts your Symfony trusted proxies config)
     *   • {{ request.header.X-Foo }}    →  any HTTP header
     *   • {{ request.query.q }}         →  ?q=something
     *   • {{ request.post.name }}       →  body fields (application/x-www-form-urlencoded, multipart, JSON parsed by you, …)
     *   • {{ request.cookie.session }}  →  cookies
     *
     * Any other placeholder is looked up verbatim in $context (e.g. {{ user_id }}).
     * Unknown placeholders are left untouched so you can chain calls safely.
     *
     * @param  string  $template
     *   The string containing {{ … }} placeholders
     * @param  Request $request
     *   The current Symfony Request
     * @param  array   $context
     *   Optional extra key/value pairs to interpolate
     *
     * @return string
     *   The interpolated result
     */
    protected function interpolateTemplate(string $template, Request $request, array $context = []): string
    {
        // Values from the request (headers, query, post, cookies) are attacker-
        // controlled. The interpolated output is written verbatim to the HTTP
        // response by sendBlockingResponse(), so every substitution is HTML-
        // escaped and stripped of CR/LF to prevent reflected XSS and response-
        // splitting (CWE-79, CWE-113).
        $sanitize = static function (mixed $value): string {
            $string = is_scalar($value) || $value === null ? (string) $value : '';
            $string = str_replace(["\r", "\n"], '', $string);
            return htmlspecialchars($string, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        };

        return strval(preg_replace_callback(
            '/\{\{\s*([a-zA-Z0-9_\.\-]+)\s*\}\}/',
            function (array $m) use ($request, $context, $sanitize): string {
                $key = strtolower($m[1]);

                // 1. Built-in request values ------------------------------------
                switch ($key) {
                    case 'request.method':
                        return $sanitize($request->getMethod());
                    case 'request.scheme':
                        return $sanitize($request->getScheme());
                    case 'request.host':
                        return $sanitize($request->getHost());
                    case 'request.path':
                        return $sanitize($request->getPathInfo());
                    case 'request.ip':
                        return $sanitize($request->getClientIp());
                    case 'request.id':
                        return $sanitize($request->attributes->get('x-request-id'));
                }

                // 2. request.header.<name>
                if (str_starts_with($key, 'request.header.')) {
                    $header = substr($key, 15);          // after 'request.header.'
                    return $sanitize($request->headers->get($header, ''));
                }

                // 3. request.query.<param>
                if (str_starts_with($key, 'request.query.')) {
                    $param = substr($key, 14);
                    return $sanitize($request->query->get($param, ''));
                }

                // 4. request.post.<param>  (body fields)
                if (str_starts_with($key, 'request.post.')) {
                    $param = substr($key, 13);
                    return $sanitize($request->request->get($param, ''));
                }

                // 5. request.cookie.<name>
                if (str_starts_with($key, 'request.cookie.')) {
                    $param = substr($key, 15);
                    $cookies = array_change_key_case($request->cookies->all());
                    return $sanitize($cookies[$param] ?? '');
                }

                // 6. Arbitrary context values ----------------------------------
                if (array_key_exists($m[1], $context)) {
                    return $sanitize($context[$m[1]]);
                }

                // 7. Unknown placeholder – leave as-is so caller sees what was missing
                return $m[0];
            },
            $template
        ));
    }

    /**
     * Block the specific key.
     *
     * @param Request $request
     *   Request information.
     * @param PluginInterface $plugin
     *   Plugin that is blocking.
     *
     * @return bool
     *   Return TRUE if successful, FALSE if there is an issue.
     */
    protected function block(Request $request, PluginInterface $plugin): bool
    {
        $this->getLogger()->warning('Request blocked by plugin', $this->getContext($request, [
            'plugin_name' => $plugin->getName(),
            'plugin_type' => $plugin::class,
            'status_code' => $plugin->getStatusCode($request),
        ]));

        $expirationTime = $this->determineExpirationTime(
            $request,
            $plugin->getExpirationTime($request)
        );

        $key = $this->storage->getKey($request);
        $value = $this->storage->getStorageData($request, $plugin);
        $success = $this->storage->set(
            $key,
            $value,
            $expirationTime
        );

        if ($success) {
            $this->getLogger()->info('IP blocked successfully', $this->getContext($request, [
                'key' => $key,
                'plugin_name' => $plugin->getName(),
                'plugin_type' => $plugin::class,
                'expiration_time' => $expirationTime,
            ]));
        } else {
            $this->getLogger()->error('Failed to block IP', $this->getContext($request, [
                'plugin_name' => $plugin->getName(),
                'plugin_type' => $plugin::class,
            ]));
        }

        return $success;
    }

    /**
     * Determine the expiration time based on the request and offenses.
     *
     * Escalation periods are written in an array/yaml format that look like:
     *
     * blocking_escalation:
     *   - window: 300
     *     offense: 1
     *   - window: 3600
     *     offense: 3
     *     duration: 3600
     *   - window: 86400
     *     offense: 5
     *     duration: 0
     *
     * Setting the window is how far back to look and count the number of offenses recorded. This is required.
     * Setting the offense is how many offenses we need to count to be able to bypass. If omitted, this defaults to 0.
     * Setting the duration is how many seconds the request should be banned for. Setting it to 0 means that it
     * should be permanently banned. Not setting this will use the default amount sent in from the plugin.
     *
     * @param Request $request
     *   Request to evaluate.
     * @param int $initialTime
     *   Initial time.
     *
     * @return int
     *   Return the expiration time.
     */
    protected function determineExpirationTime(Request $request, int $initialTime = 0): int
    {
        if ($initialTime === 0) {
            return 0;
        }

        $now = time();

        $key = $this->storage->getKey($request);

        // Reverse the blocking_escalation elements to start from bottom and go up.
        $stages = array_reverse($this->config['blocking_escalation'] ?? [], true);
        foreach ($stages as $stage) {
            // Require the window amount to exist to acknowledge.
            if (!array_key_exists('window', $stage)) {
                continue;
            }

            $windowStart = $now - intval($stage['window']);
            $count = $this->storage->countOffenses($key, $windowStart, $now);

            if ($count >= intval($stage['offense'])) {
                return intval($stage['duration'] ?? $initialTime);
            }
        }

        if ($stages !== []) {
            return intval($stages[array_key_last($stages)]['duration'] ?? $initialTime);
        }

        return $initialTime;
    }
}
