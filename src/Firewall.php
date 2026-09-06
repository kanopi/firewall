<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall;

use Kanopi\Firewall\Challenge\ChallengeProviderAwareInterface;
use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Challenge\ChallengeProviderRegistry;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\StorageException;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Logging\LoggingTrait;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Storage\StorageFactory;
use Kanopi\Firewall\Storage\StorageInterface;
use Kanopi\Firewall\Traits\RequestFieldTrait;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\PluginConfigNormalizer;
use Symfony\Component\HttpFoundation\Request;

/**
 * Firewall class that creates and evaluates requests.
 */
final class Firewall
{
    use LoggingTrait;
    use RequestFieldTrait;

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
     *   Provider named by `challenge.provider`, used for every challenge
     *   plugin that does not name one of its own. Required iff at least
     *   one challenge plugin is configured.
     * @param TokenManager|null $tokenManager
     *   Mints / verifies the pass token issued after a challenge is
     *   solved. Required iff $challengeProvider is set.
     * @param array<string, mixed> $challengeConfig
     *   Subset of config relevant to the challenge flow: path,
     *   cookie_name, header_name.
     * @param ChallengeProviderRegistry|null $challengeProviderRegistry
     *   Resolves the providers named by individual plugins. Built
     *   alongside $challengeProvider, which is the registry's default —
     *   holding it separately keeps the single-provider paths reading
     *   exactly as they did.
     */
    protected function __construct(
        private StorageInterface $storage,
        private PluginManager $blockingPluginManager,
        private PluginManager $bypassPluginManager,
        private PluginManager $challengePluginManager,
        private array $config,
        private ?ChallengeProviderInterface $challengeProvider = null,
        private ?TokenManager $tokenManager = null,
        private array $challengeConfig = [],
        private ?ChallengeProviderRegistry $challengeProviderRegistry = null
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
     * Configuration inputs are loaded leniently by default: a string that
     * does not reference a readable file, and an argument that is neither
     * string, array, nor null, are both skipped rather than raising. Unlike
     * before, a skipped or malformed input is no longer silent — each one is
     * logged at `error` level, and setting `global.require_config: true` (or
     * defining `KANOPI_FIREWALL_REQUIRE_CONFIG`) turns it into a startup
     * failure instead.
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
     * @throws ConfigurationException
     *   When challenge plugins are configured without a `challenge.secret`,
     *   when `challenge.provider` — or a provider named by a plugin's
     *   `metadata.challenge_provider` — cannot be resolved to a
     *   ChallengeProviderInterface, when `global.require_trusted_proxies`
     *   is enabled and no trusted proxies have been set, or when
     *   `global.require_config` is enabled and any config input failed to
     *   load.
     * @throws StorageException
     *   When the configured storage backend cannot create, read, or write
     *   its backing file, or — as `StorageConnectionException` — when a
     *   database-backed storage cannot reach its database.
     */
    public static function create(array $configs = [], array $overrides = []): self
    {
        // Load default config first. Clear first, read after: `Config::load()`
        // never throws, so the only evidence that a config file was missing,
        // unreadable, or malformed is the list it leaves behind.
        Config::clearLoadErrors();
        $config = Config::load(array_merge([__DIR__ . '/../config/config.yml'], $configs), $overrides);
        $configLoadErrors = Config::getLoadErrors();
        $configLoadWarnings = Config::getLoadWarnings();

        // Read the flag before the array_filter() below strips an explicit
        // `require_config: false` and makes it indistinguishable from unset.
        $requireConfig = self::requireConfig(
            isset($config['global']) && is_array($config['global']) ? $config['global'] : []
        );

        // Same reason, and the same trap: `behind_proxy: false` is the whole
        // point of the setting (#99), and array_filter() would strip it as a
        // falsy value before checkTrustedProxiesPosture() ever saw it —
        // leaving "asserted: no proxy" indistinguishable from "never said".
        $behindProxy = self::behindProxy(
            isset($config['global']) && is_array($config['global']) ? $config['global'] : []
        );

        // Set the default values.
        $config['logger'] = isset($config['logger']) && is_array($config['logger']) ? array_filter($config['logger']) : [];
        $config['storage'] = isset($config['storage']) && is_array($config['storage']) ? array_filter($config['storage']) : [];
        $config['global'] = isset($config['global']) && is_array($config['global']) ? array_filter($config['global']) : [];
        $config['challenge'] = isset($config['challenge']) && is_array($config['challenge']) ? $config['challenge'] : [];

        LoggingFactory::setLogger(LoggingFactory::create($config['logger']));

        // The logger only exists now, so this is the first moment a load
        // failure recorded above can actually reach an operator.
        self::reportConfigLoadFailures($configLoadErrors, $requireConfig);
        self::reportConfigLoadWarnings($configLoadWarnings);

        // Every plugin reads `$request->getClientIp()`. Symfony only honors
        // proxy headers (X-Forwarded-For, Forwarded, X-Real-IP, …) when the
        // integrator has called `Request::setTrustedProxies(...)`. If trusted
        // proxies aren't configured but the application sits behind a proxy
        // anyway, attackers can spoof their source IP via X-Forwarded-For
        // and trivially bypass IP/CIDR allowlists and per-IP rate limits.
        //
        // We can't detect "is there actually a proxy in front of me?" — that's
        // deployment-specific. What we can do is surface that the firewall is
        // currently trusting whatever Symfony does by default, and let the
        // operator assert the fact we cannot observe:
        //
        //   * `global.behind_proxy: false` — asserted: nothing in front of this
        //     deployment. The check is skipped silently.
        //   * `global.behind_proxy: true` — asserted: there IS a proxy, so a
        //     missing `Request::setTrustedProxies(...)` is a definite
        //     misconfiguration and is logged at `error`.
        //   * unset — the posture is genuinely unknown, so warn and continue.
        //     This one still fires per request, deliberately: it is an
        //     unresolved security question, and it is now resolvable from
        //     config rather than something an operator has to live with.
        //
        // `global.require_trusted_proxies: true` escalates whichever of those
        // applies into a startup `ConfigurationException`.
        self::checkTrustedProxiesPosture($config['global'], $behindProxy);

        // Normalize configuration to the new plugins: array format.
        $config = PluginConfigNormalizer::normalize($config);

        self::warnOnDuplicatePluginNames($config['plugins'] ?? []);

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

        [$challengeProvider, $tokenManager, $challengeConfig, $providerRegistry] = self::createChallengePieces(
            $config['challenge'],
            $partitioned['challenge']
        );

        $firewall = new self(
            StorageFactory::create($config['storage']),
            PluginManager::createFromPluginsArray($partitioned['block']),
            PluginManager::createFromPluginsArray($partitioned['allow']),
            PluginManager::createFromPluginsArray($partitioned['challenge']),
            $config['global'],
            $challengeProvider,
            $tokenManager,
            $challengeConfig,
            $providerRegistry
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
     * Returns `[provider|null, tokenManager|null, normalizedChallengeConfig,
     * registry|null]`. When no challenge plugins are present and no
     * challenge block was declared, the slots are empty/null and the
     * firewall acts as if the feature did not exist.
     *
     * Failing here (rather than at first request) keeps a missing secret
     * from looking like a 500 deep in the request lifecycle. The same goes
     * for a provider a plugin names: `warmUp()` constructs every one of
     * them now, so a typo or a missing `site_key` is a startup failure
     * rather than a surprise for the first visitor to trip that rule.
     *
     * @param array<string, mixed> $challengeConfig
     *   The `challenge:` section from the loaded YAML.
     * @param array<int, array<string, mixed>> $challengePlugins
     *   Plugin entries partitioned into the challenge bucket. Read for the
     *   providers they name; empty means the feature is not in use.
     *
     * @return array{0: ?ChallengeProviderInterface, 1: ?TokenManager, 2: array<string, mixed>, 3: ?ChallengeProviderRegistry}
     *
     * @throws ConfigurationException
     *   When challenge plugins exist but no secret is configured, or when
     *   a provider named by the config or by a plugin cannot be resolved.
     */
    private static function createChallengePieces(array $challengeConfig, array $challengePlugins): array
    {
        $hasChallengePlugins = $challengePlugins !== [];

        $defaults = [
            'provider' => 'math',
            'secret' => '',
            'cookie_name' => 'fw_challenge_pass',
            'header_name' => 'X-Firewall-Challenge',
            'path' => '/_firewall/challenge',
            'provider_options' => [],
            'audience' => '',
        ];

        $challengeConfig = array_replace($defaults, $challengeConfig);

        if (!$hasChallengePlugins) {
            return [null, null, $challengeConfig, null];
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
        $defaultProvider = (string) $challengeConfig['provider'];

        // Scope pass tokens so two instances sharing a secret but running
        // different challenges cannot accept each other's tokens. Defaults
        // to the provider name, which is what distinguishes them; operators
        // running the same provider in several places can override it.
        $audience = trim((string) ($challengeConfig['audience'] ?? ''));
        if ($audience === '') {
            $audience = $defaultProvider;
        }

        $tokenManager = new TokenManager($secret, $audience, $defaultProvider);

        $challengeProviderRegistry = new ChallengeProviderRegistry(
            $tokenManager,
            $defaultProvider,
            is_array($providerOptions) ? $providerOptions : []
        );
        $challengeProviderRegistry->warmUp(self::declaredChallengeProviders($challengePlugins));

        return [
            $challengeProviderRegistry->get($defaultProvider),
            $tokenManager,
            $challengeConfig,
            $challengeProviderRegistry,
        ];
    }

    /**
     * Collect the provider names the challenge plugins ask for.
     *
     * Read straight off the config entries rather than from constructed
     * plugins: plugins are lazily built (see `LazyObjectRegistry`), and
     * instantiating every challenge plugin at startup just to ask it which
     * provider it wants would undo that. The key read here is the same one
     * `AbstractPluginBase::getChallengeProviderName()` reads at request
     * time, so the two cannot disagree for plugins built on the base class.
     *
     * @param array<int, array<string, mixed>> $challengePlugins
     *   Plugin entries from the challenge bucket.
     *
     * @return array<int, string>
     *   Provider names, with duplicates and blanks left for the registry
     *   to normalize.
     */
    private static function declaredChallengeProviders(array $challengePlugins): array
    {
        $names = [];

        foreach ($challengePlugins as $challengePlugin) {
            $metadata = $challengePlugin['metadata'] ?? [];
            $provider = is_array($metadata) ? ($metadata['challenge_provider'] ?? null) : null;

            if (is_string($provider)) {
                $names[] = $provider;
            }
        }

        return $names;
    }

    /**
     * Is a complete config load mandatory for this firewall?
     *
     * Sources, in precedence order:
     *   1. `global.require_config` in the merged config — the normal place
     *      to set it, and reachable from an override
     *      (`['[global][require_config]' => true]`) as well as YAML.
     *   2. The `KANOPI_FIREWALL_REQUIRE_CONFIG` constant, following the same
     *      pattern as the `KANOPI_FIREWALL_CACHE_*` constants. This is the
     *      one that survives the case the flag exists for: when the *only*
     *      config file is the one that failed to load, its YAML cannot
     *      possibly carry the flag, so bootstrap PHP has to.
     *   3. Off — the 2.x default, so existing setups that pass optional
     *      config paths keep working.
     *
     * @param array<string, mixed> $globalConfig
     *   The `global` config section, before `array_filter()` strips falsey
     *   values.
     */
    private static function requireConfig(array $globalConfig): bool
    {
        if (array_key_exists('require_config', $globalConfig)) {
            return (bool) $globalConfig['require_config'];
        }

        return defined('KANOPI_FIREWALL_REQUIRE_CONFIG') && (bool) KANOPI_FIREWALL_REQUIRE_CONFIG;
    }

    /**
     * Warn when two plugin entries declare the same `metadata.name`.
     *
     * The point of naming a rule is telling it apart from the others in the
     * log, so two rules answering to `office` puts an operator back where they
     * started -- and silently, because nothing about the config looks wrong.
     *
     * A warning rather than an exception: a duplicate name is untidy rather
     * than dangerous. Nothing the firewall does depends on the name, only what
     * it says afterwards, and refusing to start over a label would be a worse
     * outcome than the ambiguity it prevents.
     *
     * Only declared names are checked. Two entries of the same class with no
     * name still share one, which is the status quo this feature exists to let
     * an operator opt out of -- warning about it would fire on almost every
     * configuration in existence and say nothing actionable.
     *
     * @param array<int|string, mixed> $plugins
     *   Plugin entries, after normalisation to the `plugins:` array format.
     */
    private static function warnOnDuplicatePluginNames(array $plugins): void
    {
        $seen = [];

        foreach ($plugins as $plugin) {
            // No `is_array()` guard: `??` already yields NULL for every entry
            // shape that has no such offset, and the `is_string()` test below
            // rejects it. An entry that is not an array at all does not reach
            // here in practice -- `partitionAndSort()` refuses it first.
            $name = $plugin['metadata']['name'] ?? null;

            if (!is_string($name)) {
                continue;
            }

            $name = trim($name);

            if ($name === '') {
                continue;
            }

            $seen[$name][] = is_string($plugin['plugin'] ?? null) ? $plugin['plugin'] : 'unknown';
        }

        foreach ($seen as $name => $classes) {
            if (count($classes) < 2) {
                continue;
            }

            LoggingFactory::logger()->warning('Two or more plugins declare the same name, so their log lines cannot be told apart', [
                'name' => $name,
                'declared_by' => $classes,
                'count' => count($classes),
            ]);
        }
    }

    /**
     * Surface config inputs that did not load (#78).
     *
     * `Config::loadFile()` returns `[]` for a missing, unreadable, or
     * malformed file. An empty plugin registry makes `PluginManager::
     * evaluate()` return false for every request, so a mistyped path used to
     * produce a firewall that allowed everything, with no exception and
     * nothing in the log to say why — a silent fail-open on a security
     * component.
     *
     * Behaviour mirrors `checkTrustedProxiesPosture()`:
     *   * default — log every failure at `error` and start anyway, because
     *     optional config paths are an established 2.x usage.
     *   * `global.require_config: true` — refuse to start, so a deploy that
     *     renames or fails to ship a config file fails the deploy instead of
     *     quietly disabling the firewall.
     *
     * @param array<int, array{file: string, message: string}> $errors
     *   Failures recorded by `Config::load()`.
     * @param bool $requireConfig
     *   Whether a complete load is mandatory.
     *
     * @throws ConfigurationException
     *   When `$requireConfig` is true and at least one input failed.
     */
    protected static function reportConfigLoadFailures(array $errors, bool $requireConfig): void
    {
        if ($errors === []) {
            return;
        }

        foreach ($errors as $error) {
            LoggingFactory::logger()->error(
                'Firewall config file failed to load — its rules are NOT active',
                [
                    'file' => $error['file'],
                    'reason' => $error['message'],
                    'require_config' => $requireConfig,
                ]
            );
        }

        if (!$requireConfig) {
            return;
        }

        throw new ConfigurationException(sprintf(
            'global.require_config is enabled and %d config input(s) failed to load: %s',
            count($errors),
            implode('; ', array_map(
                static fn (array $error): string => $error['file'] . ' — ' . $error['message'],
                $errors
            ))
        ));
    }

    /**
     * Report config inputs that loaded, but not from where they should have.
     *
     * Warnings and failures are reported separately on purpose. A failure means
     * rules are missing, which `global.require_config` may reasonably refuse to
     * start over. A warning means the rules are present but stale — a remote
     * include served from cache after the fetch failed. Escalating that to a
     * failure would take a site down over a momentary DNS blip while a
     * known-good copy sat on disk, which is the opposite of what the fallback
     * exists to do.
     *
     * @param array<int, array{file: string, message: string}> $warnings
     *   Degraded loads recorded by `Config::load()`.
     */
    protected static function reportConfigLoadWarnings(array $warnings): void
    {
        foreach ($warnings as $warning) {
            LoggingFactory::logger()->warning(
                'Firewall config loaded in a degraded state',
                [
                    'file' => $warning['file'],
                    'reason' => $warning['message'],
                ]
            );
        }
    }

    /**
     * Resolve `global.behind_proxy` into the operator's asserted posture.
     *
     * Must be called on the raw global config, before `create()` runs
     * `array_filter()` over it — see the call site.
     *
     * Accepts the boolean-ish strings `filter_var()` understands ("false",
     * "0", "no", "off" and their true counterparts) so a value arriving from
     * an `%env()%` token or a quoted YAML scalar behaves like a real boolean.
     *
     * @param array<string, mixed> $globalConfig
     *   The `global` config section, unfiltered.
     *
     * @return bool|null
     *   TRUE or FALSE when the operator asserted a posture, NULL when the key
     *   is absent or its value is not interpretable as a boolean. NULL means
     *   "unknown", which warns — failing safe, because silencing a security
     *   warning is the dangerous direction to guess in.
     */
    private static function behindProxy(array $globalConfig): ?bool
    {
        if (!array_key_exists('behind_proxy', $globalConfig)) {
            return null;
        }

        $value = $globalConfig['behind_proxy'];

        // `behind_proxy:` with nothing after it parses to NULL, and an
        // `%env()%` token resolving to an unset variable gives ''. filter_var()
        // reads both as FALSE, which would silence a security warning because
        // someone left a key half-written. Neither is an assertion, so treat
        // them as "unknown" and let the warning stand.
        if ($value === null || $value === '') {
            return null;
        }

        return filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
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
     * Two settings interact, because they answer two different questions.
     *
     * `global.behind_proxy` states a fact about the deployment that the
     * library cannot observe for itself (#99):
     *   * `false` — asserted: no proxy in front of this deployment. Nothing
     *     can spoof a forwarding header past a proxy that does not exist, so
     *     the check returns silently. This is the only way to stop the
     *     warning without lying to `Request::setTrustedProxies()`.
     *   * `true` — asserted: there IS a proxy. Missing trusted proxies is
     *     then a definite misconfiguration rather than an open question, so
     *     it is logged at `error` instead of `warning`.
     *   * unset — unknown. Warn, as 2.x always has.
     *
     * `global.require_trusted_proxies` decides how loud the unresolved cases
     * are, and is unchanged from 2.x:
     *   * `false` / unset (default) — log only.
     *   * `true` — throw `ConfigurationException` at startup so a missing
     *     trusted-proxies setup is a hard failure in production.
     *
     * `behind_proxy: false` wins over `require_trusted_proxies: true`: an
     * explicit assertion that there is no proxy makes the requirement moot,
     * and throwing anyway would leave the operator with no way to run.
     *
     * @param array<string, mixed> $globalConfig
     *   The `global` config section.
     * @param bool|null $behindProxy
     *   The operator's asserted posture, resolved by `behindProxy()` from the
     *   unfiltered config. NULL when they did not say.
     *
     * @throws ConfigurationException
     *   When `require_trusted_proxies` is true, no trusted proxies have been
     *   configured before `Firewall::create()` runs, and `behind_proxy` has
     *   not asserted that there is no proxy.
     */
    protected static function checkTrustedProxiesPosture(array $globalConfig, ?bool $behindProxy = null): void
    {
        if (Request::getTrustedProxies() !== []) {
            return;
        }

        // Asserted "there is no proxy": nothing to spoof through, so there is
        // nothing to report. Checked before `require_trusted_proxies` on
        // purpose — see the docblock.
        if ($behindProxy === false) {
            return;
        }

        $require = !empty($globalConfig['require_trusted_proxies']);

        $message = 'Symfony Request::getTrustedProxies() is empty. If this '
            . 'application sits behind a proxy / load balancer, the firewall '
            . 'cannot trust the client IP and IP-based block / allow / rate-'
            . 'limit rules can be bypassed via X-Forwarded-For. Call '
            . 'Request::setTrustedProxies(...) before Firewall::create() with '
            . 'the proxy CIDRs and the header bitmask you trust. If nothing '
            . 'is in front of this deployment, set global.behind_proxy=false '
            . 'to assert that and silence this message. Set '
            . 'global.require_trusted_proxies=true to make this a fatal '
            . 'startup error.';

        if ($behindProxy === true) {
            $message = 'global.behind_proxy is true but Symfony '
                . 'Request::getTrustedProxies() is empty, so the firewall '
                . 'cannot trust the client IP behind the proxy you have '
                . 'declared: IP-based block / allow / rate-limit rules can be '
                . 'bypassed via X-Forwarded-For. Call '
                . 'Request::setTrustedProxies(...) before Firewall::create() '
                . 'with the proxy CIDRs and the header bitmask you trust.';
        }

        if ($require) {
            LoggingFactory::logger()->error($message);
            throw new ConfigurationException($message);
        }

        // An asserted-but-unwired proxy is a known defect, not an open
        // question, so it earns `error` rather than `warning`.
        if ($behindProxy === true) {
            LoggingFactory::logger()->error($message);
            return;
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
     *   Always TRUE when the request is allowed through. A blocked or
     *   challenged request never returns — in production the response is
     *   written and the process exits, and in `mode: exception` one of the
     *   exceptions below is thrown instead.
     *
     * @throws FirewallBlockedException
     *   In `mode: exception`, when a blocking plugin matches or the request
     *   key is already on the block list.
     * @throws ChallengeRequiredException
     *   In `mode: exception`, when a challenge plugin matches and no valid
     *   pass token is held, or when a posted solution is invalid.
     * @throws ChallengeSolvedException
     *   In `mode: exception`, when a posted challenge solution is valid.
     * @throws ConfigurationException
     *   In every mode, when a challenge plugin matches but no challenge
     *   provider is configured. `create()` normally rejects that wiring
     *   first, so this is a defensive last resort.
     */
    public function evaluate(?Request $request = null): bool
    {
        // @codeCoverageIgnoreStart
        if ($this->shouldBypassForCli()) {
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

        // Intercept challenge solutions before plugin evaluation so a POST
        // to the magic path can never be blocked by an unrelated rule (e.g.
        // a URL plugin matching the magic path itself) — which would trap a
        // legitimate visitor in a challenge loop with no way out. The
        // durable storage blocklist is the one exception: an IP that already
        // earned a block does not get to solve its way back out.
        if ($this->isChallengeSubmission($request)) {
            $this->enforceStorageBlocklist($request);
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

        $this->enforceStorageBlocklist($request);

        // A held pass token short-circuits the challenge bucket. Block
        // plugins still run — the token only attests "I am human", not
        // "I am allowed everywhere".
        //
        // That short-circuit only holds while one provider serves every
        // challenge rule, because then any pass token covers all of them.
        // Once a plugin names its own provider, a token is worth only what
        // its holder actually solved, so which rule matched has to be known
        // before its token can be judged — the bucket is evaluated first
        // and the token is checked against the matched plugin below.
        $hasValidToken = !$this->hasPerPluginChallengeProviders()
            && $this->hasValidChallengeToken($request, $this->defaultChallengeProviderName());

        if (!$hasValidToken && ($plugin = $this->challengePluginManager->evaluate($request)) !== false) {
            $providerName = $this->challengeProviderNameFor($plugin);

            if ($this->hasValidChallengeToken($request, $providerName)) {
                $this->getLogger()->debug('Challenge satisfied by held pass token', $this->getContext($request, [
                    'plugin_name' => $plugin->getName(),
                    'plugin_type' => $plugin::class,
                    'provider' => $providerName,
                ]));
            } elseif ($this->firewallMode === FirewallMode::Log) {
                $this->getLogger()->warning('Request would be challenged (log mode)', $this->getContext($request, [
                    'mode' => 'log',
                    'plugin_name' => $plugin->getName(),
                    'plugin_type' => $plugin::class,
                ]));
                return true;
            } else {
                $this->sendChallengeResponse($request, $plugin);
            }
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
     * Should this invocation skip evaluation because it is a CLI process?
     *
     * Drush, cron and WP-CLI have no visitor to protect and no response to
     * write, so evaluating them is at best wasted work and at worst a
     * blocked deploy script. `mode: exception` opts out because that is the
     * mode frameworks and test suites use, where the caller handles the
     * outcome itself rather than relying on the process exiting.
     *
     * Extracted into a method purely so it can be overridden. Every mode but
     * `exception` returns early here under PHP_SAPI === 'cli', which meant the
     * `log` and `disabled` branches in `evaluate()` could not be reached from
     * a test at all — the mode tests that appeared to cover them were passing
     * on this return instead, asserting nothing about the behaviour they named.
     *
     * @return bool
     *   TRUE when evaluation should be skipped entirely.
     */
    protected function shouldBypassForCli(): bool
    {
        return PHP_SAPI === 'cli' && $this->firewallMode !== FirewallMode::Exception;
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
     *   In Exception mode when the solution does not verify, or when it
     *   verifies but has already been spent (see
     *   `consumeSingleUseSolution()`).
     */
    protected function handleChallengeSubmission(Request $request): void
    {
        if (!$this->challengeProvider instanceof \Kanopi\Firewall\Challenge\ChallengeProviderInterface || !$this->tokenManager instanceof \Kanopi\Firewall\Challenge\TokenManager) {
            // Defensive — isChallengeSubmission() already gated this.
            return;
        }

        [$providerName, $challengeProvider] = $this->resolveSubmissionProvider($request);

        // An unresolvable provider claim is refused outright rather than
        // quietly verified by the default provider: the field is signed, so
        // a bad one is either tampering or a firewall whose config changed
        // under a rendered page, and neither should mint a token.
        $valid = $challengeProvider instanceof ChallengeProviderInterface
            && $challengeProvider->verifySolution($request);
        $reason = $challengeProvider instanceof ChallengeProviderInterface
            ? 'invalid_solution'
            : 'unknown_provider';

        // A stateless verify accepts the same payload every time it is
        // posted. For providers that opt in, burn the solution here so the
        // work behind it cannot be redistributed and reused.
        if ($valid && !$this->consumeSingleUseSolution($request, $challengeProvider)) {
            $valid = false;
            $reason = 'solution_already_used';
        }

        if (!$valid) {
            $this->getLogger()->info('Challenge solution rejected', $this->getContext($request, [
                'provider' => $challengeProvider?->getName() ?? $providerName,
                'reason' => $reason,
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

        // Both fields ride in on the interstitial's POST, so both are
        // attacker-chosen. Read them off the raw bag — InputBag::get() throws
        // on an array value, and nothing above this frame catches it (#130).
        // An absent or non-string ttl falls back to the default hour; an
        // absent or non-string redirect falls back to the site root, which is
        // what sanitizeRedirect() would have reduced a hostile one to anyway.
        $rawTtl = $this->postedString($request, ChallengeProviderInterface::TTL_FIELD);
        $ttl = $rawTtl === '' ? 3600 : max(0, (int) $rawTtl);

        // Scope the token to what was actually solved. Without this a math
        // pass would satisfy a reCAPTCHA rule, and the cheapest challenge
        // in the config would set the price of every other one.
        $token = $this->tokenManager->mint($request, $ttl, $providerName);

        $rawRedirect = $this->postedString($request, ChallengeProviderInterface::REDIRECT_FIELD, false);
        $redirect = $this->sanitizeRedirect($rawRedirect === '' ? '/' : $rawRedirect);

        $this->getLogger()->info('Challenge solution accepted', $this->getContext($request, [
            'provider' => $challengeProvider->getName(),
            'provider_name' => $providerName,
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
     * Prefix for the signed provider name carried by the interstitial.
     *
     * Domain-separates that signature from every other use of
     * `TokenManager::sign()` — notably the math provider's `answer|exp`
     * state — so a value signed for one purpose can never be presented as
     * a value signed for the other.
     */
    private const PROVIDER_SIGNATURE_PREFIX = 'challenge-provider:';

    /**
     * Sign a provider name for the interstitial to carry back.
     *
     * Produces `name.signature`. The name is not a secret; the signature
     * is what stops the field being rewritten to name a provider the
     * firewall never chose for this visitor.
     */
    protected function signProviderName(string $provider): string
    {
        if (!$this->tokenManager instanceof TokenManager || $provider === '') {
            return '';
        }

        return $provider . '.' . $this->tokenManager->sign(self::PROVIDER_SIGNATURE_PREFIX . $provider);
    }

    /**
     * Work out which provider a posted solution is answering.
     *
     * The matched plugin is long gone by the time a solution arrives — this
     * is a fresh POST to `challenge.path` — so the interstitial carries the
     * provider's name back in a signed hidden field.
     *
     * Three outcomes:
     *   - **No field.** Verified by `challenge.provider`, exactly as before
     *     this existed. Keeps custom providers that render their own
     *     document working, and costs nothing: the pass token is then
     *     scoped to that provider, so it opens only the rules that provider
     *     serves.
     *   - **A field that verifies.** Its provider is resolved and used.
     *   - **Anything else** — malformed, wrong signature, or a name that no
     *     longer resolves. Returns no provider, and the caller refuses the
     *     submission.
     *
     * @return array{0: string,1: ?ChallengeProviderInterface}
     *   The provider name and its instance, or NULL for the instance when
     *   the claim could not be honoured.
     */
    protected function resolveSubmissionProvider(Request $request): array
    {
        $default = $this->defaultChallengeProviderName();

        $posted = $this->postedString($request, ChallengeProviderInterface::PROVIDER_FIELD, false);
        if ($posted === '') {
            return [$default, $this->challengeProvider];
        }

        // Split on the LAST dot: the signature is base64url and carries
        // none, but a provider named by FQCN or by a custom short name may.
        $separator = strrpos($posted, '.');
        if ($separator === false || $separator === 0) {
            return ['', null];
        }

        $name = substr($posted, 0, $separator);
        $signature = substr($posted, $separator + 1);

        if ($signature === '' || !$this->tokenManager instanceof TokenManager) {
            return ['', null];
        }

        if (!$this->tokenManager->verifySignature(self::PROVIDER_SIGNATURE_PREFIX . $name, $signature)) {
            return ['', null];
        }

        if (!$this->challengeProviderRegistry instanceof ChallengeProviderRegistry) {
            return [$name, $this->challengeProvider];
        }

        try {
            return [$name, $this->challengeProviderRegistry->get($name)];
        } catch (ConfigurationException $configurationException) {
            // Signed, so this is the firewall's own name coming back — the
            // config must have changed while the page was open. Log it:
            // unlike a tampered field, it points at a real misconfiguration.
            $this->getLogger()->error('Challenge submission named an unresolvable provider', $this->getContext($request, [
                'provider' => $name,
                'error' => $configurationException->getMessage(),
            ]));

            return [$name, null];
        }
    }

    /**
     * Record a single-use solution, refusing one that was already spent.
     *
     * Only applies to providers implementing SingleUseSolutionInterface;
     * everything else is waved through, so custom providers and the math
     * provider are unaffected.
     *
     * Note this is a read-then-write against the storage backend, which
     * exposes no atomic add. Two submissions of the same solution racing
     * within the same instant can therefore both succeed. That narrows the
     * window from the full challenge lifetime to microseconds, which is
     * what matters here — the attack this closes is redistributing one
     * solve to many clients over seconds or minutes, not winning a race.
     *
     * @param Request $request
     *   The POST carrying the solution.
     * @param ChallengeProviderInterface|null $challengeProvider
     *   The provider that just verified it. NULL means the globally
     *   configured one, which is what it always was before providers
     *   could vary per plugin.
     *
     * @return bool
     *   TRUE when the solution had not been used before (or the provider
     *   does not track reuse), FALSE when this is a replay.
     */
    protected function consumeSingleUseSolution(Request $request, ?ChallengeProviderInterface $challengeProvider = null): bool
    {
        $challengeProvider ??= $this->challengeProvider;

        if (!$challengeProvider instanceof \Kanopi\Firewall\Challenge\SingleUseSolutionInterface) {
            return true;
        }

        $receipt = $challengeProvider->getSolutionReceipt($request);
        if ($receipt === null) {
            return true;
        }

        // Hashed so the raw challenge value never lands in the store.
        $key = 'fw_challenge_solution:' . hash('sha256', $receipt['id']);

        if ($this->storage->get($key) !== null) {
            return false;
        }

        // Storage treats the third argument as a lifetime in seconds. Keep
        // the record only until the solution would expire on its own.
        $ttl = max(1, $receipt['expires'] - time());
        $this->storage->set($key, ['consumed_at' => time()], $ttl);

        return true;
    }

    /**
     * Render the challenge interstitial for the matched plugin.
     *
     * @throws ChallengeRequiredException
     *   In Exception mode.
     * @throws ConfigurationException
     *   When a challenge plugin matched but no provider is wired up — or
     *   when the plugin names a provider that cannot be resolved, which
     *   only a plugin naming one from PHP can reach, since names coming
     *   from config were all resolved at startup. Raised in every mode
     *   rather than serving an empty page.
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

        $providerName = $this->challengeProviderNameFor($plugin);
        $challengeProvider = $this->challengeProviderRegistry instanceof ChallengeProviderRegistry
            ? $this->challengeProviderRegistry->get($providerName)
            : $this->challengeProvider;

        $ttl = $plugin->getExpirationTime($request);
        if ($ttl <= 0) {
            $ttl = 3600;
        }

        $this->getLogger()->notice('Sending challenge response', $this->getContext($request, [
            'plugin_name' => $plugin->getName(),
            'plugin_type' => $plugin::class,
            'provider' => $challengeProvider->getName(),
            'provider_name' => $providerName,
            'ttl' => $ttl,
        ]));

        if ($this->firewallMode === FirewallMode::Exception) {
            throw new ChallengeRequiredException(sprintf(
                'Challenge required by plugin: %s',
                $plugin->getName()
            ));
        }

        // @codeCoverageIgnoreStart
        $body = $challengeProvider->renderInterstitial($request, [
            'submit_url' => (string) ($this->challengeConfig['path'] ?? '/_firewall/challenge'),
            'redirect_to' => $this->sanitizeRedirect($request->getRequestUri()),
            'ttl' => (string) $ttl,
            'cookie_name' => (string) ($this->challengeConfig['cookie_name'] ?? ''),
            'header_name' => (string) ($this->challengeConfig['header_name'] ?? ''),
            'provider_token' => $this->signProviderName($providerName),
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
     * Is any plugin asking for a provider other than `challenge.provider`?
     *
     * Answered from the registry, which was told at startup what the
     * challenge plugins declared. FALSE keeps the pre-existing ordering:
     * one provider serves everything, so a pass token can still be judged
     * before knowing which rule it will be spent on.
     */
    protected function hasPerPluginChallengeProviders(): bool
    {
        return $this->challengeProviderRegistry instanceof ChallengeProviderRegistry
            && $this->challengeProviderRegistry->hasOverrides();
    }

    /**
     * Which provider serves this plugin's challenges?
     *
     * Falls back to `challenge.provider` for plugins that name none, which
     * is every plugin until someone sets `metadata.challenge_provider`.
     * Pure string work — resolving the name to an instance can fail, and
     * the token check has no business throwing.
     */
    protected function challengeProviderNameFor(PluginInterface $plugin): string
    {
        $name = $plugin instanceof ChallengeProviderAwareInterface
            ? $plugin->getChallengeProviderName()
            : null;

        if ($name !== null && $name !== '') {
            return $name;
        }

        return $this->defaultChallengeProviderName();
    }

    /**
     * The `challenge.provider` name.
     *
     * Read from the registry, which holds the resolved value. The config
     * fallback covers a firewall built without one — every challenge path
     * is gated on a provider existing, so it is a guard rather than a case
     * that happens.
     */
    protected function defaultChallengeProviderName(): string
    {
        return $this->challengeProviderRegistry instanceof ChallengeProviderRegistry
            ? $this->challengeProviderRegistry->getDefaultName()
            : (string) ($this->challengeConfig['provider'] ?? '');
    }

    /**
     * Does the request carry a pass token that verifies for this client?
     *
     * Looks first in the cookie, then in the configured custom header
     * (the localStorage delivery path used by SPA callers whose XHRs
     * cannot rely on cookies).
     *
     * @param Request $request
     *   The request being evaluated.
     * @param string|null $provider
     *   Provider the token must have been earned against. NULL accepts a
     *   token from any provider, which is only safe where a single one
     *   serves every challenge rule.
     */
    protected function hasValidChallengeToken(Request $request, ?string $provider = null): bool
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

        return $this->tokenManager->verify($token, $request, $provider);
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
     * Enforce the durable storage blocklist for this request key.
     *
     * Returns quietly when the key is not on the list. When it is, the
     * offense is recorded and the request is terminated — the blocklist is
     * durable repeat-offender state, so nothing downstream (including a
     * validly signed challenge solution) gets to undo it.
     *
     * `mode: log` is the exception: it is a dry-run mode, so a listed key is
     * reported at `warning` level and the request continues. Recording the
     * offense would extend a real ban from an audit-only deployment, and
     * terminating would make `log` indistinguishable from `block` for every
     * repeat offender.
     *
     * @param Request $request
     *   Request to evaluate.
     *
     * @throws FirewallBlockedException
     *   In `mode: exception`, when the request key is on the block list.
     *   `mode: log` logs and returns; every other mode writes the response
     *   and exits.
     */
    protected function enforceStorageBlocklist(Request $request): void
    {
        $data = $this->storage->isBlocked($this->storage->getKey($request));
        if ($data === false) {
            return;
        }

        if (array_key_exists('event_id', $data)) {
            $request->attributes->set('x-request-id', $data['event_id']);
        }

        if ($this->firewallMode === FirewallMode::Log) {
            $this->getLogger()->warning('Request would be blocked by storage blocklist (log mode)', $this->getContext($request, [
                'mode' => 'log',
            ]));
            return;
        }

        $this->repeatOffender($request);
        $this->sendBlockingResponse($request, intval($this->config['repeat_offender_status'] ?? 0));
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
     *   In `mode: exception`. Every other mode writes the status code and
     *   message to the response and exits.
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
                //
                // Read off the raw bag rather than through InputBag::get(),
                // which throws on an array value — `?q[]=1` against a template
                // using this token would otherwise turn a block page into an
                // uncaught exception (#130). $sanitize() already renders a
                // non-scalar as '', so an array simply interpolates empty.
                if (str_starts_with($key, 'request.query.')) {
                    $param = substr($key, 14);
                    return $sanitize($request->query->all()[$param] ?? '');
                }

                // 4. request.post.<param>  (body fields), same treatment
                if (str_starts_with($key, 'request.post.')) {
                    $param = substr($key, 13);
                    return $sanitize($request->request->all()[$param] ?? '');
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
