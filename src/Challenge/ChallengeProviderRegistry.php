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

/**
 * Resolves challenge providers by name, one instance per name per request.
 *
 * `challenge.provider` used to be the only answer to "which challenge?", so
 * one provider was built at startup and every `response: challenge` plugin
 * got it. Plugins can now name their own (see
 * `ChallengeProviderAwareInterface`), which means several providers can be
 * live at once and the firewall has to be able to reach any of them by
 * name — when a plugin matches, and again when the solution comes back.
 *
 * This registry is that lookup. It keeps `ChallengeProviderFactory::create()`
 * as the single construction point and adds two things around it:
 *
 *   - **Memoisation.** A name resolves to the same instance for the life of
 *     the registry, so a provider is constructed at most once even if it is
 *     asked for on both halves of the round trip.
 *   - **Per-provider options.** With one provider, `challenge.provider_options`
 *     was flat and all of it belonged to that provider. With several, each
 *     needs its own block. See `optionsFor()` for how the two shapes coexist.
 *
 * ## What gets built, and when
 *
 * `warmUp()` constructs every provider named in configuration — the global
 * one plus each `metadata.challenge_provider` — while the firewall is being
 * built. That is deliberate: `TurnstileChallengeProvider` and
 * `RecaptchaChallengeProvider` refuse to construct without their key pair,
 * so building them at startup turns a missing `site_key` into a
 * configuration failure instead of a 500 on the first visitor unlucky
 * enough to trip that rule. Nothing here does I/O, so the cost is object
 * construction and option validation.
 *
 * Providers named only from PHP (a plugin implementing
 * `ChallengeProviderAwareInterface` without going through metadata) cannot
 * be discovered from config, so they are built on first use and a bad name
 * surfaces then.
 */
final class ChallengeProviderRegistry
{
    /**
     * Providers already constructed, keyed by the name they were asked for.
     *
     * @var array<string, ChallengeProviderInterface>
     */
    private array $instances = [];

    /**
     * Provider names declared by challenge plugins, from `warmUp()`.
     *
     * @var array<int, string>
     */
    private array $declared = [];

    /**
     * @param TokenManager $tokenManager
     *   Shared HMAC manager handed to every provider that wants one.
     * @param string $defaultProvider
     *   The `challenge.provider` value — used for plugins that name none,
     *   and the one provider a flat `provider_options` belongs to.
     * @param array<string, mixed> $providerOptions
     *   The `challenge.provider_options` block, in either shape.
     */
    public function __construct(
        private readonly TokenManager $tokenManager,
        private readonly string $defaultProvider,
        private readonly array $providerOptions = []
    ) {
    }

    /**
     * The `challenge.provider` name, used when a plugin names none.
     */
    public function getDefaultName(): string
    {
        return $this->defaultProvider;
    }

    /**
     * Resolve a provider by name, constructing it the first time.
     *
     * @param string $name
     *   A `challenge.provider` name. An empty string means the default.
     *
     * @throws ConfigurationException
     *   When the name resolves to nothing, to a class that is not a
     *   provider, or to a provider whose required options are missing.
     */
    public function get(string $name): ChallengeProviderInterface
    {
        $name = $name === '' ? $this->defaultProvider : $name;

        return $this->instances[$name] ??= ChallengeProviderFactory::create(
            $name,
            $this->tokenManager,
            $this->optionsFor($name)
        );
    }

    /**
     * Construct every provider named in configuration, failing fast.
     *
     * @param array<int, string> $names
     *   Provider names declared by challenge plugins. Duplicates and empty
     *   strings are tolerated; the default provider is always included.
     *
     * @throws ConfigurationException
     *   When any of them cannot be constructed.
     */
    public function warmUp(array $names): void
    {
        $this->declared = array_values(array_unique(array_filter(
            array_map(trim(...), $names)
        )));

        $this->get($this->defaultProvider);

        foreach ($this->declared as $name) {
            $this->get($name);
        }

        if ($this->hasOverrides()) {
            LoggingFactory::logMessage('debug', 'Per-plugin challenge providers active', [
                'default_provider' => $this->defaultProvider,
                'plugin_providers' => $this->declared,
            ]);
        }
    }

    /**
     * Does any plugin ask for a provider other than the global one?
     *
     * The firewall reads this to decide whether the pass-token check can
     * still short-circuit the whole challenge bucket before evaluating it:
     * with a single provider in play a valid token covers every challenge
     * rule, so the old ordering holds. Only once a plugin wants something
     * different does the matched rule have to be known before its token can
     * be judged.
     */
    public function hasOverrides(): bool
    {
        foreach ($this->declared as $name) {
            if ($name !== $this->defaultProvider) {
                return true;
            }
        }

        return false;
    }

    /**
     * Options to construct one provider with.
     *
     * Two shapes are accepted, because `provider_options` was flat when
     * only one provider could exist:
     *
     * ```yaml
     * # Nested — required once more than one provider is in play.
     * provider_options:
     *   recaptcha:
     *     site_key: '…'
     *   altcha:
     *     widget_src: /assets/altcha.min.js
     *
     * # Flat — still valid, and still belongs to `challenge.provider`.
     * provider_options:
     *   site_key: '…'
     *   secret_key: '…'
     * ```
     *
     * A block keyed by the provider's name always wins. Otherwise the flat
     * array is handed to the **default provider only** — a plugin-named
     * provider gets nothing, rather than being fed keys that were written
     * for a different service. Handing Turnstile's `secret_key` to
     * reCAPTCHA would look like it worked right up until Google rejected
     * every solution.
     *
     * @return array<string, mixed>
     *   Options for `ChallengeProviderFactory::create()`.
     */
    public function optionsFor(string $name): array
    {
        $name = $name === '' ? $this->defaultProvider : $name;
        $nested = $this->providerOptions[$name] ?? null;

        if (is_array($nested)) {
            /** @var array<string, mixed> $nested */
            return $nested;
        }

        return $name === $this->defaultProvider ? $this->providerOptions : [];
    }
}
