<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility\ReverseDns;

use Kanopi\Firewall\Exception\ConfigurationException;

/**
 * `global.reverse_dns`: which resolver each verifying rule uses (#473).
 *
 * ```yaml
 * global:
 *   reverse_dns:
 *     provider: cloudflare        # a built-in, or one defined below
 *     timeout_ms: 300             # shared: the limit on each DNS-over-HTTPS lookup
 *     providers:                  # a site's own, in the shape the built-ins have
 *       internal:
 *         resolver: "Kanopi\\Firewall\\Utility\\ReverseDns\\DnsOverHttpResolver"
 *         options:
 *           endpoint: "https://resolver.internal/dns-query?name={{ dns.name }}&type={{ dns.type }}"
 *           address: 10.0.0.53
 * ```
 *
 * Or, with no provider, a resolver named directly:
 *
 * ```yaml
 * global:
 *   reverse_dns:
 *     resolver: "App\\Firewall\\PlatformDnsResolver"
 *     resolver_options: { base_url: "https://dns.platform.internal" }
 * ```
 *
 * A rule's resolver is, in order: its `verify_provider`; the global `provider`; the global
 * `resolver`; and otherwise `SystemResolver`, PHP's own lookups -- what every release before
 * this one used, so a site that sets nothing here changes nothing.
 *
 * The rules, each checked at startup:
 *
 * - **`provider` and `resolver` together is an error.** It is ambiguous which was meant.
 * - **A provider is used whole.** Its options cannot be overridden one at a time; a site
 *   that wants different ones defines a provider of its own. Overriding parts separately is
 *   how two definitions' settings combine into one that neither describes.
 * - **A rule picks only a provider** (`verify_provider`), and `verify_timeout_ms`.
 * - **Built-in names are reserved,** so `cloudflare` always means the shipped definition.
 *
 * Held statically, as `LoggingFactory` holds the logger: rules are built lazily and know
 * only their own metadata, and `Firewall::create()` validates this once, before any rule is.
 */
final class ReverseDnsSettings
{
    /**
     * Keys `global.reverse_dns` takes.
     *
     * @var list<string>
     */
    private const KEYS = ['provider', 'providers', 'resolver', 'resolver_options', 'timeout_ms'];

    /**
     * What a provider name may look like.
     */
    private const NAME_PATTERN = '/^[a-z0-9][a-z0-9_-]*$/';

    /**
     * The settings `Firewall::create()` validated, or NULL for none yet.
     */
    private static ?self $current = null;

    /**
     * Resolvers already built, by provider or resolver and timeout.
     *
     * @var array<string, ReverseDnsResolverInterface>
     */
    private array $resolvers = [];

    /**
     * @param array<string, mixed> $settings
     *   `global.reverse_dns`, validated.
     */
    private function __construct(private readonly array $settings)
    {
    }

    /**
     * Validate the configuration and make it the one rules read.
     *
     * @param array<string, mixed> $global
     *   The `global:` section.
     * @param array<int, mixed> $declaredPlugins
     *   The `plugins:` entries, for their `verify_provider`.
     *
     * @throws ConfigurationException
     *   Naming every problem.
     */
    public static function configure(array $global, array $declaredPlugins = []): void
    {
        $problems = self::problems($global, $declaredPlugins);

        if ($problems !== []) {
            throw new ConfigurationException('global.reverse_dns: ' . implode('; ', $problems));
        }

        $reverseDnsSettings = new self(self::section($global));

        // Built now, as `ChallengeProviderRegistry::warmUp()` builds challenge providers:
        // a resolver whose constructor refuses its options is a startup failure, not an
        // error on the first crawler. Building one does no I/O.
        $reverseDnsSettings->resolverFor([]);

        foreach ($declaredPlugins as $declaredPlugin) {
            if (is_array($declaredPlugin) && is_array($declaredPlugin['metadata'] ?? null) && ($declaredPlugin['metadata']['verify'] ?? null) !== null) {
                $reverseDnsSettings->resolverFor($declaredPlugin['metadata']);
            }
        }

        self::$current = $reverseDnsSettings;
    }

    /**
     * The configured settings, or empty ones -- `SystemResolver` for every rule -- when
     * none have been configured.
     */
    public static function current(): self
    {
        return self::$current ??= new self([]);
    }

    /**
     * Forget the configured settings. For tests.
     */
    public static function reset(): void
    {
        self::$current = null;
    }

    /**
     * Settings read from a `global:` section, without validating or keeping them.
     *
     * For `firewall-doctor`, which reports on a configuration without starting it.
     *
     * @param array<string, mixed> $global
     *   The `global:` section.
     */
    public static function fromGlobal(array $global): self
    {
        return new self(self::section($global));
    }

    /**
     * Everything wrong with the configuration, without building anything.
     *
     * @param array<string, mixed> $global
     *   The `global:` section.
     * @param array<int, mixed> $declaredPlugins
     *   The `plugins:` entries.
     *
     * @return list<string>
     *   Problems, empty when the configuration can be used.
     */
    public static function problems(array $global, array $declaredPlugins = []): array
    {
        $raw = $global['reverse_dns'] ?? null;

        if ($raw !== null && !is_array($raw)) {
            return [sprintf('must be a map, not %s', get_debug_type($raw))];
        }

        $section = is_array($raw) ? $raw : [];
        $problems = [];

        foreach (array_diff(array_map(strval(...), array_keys($section)), self::KEYS) as $unknown) {
            $problems[] = sprintf('unknown key "%s"; the keys are %s', $unknown, implode(', ', self::KEYS));
        }

        $providers = $section['providers'] ?? [];

        if (!is_array($providers)) {
            $problems[] = 'providers must be a map of provider names to definitions';
            $providers = [];
        }

        foreach ($providers as $name => $definition) {
            foreach (self::providerProblems((string) $name, $definition) as $problem) {
                $problems[] = $problem;
            }
        }

        $known = array_merge(BuiltinProviders::names(), array_map(strval(...), array_keys($providers)));
        $provider = $section['provider'] ?? null;
        $resolver = $section['resolver'] ?? null;

        if ($provider !== null) {
            if (!is_string($provider) || $provider === '') {
                $problems[] = 'provider must be a provider name';
            } elseif (!in_array($provider, $known, true)) {
                $problems[] = self::unknownProvider($provider, $known);
            }
        }

        if ($provider !== null && $resolver !== null) {
            $problems[] = 'provider and resolver are both set; set one. A provider brings its own resolver';
        }

        if ($provider !== null && array_key_exists('resolver_options', $section)) {
            $problems[] = 'resolver_options is set with provider; a provider brings its own options';
        }

        if ($resolver !== null) {
            foreach (self::resolverProblems($resolver, $section['resolver_options'] ?? [], 'resolver', $known) as $problem) {
                $problems[] = $problem;
            }
        } elseif (array_key_exists('resolver_options', $section)) {
            $problems[] = 'resolver_options is set without a resolver';
        }

        if (array_key_exists('timeout_ms', $section)) {
            foreach (self::timeoutProblems($section['timeout_ms'], 'timeout_ms') as $problem) {
                $problems[] = $problem;
            }
        }

        foreach ($declaredPlugins as $index => $declaredPlugin) {
            $metadata = is_array($declaredPlugin) && is_array($declaredPlugin['metadata'] ?? null)
                ? $declaredPlugin['metadata']
                : [];

            $label = sprintf('rule "%s"', is_string($metadata['name'] ?? null) ? $metadata['name'] : '#' . $index);

            if (array_key_exists('verify_provider', $metadata)) {
                $ruleProvider = $metadata['verify_provider'];

                if (!is_string($ruleProvider) || $ruleProvider === '') {
                    $problems[] = $label . ' verify_provider must be a provider name';
                } elseif (!in_array($ruleProvider, $known, true)) {
                    $problems[] = $label . ' verify_provider: ' . self::unknownProvider($ruleProvider, $known);
                }
            }

            if (array_key_exists('verify_timeout_ms', $metadata)) {
                foreach (self::timeoutProblems($metadata['verify_timeout_ms'], $label . ' verify_timeout_ms') as $problem) {
                    $problems[] = $problem;
                }
            }

            foreach (['verify_resolver', 'verify_resolver_options'] as $unsupported) {
                if (array_key_exists($unsupported, $metadata)) {
                    $problems[] = sprintf(
                        '%s sets %s; a rule picks a provider with verify_provider instead, so define one under global.reverse_dns.providers',
                        $label,
                        $unsupported
                    );
                }
            }
        }

        return $problems;
    }

    /**
     * The resolver a rule uses, or NULL for the verifier's own default.
     *
     * NULL rather than a `SystemResolver` when nothing is configured, so the verifier keeps
     * using its own `reverseLookup()` and `forwardLookup()` -- which a subclass written
     * before resolvers existed may override.
     *
     * @param array<string, mixed> $metadata
     *   The rule's metadata.
     *
     * @throws ConfigurationException
     *   When the provider or resolver cannot be built, which `configure()` would already
     *   have refused.
     */
    public function resolverFor(array $metadata): ?ReverseDnsResolverInterface
    {
        $choice = $this->choiceFor($metadata);

        if ($choice === null) {
            return null;
        }

        [$class, $options] = $choice;
        $timeout = $this->timeoutFor($metadata);

        if ($timeout !== null && is_a($class, DnsOverHttpResolver::class, true)) {
            $options['timeout_ms'] = $timeout;
        }

        $key = $class . '|' . md5(serialize($options));

        return $this->resolvers[$key] ??= $this->instantiate($class, $options);
    }

    /**
     * Where a rule's lookups go, for `firewall-doctor`.
     *
     * @param array<string, mixed> $metadata
     *   The rule's metadata.
     *
     * @return array{resolver: string, provider: ?string, endpoint: ?string, address: ?string}
     *   The resolver class, the provider if one was chosen, and for a DNS-over-HTTPS
     *   resolver the endpoint's host and the pinned address.
     */
    public function describeFor(array $metadata): array
    {
        $choice = $this->choiceFor($metadata);

        if ($choice === null) {
            return ['resolver' => SystemResolver::class, 'provider' => null, 'endpoint' => null, 'address' => null];
        }

        [$class, $options, $provider] = $choice;
        $endpoint = null;

        if (is_a($class, DnsOverHttpResolver::class, true) && EndpointTemplate::problems($options['endpoint'] ?? null) === []) {
            $endpoint = EndpointTemplate::fromConfig($options['endpoint'])->host();
        }

        return [
            'resolver' => $class,
            'provider' => $provider,
            'endpoint' => $endpoint,
            'address' => is_string($options['address'] ?? null) ? $options['address'] : null,
        ];
    }

    /**
     * Which resolver a rule's cached verdicts belong to.
     *
     * Verdicts are cached per resolver, so switching resolver starts afresh. Without it, a
     * site that moves to a provider *because* PHP's lookups were failing would keep
     * refusing every crawler those failures refused -- remembered as "no record" for
     * `verify_negative_ttl`, a day by default.
     *
     * Empty for PHP's own lookups, whether by default or named, so the verdicts every
     * earlier release cached stay valid.
     *
     * @param array<string, mixed> $metadata
     *   The rule's metadata.
     *
     * @return string
     *   The scope: a provider's name, or a resolver class and its options.
     */
    public function scopeFor(array $metadata): string
    {
        try {
            $choice = $this->choiceFor($metadata);
        } catch (ConfigurationException) {
            // Verifies nobody, and caches only briefly; kept apart all the same.
            return 'unusable';
        }

        if ($choice === null) {
            return '';
        }

        [$class, $options, $provider] = $choice;

        if ($provider !== null) {
            return 'provider:' . $provider;
        }

        if ($class === SystemResolver::class && $options === []) {
            return '';
        }

        return 'resolver:' . $class . ':' . md5(serialize($options));
    }

    /**
     * The breaker's threshold for a rule, when it does not set its own.
     *
     * Two DNS-over-HTTPS lookups of `timeout_ms` each can take twice that and still have
     * worked, so the threshold follows the timeout rather than staying at 250 ms -- which
     * would trip the breaker on lookups that succeeded.
     *
     * @param array<string, mixed> $metadata
     *   The rule's metadata.
     *
     * @return float
     *   Milliseconds.
     */
    public function slowThresholdFor(array $metadata): float
    {
        try {
            $choice = $this->choiceFor($metadata);
        } catch (ConfigurationException) {
            // A provider that does not exist verifies nobody, so there is no lookup to time.
            return 250.0;
        }

        if ($choice === null || !is_a($choice[0], DnsOverHttpResolver::class, true)) {
            return 250.0;
        }

        $timeout = $this->timeoutFor($metadata) ?? DnsOverHttpResolver::DEFAULT_TIMEOUT_MS;

        return max(250.0, 2.0 * $timeout + 50.0);
    }

    /**
     * The resolver class, its options and the provider name a rule resolves to.
     *
     * @param array<string, mixed> $metadata
     *   The rule's metadata.
     *
     * @return array{0: class-string<ReverseDnsResolverInterface>, 1: array<string, mixed>, 2: ?string}|null
     *   NULL when nothing is configured.
     */
    private function choiceFor(array $metadata): ?array
    {
        $provider = is_string($metadata['verify_provider'] ?? null)
            ? $metadata['verify_provider']
            : (is_string($this->settings['provider'] ?? null) ? $this->settings['provider'] : null);

        if ($provider !== null) {
            $definition = BuiltinProviders::ALL[$provider] ?? ($this->settings['providers'][$provider] ?? null);

            if (!is_array($definition)) {
                throw new ConfigurationException(sprintf('reverse DNS provider "%s" is not defined', $provider));
            }

            /** @var class-string<ReverseDnsResolverInterface> $class */
            $class = ltrim((string) ($definition['resolver'] ?? ''), '\\');
            $options = is_array($definition['options'] ?? null) ? $definition['options'] : [];

            return [$class, $options, $provider];
        }

        if (is_string($this->settings['resolver'] ?? null)) {
            /** @var class-string<ReverseDnsResolverInterface> $class */
            $class = ltrim($this->settings['resolver'], '\\');
            $options = is_array($this->settings['resolver_options'] ?? null) ? $this->settings['resolver_options'] : [];

            return [$class, $options, null];
        }

        return null;
    }

    /**
     * The timeout a rule asks for, or NULL to use the resolver's own default.
     *
     * @param array<string, mixed> $metadata
     *   The rule's metadata.
     */
    private function timeoutFor(array $metadata): ?int
    {
        $timeout = $metadata['verify_timeout_ms'] ?? ($this->settings['timeout_ms'] ?? null);

        return is_int($timeout) ? $timeout : null;
    }

    /**
     * Build a resolver, handing its options to a constructor parameter typed `array`.
     *
     * Read off the signature, as `ChallengeProviderFactory` does, so a resolver that takes
     * no options declares none.
     *
     * @param class-string<ReverseDnsResolverInterface> $class
     *   A validated resolver class.
     * @param array<string, mixed> $options
     *   Its options.
     *
     * @throws ConfigurationException
     *   When it cannot be constructed.
     */
    private function instantiate(string $class, array $options): ReverseDnsResolverInterface
    {
        try {
            $constructor = (new \ReflectionClass($class))->getConstructor();
            $arguments = [];

            foreach ($constructor?->getParameters() ?? [] as $parameter) {
                $type = $parameter->getType();

                if ($type instanceof \ReflectionNamedType && $type->getName() === 'array') {
                    $arguments[] = $options;
                    continue;
                }

                if (!$parameter->isOptional()) {
                    throw new ConfigurationException(sprintf(
                        'resolver %s cannot be built: its constructor parameter $%s is not an array of options',
                        $class,
                        $parameter->getName()
                    ));
                }

                break;
            }

            /** @var ReverseDnsResolverInterface $resolver */
            $resolver = new $class(...$arguments);

            return $resolver;
        } catch (ConfigurationException $configurationException) {
            throw $configurationException;
        } catch (\Throwable $throwable) {
            throw new ConfigurationException(sprintf('resolver %s cannot be built: %s', $class, $throwable->getMessage()), 0, $throwable);
        }
    }

    /**
     * `global.reverse_dns`, as an array.
     *
     * @param array<string, mixed> $global
     *   The `global:` section.
     *
     * @return array<string, mixed>
     *   The section, or empty.
     */
    private static function section(array $global): array
    {
        return is_array($global['reverse_dns'] ?? null) ? $global['reverse_dns'] : [];
    }

    /**
     * Problems with one provider a site defines.
     *
     * @param string $name
     *   Its name.
     * @param mixed $definition
     *   Its definition.
     *
     * @return list<string>
     *   Problems.
     */
    private static function providerProblems(string $name, mixed $definition): array
    {
        $label = sprintf('providers.%s', $name);

        if (BuiltinProviders::has($name)) {
            return [sprintf(
                '%s: "%s" is a built-in provider, and built-in names are reserved; define yours under another name, such as "%s-custom"',
                $label,
                $name,
                $name
            )];
        }

        if (preg_match(self::NAME_PATTERN, $name) !== 1) {
            return [sprintf('%s: a provider name is lower-case letters, digits, "-" and "_"', $label)];
        }

        if (!is_array($definition)) {
            return [sprintf('%s must be a map with resolver and options', $label)];
        }

        $problems = [];

        foreach (array_diff(array_map(strval(...), array_keys($definition)), ['resolver', 'options']) as $unknown) {
            $problems[] = sprintf('%s: unknown key "%s"; a provider takes resolver and options', $label, $unknown);
        }

        if (!array_key_exists('resolver', $definition)) {
            $problems[] = sprintf('%s: resolver is required', $label);

            return $problems;
        }

        foreach (self::resolverProblems($definition['resolver'], $definition['options'] ?? [], $label . '.resolver', []) as $problem) {
            $problems[] = $problem;
        }

        return $problems;
    }

    /**
     * Problems with a resolver class and its options.
     *
     * @param mixed $resolver
     *   The class name.
     * @param mixed $options
     *   Its options.
     * @param string $label
     *   How to name it in a message.
     * @param list<string> $providers
     *   Provider names, to recognise one written where a class belongs.
     *
     * @return list<string>
     *   Problems.
     */
    private static function resolverProblems(mixed $resolver, mixed $options, string $label, array $providers): array
    {
        if (!is_string($resolver) || $resolver === '') {
            return [sprintf('%s must be a fully-qualified class name', $label)];
        }

        $class = ltrim($resolver, '\\');

        if (in_array($resolver, $providers, true)) {
            return [sprintf(
                '%s: "%s" is a provider, not a resolver. Set provider: %s, and leave resolver unset',
                $label,
                $resolver,
                $resolver
            )];
        }

        if (!class_exists($class)) {
            return [sprintf('%s: class %s does not exist; resolver takes a fully-qualified class name', $label, $class)];
        }

        if (!is_subclass_of($class, ReverseDnsResolverInterface::class)) {
            return [sprintf('%s: %s does not implement %s', $label, $class, ReverseDnsResolverInterface::class)];
        }

        if (!is_array($options)) {
            return [sprintf('%s options must be a map', $label)];
        }

        if (!is_a($class, DnsOverHttpResolver::class, true)) {
            return [];
        }

        return array_map(
            static fn(string $problem): string => $label . ' options: ' . $problem,
            DnsOverHttpResolver::problems($options)
        );
    }

    /**
     * Problems with a timeout.
     *
     * @param mixed $timeout
     *   The value.
     * @param string $label
     *   How to name it in a message.
     *
     * @return list<string>
     *   Problems.
     */
    private static function timeoutProblems(mixed $timeout, string $label): array
    {
        if (!is_int($timeout) || $timeout < 1 || $timeout > DnsOverHttpResolver::MAX_TIMEOUT_MS) {
            return [sprintf('%s must be a whole number of milliseconds from 1 to %d', $label, DnsOverHttpResolver::MAX_TIMEOUT_MS)];
        }

        return [];
    }

    /**
     * The message for a provider name nobody defined.
     *
     * @param string $name
     *   The name given.
     * @param list<string> $known
     *   The names that exist.
     */
    private static function unknownProvider(string $name, array $known): string
    {
        return sprintf('"%s" is not a provider; the providers are %s', $name, implode(', ', $known));
    }
}
