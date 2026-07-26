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
 * Resolves a provider short name or FQCN into a ChallengeProviderInterface.
 *
 * Mirrors StorageFactory in shape: built-in short names map to first-party
 * classes, FQCN strings are instantiated if they implement the contract.
 * Anything else throws — there is no silent fallback because misconfiguring
 * the provider while challenge plugins exist should be a startup failure.
 */
final class ChallengeProviderFactory
{
    /**
     * @var array<string, class-string<ChallengeProviderInterface>>
     */
    private const BUILTINS = [
        'math' => MathChallengeProvider::class,
        'altcha' => AltchaChallengeProvider::class,
    ];

    /**
     * Build a provider from `challenge.provider` config.
     *
     * @param string $provider
     *   Built-in short name ("math") or fully-qualified class name.
     * @param TokenManager $tokenManager
     *   Shared HMAC manager. Providers that need to sign per-challenge
     *   state (like MathChallengeProvider) receive it via constructor.
     * @param array<string, mixed> $options
     *   Contents of `challenge.provider_options`, passed as a second
     *   constructor argument to providers that declare one. Providers
     *   taking only a TokenManager — including every custom provider
     *   written against the original single-argument signature — are
     *   constructed unchanged, so this stays backward compatible.
     *
     * @throws ConfigurationException
     *   When the provider name resolves to nothing or to a class that
     *   does not implement ChallengeProviderInterface.
     */
    public static function create(
        string $provider,
        TokenManager $tokenManager,
        array $options = []
    ): ChallengeProviderInterface {
        $class = self::BUILTINS[$provider] ?? $provider;

        if (!class_exists($class)) {
            throw new ConfigurationException(sprintf(
                'Challenge provider "%s" is not a built-in name or a loadable class.',
                $provider
            ));
        }

        if (!is_subclass_of($class, ChallengeProviderInterface::class)) {
            throw new ConfigurationException(sprintf(
                'Challenge provider "%s" must implement %s.',
                $class,
                ChallengeProviderInterface::class
            ));
        }

        $instance = self::instantiate($class, $tokenManager, $options);

        LoggingFactory::logMessage('debug', 'Challenge provider created', [
            'provider' => $instance->getName(),
            'class' => $class,
        ]);

        return $instance;
    }

    /**
     * Construct the provider, passing options only when it accepts them.
     *
     * `ChallengeProviderInterface` cannot describe a constructor, so the
     * arity is checked directly rather than assumed. A provider written
     * against the original `__construct(TokenManager $tm)` signature keeps
     * working; one that declares a second parameter receives the options.
     *
     * @param class-string<ChallengeProviderInterface> $class
     *   Resolved provider class.
     * @param array<string, mixed> $options
     *   Provider options to forward when supported.
     */
    private static function instantiate(
        string $class,
        TokenManager $tokenManager,
        array $options
    ): ChallengeProviderInterface {
        $constructor = (new \ReflectionClass($class))->getConstructor();

        if ($constructor instanceof \ReflectionMethod && $constructor->getNumberOfParameters() >= 2) {
            return new $class($tokenManager, $options);
        }

        return new $class($tokenManager);
    }
}
