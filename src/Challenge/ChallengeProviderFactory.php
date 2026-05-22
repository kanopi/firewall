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
     *
     * @throws ConfigurationException
     *   When the provider name resolves to nothing or to a class that
     *   does not implement ChallengeProviderInterface.
     */
    public static function create(string $provider, TokenManager $tokenManager): ChallengeProviderInterface
    {
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

        $instance = new $class($tokenManager);

        LoggingFactory::logMessage('debug', 'Challenge provider created', [
            'provider' => $instance->getName(),
            'class' => $class,
        ]);

        return $instance;
    }
}
