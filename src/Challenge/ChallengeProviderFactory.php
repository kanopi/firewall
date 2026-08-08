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
        'turnstile' => TurnstileChallengeProvider::class,
        'recaptcha' => RecaptchaChallengeProvider::class,
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
     *   Contents of `challenge.provider_options`, passed to providers that
     *   declare an `array` constructor parameter.
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

        $challengeProvider = self::instantiate($class, $tokenManager, $options);

        LoggingFactory::logMessage('debug', 'Challenge provider created', [
            'provider' => $challengeProvider->getName(),
            'class' => $class,
        ]);

        return $challengeProvider;
    }

    /**
     * Construct the provider, giving it only the collaborators it declares.
     *
     * `ChallengeProviderInterface` cannot describe a constructor, so what to
     * pass is read off the signature rather than assumed. Each parameter is
     * matched by declared type: an `array` receives
     * `challenge.provider_options`, anything else receives the shared
     * `TokenManager`.
     *
     * Reading types rather than counting parameters is what lets a provider
     * decline the TokenManager altogether. `TurnstileChallengeProvider` has
     * no per-challenge state to sign — Cloudflare owns the only thing that
     * has to survive from render to verify — and accepting a collaborator it
     * never uses would be a lie in its signature.
     *
     * Backward compatible in both directions: an untyped parameter is
     * treated as wanting the TokenManager, so providers written against the
     * original `__construct(TokenManager $tm)` or
     * `__construct(TokenManager $tm, array $opts)` signatures are
     * constructed exactly as before.
     *
     * @param class-string<ChallengeProviderInterface> $class
     *   Resolved provider class.
     * @param array<string, mixed> $options
     *   Provider options to forward to an `array` parameter.
     */
    private static function instantiate(
        string $class,
        TokenManager $tokenManager,
        array $options
    ): ChallengeProviderInterface {
        $constructor = (new \ReflectionClass($class))->getConstructor();

        if (!$constructor instanceof \ReflectionMethod) {
            return new $class();
        }

        $arguments = [];
        foreach ($constructor->getParameters() as $reflectionParameter) {
            $type = $reflectionParameter->getType();
            $arguments[] = $type instanceof \ReflectionNamedType && $type->getName() === 'array'
                ? $options
                : $tokenManager;
        }

        return new $class(...$arguments);
    }
}
