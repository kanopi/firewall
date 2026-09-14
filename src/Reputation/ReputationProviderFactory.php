<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Reputation;

use Kanopi\Firewall\Exception\ConfigurationException;

/**
 * Resolves a provider short name or FQCN into a ReputationProviderInterface.
 *
 * Mirrors `ChallengeProviderFactory` and `StorageFactory` in shape: built-in
 * short names map to first-party classes, an FQCN is instantiated if it
 * implements the contract, and anything else throws. There is no silent
 * fallback -- a reputation rule pointed at a provider that does not exist would
 * otherwise match nothing, which for a block rule is indistinguishable from a
 * working rule finding nothing.
 */
final class ReputationProviderFactory
{
    /**
     * @var array<string, class-string<ReputationProviderInterface>>
     */
    private const BUILTINS = [
        'abuseipdb' => AbuseIpdbProvider::class,
        'http' => HttpReputationProvider::class,
    ];

    /**
     * Build a provider from a rule's `config.provider`.
     *
     * @param string $provider
     *   Built-in short name (`abuseipdb`, `http`) or a fully-qualified class
     *   name implementing the interface.
     * @param array<int|string, mixed> $config
     *   The rule's `config:` block, handed to the provider whole. Provider
     *   settings sit alongside the plugin's rather than under a nested key,
     *   which is what keeps `api_key` where every existing AbuseIPDB config
     *   already has it.
     *
     * @return ReputationProviderInterface
     *   The provider.
     *
     * @throws ConfigurationException
     *   When the name resolves to nothing, or to a class that is not a
     *   provider.
     */
    public static function create(string $provider, array $config = []): ReputationProviderInterface
    {
        $class = self::BUILTINS[$provider] ?? $provider;

        if (!class_exists($class)) {
            throw new ConfigurationException(sprintf(
                'Reputation provider "%s" resolves to no class. Use one of %s, or a fully-qualified class '
                . 'name implementing %s.',
                $provider,
                implode(', ', array_keys(self::BUILTINS)),
                ReputationProviderInterface::class
            ));
        }

        if (!is_subclass_of($class, ReputationProviderInterface::class)) {
            throw new ConfigurationException(sprintf(
                'Reputation provider "%s" does not implement %s.',
                $class,
                ReputationProviderInterface::class
            ));
        }

        return new $class($config);
    }
}
