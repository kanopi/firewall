<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Reputation;

use Kanopi\Firewall\Logging\LoggingFactory;

/**
 * Numbers out of a provider's configuration, forgivingly.
 *
 * A typo in a YAML file should degrade a reputation lookup to its default, not
 * take a site down -- reputation is corroborating evidence, and `timeout: "2s"`
 * is not a reason to stop serving. It is still said out loud, at warning level,
 * because a silently ignored setting is how somebody spends an afternoon
 * wondering why their timeout did nothing.
 */
final class ProviderConfig
{
    /**
     * Read an integer, warning rather than silently coercing.
     *
     * @param array<int|string, mixed> $config
     *   The provider's configuration.
     * @param string $key
     *   The key to read.
     * @param int $default
     *   Value to use when the key is absent or unusable.
     * @param string $provider
     *   Provider name, for the warning.
     *
     * @return int
     *   The configured value, or the default.
     */
    public static function int(array $config, string $key, int $default, string $provider): int
    {
        $configured = $config[$key] ?? null;

        if ($configured === null) {
            return $default;
        }

        if (!is_numeric($configured)) {
            self::warn($provider, $key, $configured, $default);

            return $default;
        }

        return (int) $configured;
    }

    /**
     * Read a float, warning rather than silently coercing.
     *
     * @param array<int|string, mixed> $config
     *   The provider's configuration.
     * @param string $key
     *   The key to read.
     * @param float $default
     *   Value to use when the key is absent or unusable.
     * @param string $provider
     *   Provider name, for the warning.
     *
     * @return float
     *   The configured value, or the default.
     */
    public static function float(array $config, string $key, float $default, string $provider): float
    {
        $configured = $config[$key] ?? null;

        if ($configured === null) {
            return $default;
        }

        if (!is_numeric($configured)) {
            self::warn($provider, $key, $configured, $default);

            return $default;
        }

        return (float) $configured;
    }

    /**
     * Say that a setting was ignored, and what was used instead.
     *
     * @param string $provider
     *   Provider name.
     * @param string $key
     *   The key that could not be read.
     * @param mixed $given
     *   What was written there.
     * @param int|float $default
     *   What is being used instead.
     */
    private static function warn(string $provider, string $key, mixed $given, int|float $default): void
    {
        LoggingFactory::logger()->warning($provider . ' ' . $key . ' is not a number - using the default', [
            'plugin' => $provider,
            'given' => get_debug_type($given),
            'default' => $default,
        ]);
    }
}
