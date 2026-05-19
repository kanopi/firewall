<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

/**
 * Normalizes plugin configuration from legacy (block:/bypass:) format to the new plugins: array format.
 *
 * The new canonical format is:
 *
 * plugins:
 *   - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
 *     response: allow
 *     weight: -200
 *     enable: true
 *     metadata: []
 *     config: ["127.0.0.1"]
 *
 * The legacy format is:
 *
 * bypass:
 *   Kanopi\Firewall\Plugins\IpAddress:
 *     priority: -200
 *     enable: true
 *     config: ["127.0.0.1"]
 *
 * block:
 *   Kanopi\Firewall\Plugins\IpAddress:
 *     priority: -100
 *     config: ["192.168.1.100"]
 */
final class PluginConfigNormalizer
{
    /**
     * Normalize configuration to the canonical plugins: array format.
     *
     * Converts legacy block: and bypass: sections into the plugins: array format.
     * If the config already uses plugins:, those entries are preserved.
     *
     * @param array<string, mixed> $config
     *   The configuration array to normalize.
     *
     * @return array<string, mixed>
     *   The normalized configuration with all plugins in the plugins: array.
     */
    public static function normalize(array $config): array
    {
        $plugins = $config['plugins'] ?? [];

        // Convert legacy bypass: section → response: allow
        if (isset($config['bypass']) && is_array($config['bypass'])) {
            foreach ($config['bypass'] as $class => $pluginConfig) {
                if (!is_array($pluginConfig)) {
                    continue;
                }

                $plugins[] = self::convertLegacyPlugin($class, $pluginConfig, 'allow');
            }

            unset($config['bypass']);
        }

        // Convert legacy block: section → response: block
        if (isset($config['block']) && is_array($config['block'])) {
            foreach ($config['block'] as $class => $pluginConfig) {
                if (!is_array($pluginConfig)) {
                    continue;
                }

                $plugins[] = self::convertLegacyPlugin($class, $pluginConfig, 'block');
            }

            unset($config['block']);
        }

        $config['plugins'] = $plugins;

        return $config;
    }

    /**
     * Convert a legacy plugin configuration to the new format.
     *
     * @param string $class
     *   The plugin class name.
     * @param array<string, mixed> $config
     *   The plugin configuration.
     * @param string $response
     *   The response type ('allow' or 'block').
     *
     * @return array<string, mixed>
     *   The converted plugin configuration.
     */
    private static function convertLegacyPlugin(string $class, array $config, string $response): array
    {
        return [
            'plugin' => $class,
            'response' => $response,
            'weight' => $config['priority'] ?? 0,
            'enable' => $config['enable'] ?? true,
            'metadata' => $config['metadata'] ?? [],
            'config' => $config['config'] ?? [],
        ];
    }

    /**
     * Partition plugins array by response type and sort by weight.
     *
     * Unknown response values default to 'block' so a typo never silently
     * promotes a plugin to 'allow' or 'challenge'.
     *
     * @param array<int, array<string, mixed>> $plugins
     *   The plugins array to partition.
     *
     * @return array{allow: array<int, array<string, mixed>>, block: array<int, array<string, mixed>>, challenge: array<int, array<string, mixed>>}
     *   Partitioned plugins: 'allow', 'block', and 'challenge', each sorted by weight.
     */
    public static function partitionAndSort(array $plugins): array
    {
        $allowPlugins = [];
        $blockPlugins = [];
        $challengePlugins = [];

        foreach ($plugins as $plugin) {
            // Skip disabled plugins
            if (!($plugin['enable'] ?? true)) {
                continue;
            }

            switch ($plugin['response'] ?? 'block') {
                case 'allow':
                    $allowPlugins[] = $plugin;
                    break;
                case 'challenge':
                    $challengePlugins[] = $plugin;
                    break;
                default:
                    $blockPlugins[] = $plugin;
            }
        }

        $byWeight = static fn(array $a, array $b): int => ($a['weight'] ?? 0) <=> ($b['weight'] ?? 0);
        usort($allowPlugins, $byWeight);
        usort($blockPlugins, $byWeight);
        usort($challengePlugins, $byWeight);

        return [
            'allow' => $allowPlugins,
            'block' => $blockPlugins,
            'challenge' => $challengePlugins,
        ];
    }
}
