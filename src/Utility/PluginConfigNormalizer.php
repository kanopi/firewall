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
     * @param array<int, mixed> $plugins
     *   The `plugins:` list, exactly as it came out of the configuration --
     *   which is to say, not necessarily a list of maps. It was annotated as
     *   `array<int, array<string, mixed>>` and that annotation was the problem:
     *   it described the config an operator meant to write rather than the one
     *   they can write, so nothing checked, and a stray scalar reached a
     *   comparator typed `array` and left as a TypeError (#281). Entries that
     *   are not maps are skipped below.
     *
     * @return array{allow: array<int, array<string, mixed>>, block: array<int, array<string, mixed>>, challenge: array<int, array<string, mixed>>, record: array<int, array<string, mixed>>, redirect: array<int, array<string, mixed>>}
     *   Partitioned plugins: 'allow', 'block', 'challenge', 'record' and 'redirect', each sorted by weight.
     */
    public static function partitionAndSort(array $plugins): array
    {
        $allowPlugins = [];
        $blockPlugins = [];
        $challengePlugins = [];
        $recordPlugins = [];
        $redirectPlugins = [];

        foreach ($plugins as $plugin) {
            // A stray scalar where a map belongs. `plugins:` is hand-edited
            // YAML and the ways to produce one are ordinary -- a rule written
            // as a bare string, a commented-out block leaving an orphan list
            // item. `$plugin['enable'] ?? true` swallows it silently, so the
            // entry reached the weight comparator below, which is typed `array`
            // and threw a TypeError: an `\Error`, which a host catching
            // `\Exception` never sees (#281).
            //
            // Skipped, matching how every other malformed-plugin case behaves
            // here -- `PluginManager` skips a class that does not exist and
            // records why, rather than refusing to start.
            if (!is_array($plugin)) {
                continue;
            }

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
                case 'record':
                    $recordPlugins[] = $plugin;
                    break;
                case 'redirect':
                    $redirectPlugins[] = $plugin;
                    break;
                default:
                    $blockPlugins[] = $plugin;
            }
        }

        $byWeight = static fn(array $a, array $b): int => ($a['weight'] ?? 0) <=> ($b['weight'] ?? 0);
        usort($allowPlugins, $byWeight);
        usort($blockPlugins, $byWeight);
        usort($challengePlugins, $byWeight);
        usort($recordPlugins, $byWeight);
        usort($redirectPlugins, $byWeight);

        return [
            'allow' => $allowPlugins,
            'block' => $blockPlugins,
            'challenge' => $challengePlugins,
            'record' => $recordPlugins,
            'redirect' => $redirectPlugins,
        ];
    }
}
