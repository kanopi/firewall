<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Kanopi\Firewall\Logging\Handler\DatabaseHandler;
use Kanopi\Firewall\RateLimitStorage\DatabaseRateLimitStorage;
use Kanopi\Firewall\Storage\DatabaseStorage;

/**
 * Find every database-backed thing a configuration declares, and build it.
 *
 * Three places declare one, and they do not look alike: `storage:` at the top level, a
 * rate limit backend inside each rate limit plugin's `metadata.storage`, and each
 * `DatabaseHandler` under `logger:`. Anything asking "which tables does this configuration
 * own" has to walk all three.
 *
 * Extracted from `bin/firewall-migrate`, which was the only caller until
 * `bin/firewall-doctor` needed the same answer. A second copy of this walk is a second
 * place to forget when a fourth consumer appears.
 *
 * **Constructing is the point, not a side effect.** The declared schema lives on the class
 * -- `getStorageTables()` is where a column is added when a release adds one -- so there is
 * no way to ask what a configuration's tables should look like without building the object
 * that declares them. It also means a table that does not exist yet is created, which is
 * the right outcome for a migration and worth knowing about for a diagnosis.
 */
class DatabaseConsumers
{
    /**
     * Build every database-backed consumer a configuration declares.
     *
     * @param array<string, mixed> $config
     *   A loaded configuration.
     *
     * @return array{consumers: array<string, DatabaseStorage|DatabaseRateLimitStorage|DatabaseHandler>, failures: array<int, array{label: string, error: string}>}
     *   `consumers` keyed by a label naming where in the config it came from, and
     *   `failures` for the ones that could not be built -- an unreachable database, a
     *   driver that is not installed. A failure is returned rather than thrown, because
     *   one unreachable database is not a reason to say nothing about the others.
     */
    public static function fromConfig(array $config): array
    {
        $consumers = [];
        $failures = [];

        /**
         * @param callable(): (DatabaseStorage|DatabaseRateLimitStorage|DatabaseHandler) $factory
         */
        $build = static function (string $label, callable $factory) use (&$consumers, &$failures): void {
            try {
                $consumers[$label] = $factory();
            } catch (\Exception $exception) {
                $failures[] = ['label' => $label, 'error' => $exception->getMessage()];
            }
        };

        $storage = is_array($config['storage'] ?? null) ? $config['storage'] : [];
        $storageType = is_string($storage['type'] ?? null) ? ltrim($storage['type'], '\\') : '';

        if (is_a($storageType, DatabaseStorage::class, true)) {
            $settings = is_array($storage['config'] ?? null) ? $storage['config'] : [];
            $build('storage', static fn(): DatabaseStorage => new DatabaseStorage($settings));
        }

        $plugins = is_array($config['plugins'] ?? null) ? $config['plugins'] : [];

        foreach ($plugins as $index => $plugin) {
            if (!is_array($plugin)) {
                continue;
            }

            // Rate limit storage is declared on the plugin, not globally, and a
            // config may hold several rate limit rules pointed at different tables.
            $metadata = is_array($plugin['metadata'] ?? null) ? $plugin['metadata'] : [];
            $rateStorage = is_array($metadata['storage'] ?? null) ? $metadata['storage'] : [];
            $rateType = is_string($rateStorage['type'] ?? null) ? ltrim($rateStorage['type'], '\\') : '';

            if (!is_a($rateType, DatabaseRateLimitStorage::class, true)) {
                continue;
            }

            $settings = is_array($rateStorage['config'] ?? null) ? $rateStorage['config'] : [];
            $build('rate limit (plugin ' . $index . ')', static fn(): DatabaseRateLimitStorage => new DatabaseRateLimitStorage($settings));
        }

        $loggers = is_array($config['logger'] ?? null) ? $config['logger'] : [];

        foreach ($loggers as $index => $handler) {
            if (!is_array($handler)) {
                continue;
            }

            $class = is_string($handler['class'] ?? null) ? ltrim($handler['class'], '\\') : '';

            if (!is_a($class, DatabaseHandler::class, true)) {
                continue;
            }

            $args = is_array($handler['args'][0] ?? null) ? $handler['args'][0] : [];

            // Neither caller is here to write a log row, and a handler that
            // pruned on construction would be doing something nobody asked for.
            $args['prune_probability'] = 0;

            $build('logger (handler ' . $index . ')', static fn(): DatabaseHandler => new DatabaseHandler($args));
        }

        return ['consumers' => $consumers, 'failures' => $failures];
    }
}
