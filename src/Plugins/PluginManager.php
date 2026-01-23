<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Logging\LoggingTrait;
use Kanopi\Firewall\Utility\LazyObjectRegistry;
use Symfony\Component\HttpFoundation\Request;

/**
 * Create an array of plugins prioritized.
 */
class PluginManager
{
    use LoggingTrait;

    /**
     * Construct a new Plugin Manager Service.
     *
     * @param LazyObjectRegistry $registry
     *   Plugin Registry
     */
    protected function __construct(protected LazyObjectRegistry $registry)
    {
        $this->getLogger()->debug('PluginManager initialized', [
            'plugin_count' => $registry->getCount(),
        ]);
    }

    /**
     * Initialize the plugins and return the resulting array.
     *
     * @param array $config
     *   Configuration for the plugins.
     *
     * @return self
     *   Return a new instance of self.
     */
    public static function create(array $config = []): self
    {
        $lazyObjectRegistry = new LazyObjectRegistry();
        $enabledPlugins = [];
        $skippedPlugins = [];

        foreach ($config as $plugin => $pluginConfig) {
            if (!($pluginConfig['enable'] ?? false)) {
                $skippedPlugins[] = ['plugin' => $plugin, 'reason' => 'disabled'];
                continue;
            }

            if (!class_exists($plugin)) {
                $skippedPlugins[] = ['plugin' => $plugin, 'reason' => 'class_not_found'];
                continue;
            }

            if (!in_array(PluginInterface::class, class_implements($plugin), true)) {
                $skippedPlugins[] = ['plugin' => $plugin, 'reason' => 'invalid_interface'];
                continue;
            }

            $priority = ($pluginConfig['priority'] ?? 0);
            $priority = is_int($priority) ? $priority : 0;

            $lazyObjectRegistry->add(
                $plugin,
                fn(): object => new $plugin($pluginConfig['metadata'] ?? [], $pluginConfig['config'] ?? []),
                $priority
            );

            $enabledPlugins[] = [
                'plugin' => $plugin,
                'priority' => $priority,
            ];
        }

        $manager = new self($lazyObjectRegistry);

        if ($enabledPlugins !== []) {
            $manager->getLogger()->debug('Plugins loaded', [
                'enabled_plugins' => $enabledPlugins,
                'enabled_count' => count($enabledPlugins),
            ]);
        }

        if ($skippedPlugins !== []) {
            $manager->getLogger()->debug('Plugins skipped', [
                'skipped_plugins' => $skippedPlugins,
                'skipped_count' => count($skippedPlugins),
            ]);
        }

        return $manager;
    }

    /**
     * Check to see if the provided IP Address can bypass the checks.
     *
     * @param Request $request
     *   The request to evaluate.
     *
     * @return false|PluginInterface
     *   Return false if not evaluated or return Plugin that matched criteria.
     */
    public function evaluate(Request $request): false|PluginInterface
    {
        $evaluatedPlugins = [];

        /** @var PluginInterface $plugin */
        foreach ($this->registry->getIterator() as $plugin) {
            $pluginName = $plugin->getName();
            $startTime = microtime(true);

            $status = $plugin->evaluate($request);

            $evaluationTime = round((microtime(true) - $startTime) * 1000, 2); // Convert to ms
            $evaluatedPlugins[] = [
                'plugin' => $pluginName,
                'result' => $status,
                'time_ms' => $evaluationTime,
            ];

            if ($status) {
                $this->getLogger()->debug('Plugin evaluation matched', $this->getContext($request, [
                    'plugin' => $pluginName,
                    'evaluation_time_ms' => $evaluationTime,
                    'evaluated_plugins' => $evaluatedPlugins,
                ]));

                return $plugin;
            }
        }

        $this->getLogger()->debug('No plugins matched', $this->getContext($request, [
            'evaluated_plugins' => $evaluatedPlugins,
            'total_plugins' => count($evaluatedPlugins),
        ]));

        return false;
    }

    /**
     * Get the list of plugins.
     *
     * @return array<PluginInterface>
     *   Array of plugins.
     */
    public function getPlugins(): array
    {
        return iterator_to_array($this->registry->getIterator());
    }
}
