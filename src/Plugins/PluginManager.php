<?php

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Utility\LazyObjectRegistry;
use Symfony\Component\HttpFoundation\Request;

/**
 * Create an array of plugins prioritized.
 */
class PluginManager
{
    /**
     * Construct a new Plugin Manager Service.
     *
     * @param LazyObjectRegistry $registry
     *   Plugin Registry
     */
    protected function __construct(protected LazyObjectRegistry $registry)
    {
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

        foreach ($config as $plugin => $pluginConfig) {
            if (!($pluginConfig['enable'] ?? false)) {
                continue;
            }
            if (!class_exists($plugin)) {
                continue;
            }
            if (!class_implements($plugin, PluginInterface::class)) {
                continue;
            }
            $priority = ($pluginConfig['priority'] ?? 0);
            $priority = is_int($priority) ? $priority : 0;
            $lazyObjectRegistry->add(
                $plugin,
                fn(): object => new $plugin($pluginConfig['metadata'] ?? [], $pluginConfig['config'] ?? []),
                $priority
            );
        }

        return new self($lazyObjectRegistry);
    }

    /**
     * Check to see if the provided IP Address can bypass the checks.
     *
     * @param Request $request
     *   The request to evaluate.
     * @param bool $block
     *   Block the request.
     * @paran callable $callback
     *   Callback to use when blocking.
     *
     * @return bool
     *   Return TRUE if allowed, FALSE if not.
     */
    public function evaluate(Request $request, bool $block = false, ?callable $callback = null): bool
    {
        /** @var PluginInterface $plugin */
        foreach ($this->registry->getIterator() as $plugin) {
            $status = $plugin->evaluate($request);
            if ($status) {
                call_user_func($callback, $block, $request, $plugin);
                return true;
            }
        }

        return false;
    }
}
