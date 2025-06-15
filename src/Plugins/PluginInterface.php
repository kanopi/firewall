<?php

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Logging\LoggableInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Interface for Plugins.
 */
interface PluginInterface
{
    /**
     * Return the name of the plugin.
     *
     * @return string
     */
    public function getName(): string;

    /**
     * Return the plugin's description and what it is used for.
     *
     * @return string
     */
    public function getDescription(): string;

    /**
     * Evaluate the current request to see if it passes the current plugin.
     *
     * @param Request $request
     *   Request to evaluate.
     *
     * @return bool
     *   Return TRUE if allowed to pass.
     *
     * @throws \Kanopi\Firewall\Exception\BlockAccessException
     *   When found in the list.
     */
    public function evaluate(Request $request): bool;
}
