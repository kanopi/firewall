<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Symfony\Component\HttpFoundation\Request;

/**
 * Interface for Plugins.
 */
interface PluginInterface
{
    /**
     * Return the name of the plugin.
     */
    public function getName(): string;

    /**
     * Return the plugin's description and what it is used for.
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

    /**
     * Return the status code for the matching request.
     *
     * @return int
     *   Status code to return.
     */
    public function getStatusCode(): int;

    /**
     * Number of seconds when an IP address should be expired from the list of blocked elements.
     *
     * @return int
     *   Return the number of seconds.
     */
    public function getExpirationTime(): int;
}
