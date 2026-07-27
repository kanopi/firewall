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
     * Evaluate the current request against this plugin's rules.
     *
     * This reports whether the plugin **matched**, not whether the request
     * should be allowed. What a match does is decided by the entry's
     * `response:` setting, which PluginManager applies:
     *
     * - `response: allow`     — a match permits the request immediately.
     * - `response: challenge` — a match serves the interstitial.
     * - `response: block`     — a match rejects the request.
     *
     * So a plugin that detects something bad returns TRUE. Returning FALSE
     * means "my rules did not apply to this request", which lets evaluation
     * continue to the next plugin.
     *
     * @param Request $request
     *   Request to evaluate.
     *
     * @return bool
     *   TRUE if the request matched this plugin's rules and the configured
     *   `response:` should be applied; FALSE if it did not match.
     */
    public function evaluate(Request $request): bool;

    /**
     * Return the status code for the matching request.
     *
     * @param Request|null $request
     *   The request that was being evaluated.
     *
     * @return int
     *   Status code to return.
     */
    public function getStatusCode(?Request $request = null): int;

    /**
     * Number of seconds when an IP address should be expired from the list of blocked elements.
     *
     * @param Request|null $request
     *   The request that was being evaluated.
     *
     * @return int
     *   Return the number of seconds.
     */
    public function getExpirationTime(?Request $request = null): int;
}
