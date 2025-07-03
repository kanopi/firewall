<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Storage;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Interface used for defining a Storage Item
 */
interface StorageInterface
{
    /**
     * Set the value of the provided key.
     *
     * @param Request $request
     *   Request data.
     * @param int $expire
     *   Timestamp when the key should be expired.
     *
     * @return bool
     *   True if successful, False if not.
     */
    public function set(Request $request, int $expire = 0): bool;

    /**
     * Delete the provided key.
     *
     * @param Request $request
     *   Request data.
     *
     * @return bool
     *   True if successful, False if not.
     */
    public function delete(Request $request): bool;

    /**
     * Get the value for the provided key.
     *
     * @param Request $request
     *   Request data.
     * @param mixed $default
     *   If the key isn't found, return the default value.
     *
     * @return mixed
     *   Return the value for the provided key.
     */
    public function get(Request $request, mixed $default = null): mixed;

    /**
     * Delete all elements in the storage and reset to nothing.
     *
     * @return bool
     *   True if successful, False if not.
     */
    public function reset(): bool;

    /**
     * Check if key exists.
     *
     * @param Request $request
     *   Request data.
     *
     * @return bool
     *   Return TRUE if found, FALSE if not.
     */
    public function exists(Request $request): bool;

    /**
     * Clear out all the expired items.
     *
     * @return bool
     *   Return TRUE if successful, FALSE if issues.
     */
    public function clearExpire(): bool;

    /**
     * Example the expiration time by a specific amount.
     *
     * @param Request $request
     *   Request data.
     * @param int $amount
     *   Amount of time to add to the expiration time.
     *
     * @return bool
     *   Return TRUE if successful, FALSE if issues.
     */
    public function addToExpire(Request $request, int $amount): bool;

    /**
     * Record the offense in the database.
     *
     * @param Request $request
     *   Request to get information about.
     *
     * @return bool
     *   Return TRUE if successful.
     */
    public function recordOffense(Request $request): bool;

    /**
     * Count how many offenses happened between a certain time period.
     *
     * @param Request $request
     *   Request data.
     * @param int $start
     *   The start timestamp to look for.
     * @param int $end
     *   The ending timestamp to include.
     *
     * @return int
     *   The total number of offenses found.
     */
    public function countOffenses(Request $request, int $start = 0, int $end = PHP_INT_MAX): int;

    /**
     * Check to see if the request is currently blocked.
     *
     * @param Request $request
     *   Request to evaluate.
     * @param int $addToExpire
     *   Amount of time to add if the request is already blocked.
     *
     * @return mixed
     *   Return an array of items if found, False if issues.
     */
    public function isBlocked(Request $request, int $addToExpire = 0): mixed;

    /**
     * Block the IP Address against the database.
     *
     * @param Request $request
     *   Request information.
     * @param PluginInterface $plugin
     *   Plugin that is blocking the IP Address.
     *
     * @return bool
     *   Return TRUE if successful, FALSE if there is an issue.
     */
    public function blockIp(Request $request, PluginInterface $plugin): bool;
}
