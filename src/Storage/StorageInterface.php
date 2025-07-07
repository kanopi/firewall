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
     * Return the key for the provided request.
     *
     * @param Request $request
     *   Request to get information from.
     *
     * @return string
     *   Return the key.
     */
    public function getKey(Request $request): string;

    /**
     * Set the value of the provided key.
     *
     * @param string $key
     *   Key to set.
     * @param array $value
     *   Value to set.
     * @param int $expire
     *   Timestamp when the key should be expired.
     *
     * @return bool
     *   True if successful, False if not.
     */
    public function set(string $key, array $value, int $expire = 0): bool;

    /**
     * Delete the provided key.
     *
     * @param string $key
     *   Key to look up data.
     *
     * @return bool
     *   True if successful, False if not.
     */
    public function delete(string $key): bool;

    /**
     * Get the value for the provided key.
     *
     * @param string $key
     *   Key to look up.
     * @param mixed $default
     *   Default value to return.
     *
     * @return mixed
     *   Return the value for the provided key, null if not found.
     */
    public function get(string $key, mixed $default = null): mixed;

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
     * @param string $key
     *   Check to see if the provided key exists.
     *
     * @return bool
     *   Return TRUE if found, FALSE if not.
     */
    public function exists(string $key): bool;

    /**
     * Clear out all the expired items.
     *
     * @return bool
     *   Return TRUE if successful, FALSE if issues.
     */
    public function expire(): bool;

    /**
     * Example the expiration time by a specific amount.
     *
     * @param string $key
     *   Key to look up.
     * @param int $amount
     *   Amount of time to add to the expiration time.
     *
     * @return bool
     *   Return TRUE if successful, FALSE if issues.
     */
    public function addToExpire(string $key, int $amount): bool;

    /**
     * Record the offense in the database.
     *
     * @param string $key
     *   Key to set offense for..
     *
     * @return bool
     *   Return TRUE if successful.
     */
    public function recordOffense(string $key): bool;

    /**
     * Count how many offenses happened between a certain time period.
     *
     * @param string $key
     *   Key to search for periods.
     * @param int $start
     *   The start timestamp to look for.
     * @param int $end
     *   The ending timestamp to include.
     *
     * @return int
     *   The total number of offenses found.
     */
    public function countOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX): int;

    /**
     * Check to see if the key is currently blocked.
     *
     * @param string $key
     *   Key to look up.
     *
     * @return array|false
     *   Return an array of items if found, False if issues.
     */
    public function isBlocked(string $key): array|false;

    /**
     * Return the data for storage.
     *
     * @param Request $request
     *   Request element.
     * @param PluginInterface|null $plugin
     *   Plugin making the request.
     *
     * @return array
     *   Return the data for the provided request.
     */
    public function getStorageData(Request $request, ?PluginInterface $plugin): array;
}
