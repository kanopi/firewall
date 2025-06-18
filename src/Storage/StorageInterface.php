<?php

namespace Kanopi\Firewall\Storage;

/**
 * Interface used for defining a Storage Item
 */
interface StorageInterface
{
    /**
     * Set the value of the provided key.
     *
     * @param string $key
     *   Key value of the storage item.
     * @param mixed $value
     *   Value to set for the key element.
     * @param int $expire
     *   Timestamp when the key should be expired.
     *
     * @return bool
     *   True if successful, False if not.
     */
    public function set(string $key, mixed $value, int $expire = 0): bool;

    /**
     * Delete the provided key.
     *
     * @param string $key
     *   Key value of the storage item.
     *
     * @return bool
     *   True if successful, False if not.
     */
    public function delete(string $key): bool;

    /**
     * Get the value for the provided key.
     *
     * @param string $key
     *   Key to search for.
     * @param mixed $default
     *   If the key isn't found, return the default value.
     *
     * @return mixed
     *   Return the value for the provided key.
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
     *   The key to check for.
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
    public function clearExpire(): bool;

    /**
     * Example the expiration time by a specific amount.
     *
     * @param string $key
     *   The key to check for.
     * @param int $amount
     *   Amount of time to expand the expiration time for.
     *
     * @return bool
     *   Return TRUE if successful, FALSE if issues.
     */
    public function addToExpire(string $key, int $amount): bool;
}
