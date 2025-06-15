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
     *
     * @return bool
     *   True if successful, False if not.
     */
    public function set(string $key, mixed $value): bool;

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
     *   If key isn't found what is the default provided.
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
}
