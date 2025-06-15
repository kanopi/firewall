<?php

namespace Kanopi\Firewall\Storage;

/**
 * In-memory key-value store for temporary runtime use.
 */
class InMemoryStorage extends AbstractStorageBase
{
    /**
     * Stores the data.
     * @var array<string, mixed>
     */
    protected array $store = [];

    /**
     * Store a value by key.
     *
     * @param string $key
     *   Key to store the value under.
     * @param mixed $value
     *   Value to store.
     *
     * @return bool
     *   Always returns true.
     */
    public function set(string $key, mixed $value): bool
    {
        if (isset($this->store[$key])) {
            return false;
        }
        $this->store[$key] = $value;
        return true;
    }

    /**
     * Delete a stored key.
     *
     * @param string $key
     *   Key to delete.
     *
     * @return bool
     *   True if key was deleted, false if key didn't exist.
     */
    public function delete(string $key): bool
    {
        if ($this->exists($key)) {
            unset($this->store[$key]);
            return true;
        }
        return false;
    }

    /**
     * Retrieve a value by key.
     *
     * @param string $key
     *   Key to retrieve.
     * @param mixed $default
     *   Default value if key is not found.
     *
     * @return mixed
     *   Value if found, otherwise $default.
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->store[$key] ?? $default;
    }

    /**
     * Clear all stored values.
     *
     * @return bool
     *   Always returns true.
     */
    public function reset(): bool
    {
        $this->store = [];
        return true;
    }

    /**
     * Check if a key exists in storage.
     *
     * @param string $key
     *   Key to check.
     *
     * @return bool
     *   True if key exists, false otherwise.
     */
    public function exists(string $key): bool
    {
        return array_key_exists($key, $this->store);
    }
}
