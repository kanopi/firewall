<?php

namespace Kanopi\Firewall\Storage;

use RuntimeException;

/**
 * File-based key-value store with in-memory caching.
 * Persists data to disk using PHP serialization.
 */
class FileStorage extends InMemoryStorage
{
    /**
     * Path of the file to save/load.
     */
    protected string $filePath;

    /**
     * Construct a FileStorage instance.
     *
     * @param array<string, mixed> $config
     *   Configuration array, must contain 'file' => string path.
     *
     * @throws RuntimeException
     *   If file path is missing or inaccessible.
     */
    public function __construct(array $config = [])
    {
        parent::__construct($config);

        if (!isset($config['file']) || !is_string($config['file'])) {
            throw new RuntimeException("Missing or invalid 'file' path in configuration.");
        }

        $this->filePath = $config['file'];

        if (!file_exists($this->filePath) && !@touch($this->filePath)) {
            throw new RuntimeException(sprintf("Unable to create file at '%s'", $this->filePath));
        }

        if (!is_readable($this->filePath) || !is_writable($this->filePath)) {
            throw new RuntimeException(sprintf("File '%s' must be readable and writable.", $this->filePath));
        }

        $this->loadFromFile();
    }

    /**
     * Load data from file into memory.
     */
    protected function loadFromFile(): void
    {
        $contents = file_get_contents($this->filePath);
        if ($contents !== false && strlen(trim($contents)) > 0) {
            $data = @unserialize($contents);
            if (is_array($data)) {
                $this->store = [];
                foreach ($data as $key => $value) {
                    if (is_string($key)) {
                        $this->store[$key] = $value;
                    }
                }
            }
        }
    }

    /**
     * Persist in-memory data to file.
     */
    protected function persistToFile(): void
    {
        $serialized = serialize($this->store);
        if (@file_put_contents($this->filePath, $serialized) === false) {
            $this->getLogger()->error(sprintf("Failed to write to file '%s'", $this->filePath));
        }
    }

    /**
     * Store a value by key and persist to file.
     *
     * @param string $key
     *   Key to store the value under.
     * @param mixed $value
     *   Value to store.
     *
     * @return bool
     *   True on success.
     */
    public function set(string $key, mixed $value): bool
    {
        $result = parent::set($key, $value);
        $this->persistToFile();
        return $result;
    }

    /**
     * Delete a key and persist the updated data to file.
     *
     * @param string $key
     *   Key to delete.
     *
     * @return bool
     *   True if key was deleted, false otherwise.
     */
    public function delete(string $key): bool
    {
        $result = parent::delete($key);
        if ($result) {
            $this->persistToFile();
        }

        return $result;
    }

    /**
     * Clear all keys and persist the empty store to file.
     *
     * @return bool
     *   True on success.
     */
    public function reset(): bool
    {
        $result = parent::reset();
        $this->persistToFile();
        return $result;
    }
}
