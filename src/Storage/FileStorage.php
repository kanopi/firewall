<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

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
            $this->getLogger()->error('Unable to create storage file', ['file' => $this->filePath]);
            throw new RuntimeException(sprintf("Unable to create file at '%s'", $this->filePath));
        }

        if (!is_readable($this->filePath)) {
            $this->getLogger()->error('Storage file not readable', ['file' => $this->filePath]);
            throw new RuntimeException(sprintf("File '%s' must be readable.", $this->filePath));
        }

        if (!is_writable($this->filePath)) {
            $this->getLogger()->error('Storage file not writable', ['file' => $this->filePath]);
            throw new RuntimeException(sprintf("File '%s' must be writeable.", $this->filePath));
        }

        $this->getLogger()->info('FileStorage initialized', ['file' => $this->filePath]);
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
                $count = 0;
                foreach ($data as $key => $value) {
                    if (is_string($key)) {
                        $this->store[$key] = $value;
                        $count++;
                    }
                }

                $this->getLogger()->debug('Data loaded from file', [
                    'file' => $this->filePath,
                    'entries_loaded' => $count,
                ]);
            } else {
                $this->getLogger()->warning('Failed to unserialize file data', [
                    'file' => $this->filePath,
                ]);
            }
        } else {
            $this->getLogger()->debug('No data to load from file', [
                'file' => $this->filePath,
            ]);
        }
    }

    /**
     * Persist in-memory data to file.
     */
    protected function persistToFile(): void
    {
        $serialized = serialize($this->store);
        if (@file_put_contents($this->filePath, $serialized) === false) {
            $this->getLogger()->error('Failed to write to storage file', [
                'file' => $this->filePath,
                'data_size' => strlen($serialized),
            ]);
        } else {
            $this->getLogger()->debug('Data persisted to file', [
                'file' => $this->filePath,
                'entries' => count($this->store),
                'size_bytes' => strlen($serialized),
            ]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function set(string $key, mixed $value, int $expire = 0): bool
    {
        $this->loadFromFile();
        $result = parent::set($key, $value, $expire);
        if ($result) {
            $this->getLogger()->debug('Value set in file storage', [
                'key' => $key,
                'expire' => $expire,
                'file' => $this->filePath,
            ]);
            $this->persistToFile();
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function delete(string $key): bool
    {
        $this->loadFromFile();
        $result = parent::delete($key);
        if ($result) {
            $this->getLogger()->debug('Key deleted from file storage', [
                'key' => $key,
                'file' => $this->filePath,
            ]);
            $this->persistToFile();
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function reset(): bool
    {
        $previousCount = count($this->store);
        $result = parent::reset();
        if ($result) {
            $this->getLogger()->info('File storage reset', [
                'file' => $this->filePath,
                'entries_cleared' => $previousCount,
            ]);
            $this->persistToFile();
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function addToExpire(string $key, int $amount): bool
    {
        $this->loadFromFile();
        $return = parent::addToExpire($key, $amount);
        if ($return) {
            $this->persistToFile();
        }

        return $return;
    }
}
