<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Storage;

use Kanopi\Firewall\Traits\FileTrait;

/**
 * File-based key-value store with in-memory caching.
 * Persists data to disk using PHP serialization.
 */
class FileStorage extends InMemoryStorage
{
    use FileTrait;

    /**
     * Path of the file to save/load.
     */
    protected string $filePath;

    /**
     * Path of the file to save/load the offenses from.
     */
    protected string $offensesFilePath;

    /**
     * Construct a FileStorage instance.
     *
     * @param array<string, mixed> $config
     *   Configuration array.
     */
    public function __construct(array $config = [])
    {
        parent::__construct($config);

        $this->filePath = $this->validateFilePath(strval($config['storage_file'] ?? '/tmp/storage_data.data'));
        $this->loadStorageFile();
        $this->getLogger()->debug('FileStorage initialized', ['file' => $this->filePath]);

        $this->offensesFilePath = $this->validateFilePath(strval($config['offense_file'] ?? (\dirname(\realpath($this->filePath)) . '/storage_data_offenses.data')));
        $this->loadOffenseFile();
        $this->getLogger()->debug('FileStorage offenses initialized', ['file' => $this->offensesFilePath]);
    }

    /**
     * Internal method used for loading the storage file.
     */
    protected function loadStorageFile(): void
    {
        /** @phpstan-ignore assign.propertyType */
        $this->store = $this->loadFromFile($this->filePath);
    }

    /**
     * Internal method used for saving to storage file.
     */
    protected function persistStorageFile(): void
    {
        $this->persistToFile($this->store, $this->filePath);
    }

    /**
     * Internal method used for loading the offense file.
     */
    protected function loadOffenseFile(): void
    {
        /** @phpstan-ignore assign.propertyType */
        $this->offenses = $this->loadFromFile($this->offensesFilePath);
    }

    /**
     * Internal method used for saving to the offense file.
     */
    protected function persistOffenseFile(): void
    {
        $this->persistToFile($this->offenses, $this->offensesFilePath);
    }

    /**
     * {@inheritdoc}
     */
    public function recordOffense(string $key): bool
    {
        $this->loadOffenseFile();
        parent::recordOffense($key);
        $this->persistOffenseFile();
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function set(string $key, array $value, int $expire = 0): bool
    {
        $this->loadStorageFile();
        $result = parent::set($key, $value, $expire);
        if ($result) {
            $this->getLogger()->debug('Value set in file storage', [
                'key' => $key,
                'expire' => $expire,
                'file' => $this->filePath,
            ]);
            $this->persistStorageFile();
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $this->loadStorageFile();
        return parent::get($key, $default);
    }

    /**
     * {@inheritdoc}
     */
    public function delete(string $key): bool
    {
        $this->loadStorageFile();
        $result = parent::delete($key);
        if ($result) {
            $this->getLogger()->debug('Key deleted from file storage', [
                'key' => $key,
                'file' => $this->filePath,
            ]);
            $this->persistStorageFile();
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
            $this->persistStorageFile();
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function addToExpire(string $key, int $amount): bool
    {
        $this->loadStorageFile();
        $return = parent::addToExpire($key, $amount);
        if ($return) {
            $this->persistStorageFile();
        }

        return $return;
    }

    /**
     * {@inheritdoc}
     */
    public function countOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX): int
    {
        $this->loadOffenseFile();
        return parent::countOffenses($key, $start, $end);
    }
}
