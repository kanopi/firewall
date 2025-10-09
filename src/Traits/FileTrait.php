<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Traits;

use Kanopi\Firewall\Logging\LoggingTrait;
use RuntimeException;

/**
 * Used for loading items from a file.
 */
trait FileTrait
{
    use LoggingTrait;

    /**
     * Load data from file into memory.
     *
     * @param string $filePath
     *   File to load.
     *
     * @return array<mixed>
     *   Return array of mixed data;
     */
    protected function loadFromFile(string $filePath): array
    {
        $contents = @file_get_contents($filePath);
        $store = [];
        if ($contents !== false && trim($contents) !== '') {
            $data = @unserialize($contents);
            if (is_array($data)) {
                $count = 0;
                foreach ($data as $key => $value) {
                    if (is_string($key)) {
                        $store[$key] = $value;
                        $count++;
                    }
                }

                $this->getLogger()->debug('Data loaded from file', [
                    'file' => $filePath,
                    'entries_loaded' => $count,
                ]);
            } else {
                $this->getLogger()->warning('Failed to unserialize file data', [
                    'file' => $filePath,
                ]);
            }
        } else {
            $this->getLogger()->debug('No data to load from file', [
                'file' => $filePath,
            ]);
        }

        return $store;
    }

    /**
     * Save the data to a file.
     *
     * @param array $data
     *   Data to serialize and store to file.
     * @param string $filePath
     *   File path to store the data.
     *
     * @return bool
     *   Returns true if successful and false if not.
     */
    protected function persistToFile(array $data, string $filePath): bool
    {
        $serialized = @serialize($data);
        if (@file_put_contents($filePath, $serialized) === false) {
            $this->getLogger()->error('Failed to write to storage file', [
                'file' => $filePath,
                'data_size' => strlen($serialized),
            ]);
            return false;
        }

        $this->getLogger()->debug('Data persisted to file', [
            'file' => $filePath,
            'entries' => count($data),
            'size_bytes' => strlen($serialized),
        ]);
        return true;
    }

    /**
     * Validate and confirm the file path.
     */
    protected function validateFilePath(string $filePath): string
    {
        if (!file_exists($filePath) && !@touch($filePath)) {
            $this->getLogger()->error('Unable to create storage file', ['file' => $filePath]);
            throw new RuntimeException(sprintf("Unable to create file at '%s'", $filePath));
        }

        if (!is_readable($filePath)) {
            $this->getLogger()->error('Storage file not readable', ['file' => $filePath]);
            throw new RuntimeException(sprintf("File '%s' must be readable.", $filePath));
        }

        if (!is_writable($filePath)) {
            $this->getLogger()->error('Storage file not writable', ['file' => $filePath]);
            throw new RuntimeException(sprintf("File '%s' must be writeable.", $filePath));
        }

        return strval(realpath($filePath));
    }
}
