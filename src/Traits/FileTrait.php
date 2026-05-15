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
use Kanopi\Firewall\Exception\StorageException;

/**
 * Used for loading items from a file.
 */
trait FileTrait
{
    use LoggingTrait;

    /**
     * Load data from file into memory.
     *
     * Storage uses JSON, not PHP `serialize()`, to eliminate the PHP Object
     * Injection (CWE-502) class of attack on the persisted file.
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
        if ($contents === false || trim($contents) === '') {
            $this->getLogger()->debug('No data to load from file', [
                'file' => $filePath,
            ]);
            return $store;
        }

        try {
            $data = json_decode($contents, true, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (\JsonException $jsonException) {
            $this->getLogger()->warning('Failed to decode storage file as JSON, ignoring contents', [
                'file' => $filePath,
                'error' => $jsonException->getMessage(),
            ]);
            return $store;
        }

        if (!is_array($data)) {
            $this->getLogger()->warning('File data is not an array, ignoring', [
                'file' => $filePath,
                'type' => gettype($data),
            ]);
            return $store;
        }

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

        return $store;
    }

    /**
     * Save the data to a file.
     *
     * @param array $data
     *   Data to encode and store to file.
     * @param string $filePath
     *   File path to store the data.
     *
     * @return bool
     *   Returns true if successful and false if not.
     */
    protected function persistToFile(array $data, string $filePath): bool
    {
        try {
            $encoded = json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (\JsonException $jsonException) {
            $this->getLogger()->error('Failed to encode data for storage file', [
                'file' => $filePath,
                'error' => $jsonException->getMessage(),
            ]);
            return false;
        }

        if (@file_put_contents($filePath, $encoded) === false) {
            $this->getLogger()->error('Failed to write to storage file', [
                'file' => $filePath,
                'data_size' => strlen($encoded),
            ]);
            return false;
        }

        $this->getLogger()->debug('Data persisted to file', [
            'file' => $filePath,
            'entries' => count($data),
            'size_bytes' => strlen($encoded),
        ]);
        return true;
    }

    /**
     * Validate and confirm the file path.
     *
     * When the file does not yet exist, it is created with mode 0600 so the
     * persisted firewall state (block list, rate-limit counters, request
     * metadata) is not readable by other local users. Existing files have
     * their permissions tightened to 0600 as well unless they're already
     * more restrictive — this is best-effort and won't fail validation if
     * the file's owner doesn't allow chmod.
     */
    protected function validateFilePath(string $filePath): string
    {
        $existed = file_exists($filePath);

        if (!$existed && !@touch($filePath)) {
            $this->getLogger()->error('Unable to create storage file', ['file' => $filePath]);
            throw new StorageException(sprintf("Unable to create file at '%s'", $filePath));
        }

        if (!$existed) {
            // Brand-new file: lock it down immediately, before any data is
            // written. Other code paths in this trait will keep it at 0600.
            @chmod($filePath, 0600);
        } else {
            // Pre-existing file: only tighten if currently world- or group-
            // readable. Don't fight an operator who deliberately set 0640
            // for a specific log shipper, etc.
            // Mask to the bottom 12 bits — `fileperms()` returns S_IFREG
            // and friends too, and on some platforms (the CircleCI Docker
            // base image, notably) chmod refuses modes carrying those.
            $perms = @fileperms($filePath);
            if ($perms !== false && ($perms & 0077) !== 0) {
                @chmod($filePath, ($perms & 07777) & ~0077);
            }
        }

        if (!is_readable($filePath)) {
            $this->getLogger()->error('Storage file not readable', ['file' => $filePath]);
            throw new StorageException(sprintf("File '%s' must be readable.", $filePath));
        }

        if (!is_writable($filePath)) {
            $this->getLogger()->error('Storage file not writable', ['file' => $filePath]);
            throw new StorageException(sprintf("File '%s' must be writeable.", $filePath));
        }

        return strval(realpath($filePath));
    }

    /**
     * Return a per-install default storage path.
     *
     * The default sits in `sys_get_temp_dir()` (not hardcoded `/tmp`,
     * which doesn't exist on every platform) inside a per-user, per-install
     * subdirectory. Including the current uid and a hash of the install
     * location keeps the filename from being trivially guessable across
     * tenants on a shared host, and the subdirectory is created with mode
     * 0700 so other local users can't list / replace files inside it.
     *
     * @param string $filename
     *   The leaf filename, e.g. "storage_data.json".
     *
     * @return string
     *   An absolute filesystem path safe to pass to validateFilePath().
     */
    protected function defaultStoragePath(string $filename): string
    {
        $fingerprint = substr(
            hash(
                'sha256',
                getmyuid() . '|' . __DIR__ . '|' . phpversion()
            ),
            0,
            16
        );

        $directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'kanopi-firewall-' . $fingerprint;

        if (!is_dir($directory)) {
            // Mode 0700 so the directory listing isn't visible to other users
            // even if the temp directory itself is world-readable.
            @mkdir($directory, 0700, true);
        }

        return $directory . DIRECTORY_SEPARATOR . $filename;
    }
}
