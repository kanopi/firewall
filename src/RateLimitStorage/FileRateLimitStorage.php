<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\RateLimitStorage;

use Kanopi\Firewall\Traits\FileTrait;

/**
 * File-based rate limit storage.
 */
class FileRateLimitStorage extends InMemoryRateLimitStorage
{
    use FileTrait;

    /**
     * Location where file is stored.
     */
    protected string $filePath;

    /**
     * Constructs a new FileRateLimitStorage object.
     *
     * @param array $config
     *   Configuration array. Supported keys:
     *   - 'file' => string: Path to the JSON file holding request timestamps.
     *     Defaults to `ratelimit_data.json` inside a mode-0700, per-user
     *     fingerprinted subdirectory of the system temp directory, so
     *     counters are not readable by other users on a shared host.
     *   Any keys understood by InMemoryRateLimitStorage are also honored.
     */
    public function __construct(array $config = [])
    {
        parent::__construct($config);
        $this->filePath = $this->validateFilePath(
            strval($config['file'] ?? $this->defaultStoragePath('ratelimit_data.json'))
        );

        $this->getLogger()->debug('File rate limit storage initialized', [
            'file' => $this->filePath,
        ]);

        $this->loadFile();
    }

    /**
     * {@inheritdoc}
     */
    public function recordRequest(string $key, int $timestamp): void
    {
        $this->withExclusiveLock($this->filePath, function () use ($key, $timestamp): void {
            $this->loadFile();
            parent::recordRequest($key, $timestamp);

            $this->getLogger()->debug('Request recorded to file storage', [
                'key' => $key,
                'timestamp' => $timestamp,
                'file' => $this->filePath,
            ]);

            $this->saveFile();
        });
    }

    /**
     * {@inheritdoc}
     *
     * Overridden so the pruned state reaches disk. Inherited unchanged it
     * would filter the in-memory copy and be discarded by the next
     * `loadFile()`, leaving the file exactly as large as before.
     *
     * This is the backend the fix matters most for. `recordRequest()` reads
     * and rewrites the whole file under an exclusive lock on every request, so
     * the per-request cost was the file size and the file size was every
     * request ever seen. Pruning adds a third lock/read/write cycle to the
     * allowed path and removes the unbounded growth that made the other two
     * expensive, which is a trade worth taking by a wide margin -- see the
     * measurements in the pull request.
     */
    public function forget(string $key, int $before): int
    {
        $dropped = 0;

        $this->withExclusiveLock($this->filePath, function () use ($key, $before, &$dropped): void {
            // Reloaded inside the lock: another process may have recorded
            // against this key since the count that produced `$before`, and
            // saving a copy read before that would discard its request.
            $this->loadFile();
            $dropped = parent::forget($key, $before);

            if ($dropped > 0) {
                $this->saveFile();
            }
        });

        return $dropped;
    }

    /**
     * {@inheritdoc}
     */
    public function countRequests(string $key, int $start, int $end): int
    {
        $this->loadFile();
        return parent::countRequests($key, $start, $end);
    }

    /**
     * Load the file contents.
     */
    protected function loadFile(): void
    {
        $this->requests = $this->loadFromFile($this->filePath);
    }

    /**
     * Persist items to file.
     */
    protected function saveFile(): void
    {
        $this->persistToFile($this->requests, $this->filePath);
    }
}
