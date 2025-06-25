<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\RateLimitStorage;

/**
 * File-based rate limit storage.
 */
class FileRateLimitStorage extends InMemoryRateLimitStorage
{
    /**
     * Location where file is stored.
     */
    protected string $filePath;

    public function __construct(array $config = [])
    {
        parent::__construct($config);
        $this->filePath = strval($config['file'] ?? '/tmp/ratelimit_data.json');

        $this->getLogger()->info('File rate limit storage initialized', [
            'file' => $this->filePath,
        ]);

        $this->loadFromFile();
    }

    /**
     * {@inheritdoc}
     */
    public function recordRequest(string $key, int $timestamp): void
    {
        parent::recordRequest($key, $timestamp);

        $this->getLogger()->debug('Request recorded to file storage', [
            'key' => $key,
            'timestamp' => $timestamp,
            'file' => $this->filePath,
        ]);

        $this->saveToFile();
    }

    /**
     * Load the file contents.
     */
    protected function loadFromFile(): void
    {
        if (file_exists($this->filePath)) {
            $contents = file_get_contents($this->filePath);
            $data = json_decode($contents, true);
            if (is_array($data)) {
                $this->requests = $data;
                $totalRequests = array_sum(array_map('count', $data));
                $this->getLogger()->debug('Rate limit data loaded from file', [
                    'file' => $this->filePath,
                    'keys' => count($data),
                    'total_requests' => $totalRequests,
                ]);
            } else {
                $this->getLogger()->warning('Failed to decode rate limit file', [
                    'file' => $this->filePath,
                ]);
            }
        } else {
            $this->getLogger()->debug('Rate limit file does not exist, starting fresh', [
                'file' => $this->filePath,
            ]);
        }
    }

    /**
     * Persist items to file.
     */
    protected function saveToFile(): void
    {
        $result = file_put_contents($this->filePath, json_encode($this->requests));
        if ($result === false) {
            $this->getLogger()->error('Failed to save rate limit data to file', [
                'file' => $this->filePath,
            ]);
        } else {
            $this->getLogger()->debug('Rate limit data saved to file', [
                'file' => $this->filePath,
                'bytes_written' => $result,
            ]);
        }
    }
}
