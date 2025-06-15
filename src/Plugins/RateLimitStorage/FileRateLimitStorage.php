<?php

namespace Kanopi\Firewall\Plugins\RateLimitStorage;

/**
 * File-based rate limit storage.
 */
class FileRateLimitStorage extends InMemoryRateLimitStorage
{
    /**
     * Location where file is stored.
     *
     * @var string
     */
    protected string $filePath;

    public function __construct(array $config = [])
    {
        parent::__construct($config);
        $this->filePath = strval($config['file'] ?? '/tmp/ratelimit_data.json');
        $this->loadFromFile();
    }

    /**
     * {@inheritdoc}
     */
    public function recordRequest(string $key, int $timestamp): void
    {
        parent::recordRequest($key, $timestamp);
        $this->saveToFile();
    }

    /**
     * Load the file contents.
     */
    protected function loadFromFile(): void
    {
        if (file_exists($this->filePath)) {
            $data = json_decode(file_get_contents($this->filePath), true);
            if (is_array($data)) {
                $this->requests = $data;
            }
        }
    }

    /**
     * Persist items to file.
     */
    protected function saveToFile(): void
    {
        file_put_contents($this->filePath, json_encode($this->requests, JSON_PRETTY_PRINT));
    }
}
