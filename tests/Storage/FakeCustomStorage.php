<?php

namespace Kanopi\Firewall\Tests\Storage;

use Kanopi\Firewall\Storage\StorageInterface;

/**
 * Fake custom storage implementation for testing StorageFactory.
 */
class FakeCustomStorage implements StorageInterface
{
    private array $config;
    private array $store = [];
    private array $expires = [];

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    /**
     * Returns the configuration passed to the constructor.
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    public function set(string $key, mixed $value, int $expire = 0): bool
    {
        $this->store[$key] = $value;
        if ($expire > 0) {
            $this->expires[$key] = time() + $expire;
        }
        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->store[$key], $this->expires[$key]);
        return true;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        if (!$this->exists($key)) {
            return $default;
        }
        return $this->store[$key];
    }

    public function reset(): bool
    {
        $this->store = [];
        $this->expires = [];
        return true;
    }

    public function exists(string $key): bool
    {
        if (!array_key_exists($key, $this->store)) {
            return false;
        }
        if (isset($this->expires[$key]) && $this->expires[$key] < time()) {
            // Expired
            $this->delete($key);
            return false;
        }
        return true;
    }

    public function clearExpire(): bool
    {
        foreach ($this->expires as $key => $expiry) {
            if ($expiry < time()) {
                $this->delete($key);
            }
        }
        return true;
    }

    public function addToExpire(string $key, int $amount): bool
    {
        if (!$this->exists($key)) {
            return false;
        }
        $this->expires[$key] = ($this->expires[$key] ?? time()) + $amount;
        return true;
    }
}
