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
     * {@inheritdoc}
     */
    public function set(string $key, mixed $value, int $expire = 0): bool
    {
        $this->store[$key] = [
            "value" => $value,
            "expire" => $expire > 0 ? time() + $expire : 0,
        ];
        return true;
    }

    /**
     * {@inheritdoc}
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
     * {@inheritdoc}
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $value = $this->store[$key] ?? null;
        if ($value === null || $value['expire'] < time()) {
            $this->delete($key);
            return $default;
        }

        return $value['value'];
    }

    /**
     * {@inheritdoc}
     */
    public function reset(): bool
    {
        $this->store = [];
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function exists(string $key): bool
    {
        return array_key_exists($key, $this->store);
    }

    /**
     * {@inheritdoc}
     */
    public function clearExpire(): bool
    {
        foreach ($this->store as $key => $value) {
            if ($value['expire'] < time()) {
                $this->delete($key);
            }
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function addToExpire(string $key, int $amount): bool
    {
        if ($this->exists($key) && intval($this->store[$key]['expire']) > 0) {
            $this->store[$key]['expire'] = intval($this->store[$key]['expire']) + $amount;
            return true;
        }

        return false;
    }
}
