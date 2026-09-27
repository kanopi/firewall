<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Storage;

use Memcached;

/**
 * An in-process Memcached, for the paths a real server will not take on request.
 *
 * A mock proves which calls are made. What `MemcachedStorage` needs proving is what happens
 * *between* them -- another worker swapping a shard between this one's read and its
 * compare-and-swap, a shard evicted between two writes, a server that fails on the third
 * call and not the first -- and a real server cannot be asked to do any of that at an exact
 * moment. This keeps state the way Memcached does, CAS tokens included, and lets a test
 * schedule the interruption.
 *
 * The integration test runs the same backend against a real server; this is not a
 * substitute for that.
 */
class FakeMemcached extends Memcached
{
    /**
     * @var array<string, array{value: mixed, cas: int, expires: int}>
     */
    public array $items = [];

    /**
     * Failures to inject, per method, consumed in order.
     *
     * @var array<string, array<int, int>>
     */
    public array $failures = [];

    /**
     * Called just before each `cas()`, with the key, so a test can play a concurrent writer.
     *
     * @var (callable(string, FakeMemcached): void)|null
     */
    public $beforeCas = null;

    /**
     * How many times each method was called.
     *
     * @var array<string, int>
     */
    public array $calls = [];

    /**
     * @var array<int, array{host: string, port: int}>
     */
    public array $servers = [['host' => 'fake', 'port' => 11211]];

    private int $code = Memcached::RES_SUCCESS;

    private int $nextCas = 1;

    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Fail the next call to a method with a result code.
     */
    public function failNext(string $method, int $code = Memcached::RES_FAILURE, int $times = 1): void
    {
        for ($i = 0; $i < $times; $i++) {
            $this->failures[$method][] = $code;
        }
    }

    /**
     * Drop an item, as eviction would.
     */
    public function evict(string $key): void
    {
        unset($this->items[$key]);
    }

    /**
     * Store a raw value, bypassing the backend.
     */
    public function put(string $key, mixed $value, int $expires = 0): void
    {
        $this->items[$key] = ['value' => $value, 'cas' => $this->nextCas++, 'expires' => $expires];
    }

    public function get(string $key, ?callable $cache_cb = null, int $get_flags = 0): mixed
    {
        if ($this->failed('get')) {
            return false;
        }

        $item = $this->live($key);

        if ($item === null) {
            $this->code = Memcached::RES_NOTFOUND;

            return false;
        }

        $this->code = Memcached::RES_SUCCESS;

        return ($get_flags & Memcached::GET_EXTENDED) !== 0
            ? ['value' => $item['value'], 'cas' => $item['cas'], 'flags' => 0]
            : $item['value'];
    }

    public function getMulti(array $keys, int $get_flags = 0): array|false
    {
        if ($this->failed('getMulti')) {
            return false;
        }

        $found = [];

        foreach ($keys as $key) {
            $item = $this->live((string) $key);

            if ($item !== null) {
                $found[(string) $key] = $item['value'];
            }
        }

        $this->code = Memcached::RES_SUCCESS;

        return $found;
    }

    public function set(string $key, mixed $value, int $expiration = 0): bool
    {
        if ($this->failed('set')) {
            return false;
        }

        $this->store($key, $value, $expiration);

        return true;
    }

    public function add(string $key, mixed $value, int $expiration = 0): bool
    {
        if ($this->failed('add')) {
            return false;
        }

        if ($this->live($key) !== null) {
            $this->code = Memcached::RES_NOTSTORED;

            return false;
        }

        $this->store($key, $value, $expiration);

        return true;
    }

    public function cas(string|int|float $cas_token, string $key, mixed $value, int $expiration = 0): bool
    {
        if ($this->beforeCas !== null) {
            ($this->beforeCas)($key, $this);
        }

        if ($this->failed('cas')) {
            return false;
        }

        $item = $this->live($key);

        if ($item === null) {
            $this->code = Memcached::RES_NOTFOUND;

            return false;
        }

        if ($item['cas'] !== (int) $cas_token) {
            $this->code = Memcached::RES_DATA_EXISTS;

            return false;
        }

        $this->store($key, $value, $expiration);

        return true;
    }

    public function delete(string $key, int $time = 0): bool
    {
        if ($this->failed('delete')) {
            return false;
        }

        if ($this->live($key) === null) {
            $this->code = Memcached::RES_NOTFOUND;

            return false;
        }

        unset($this->items[$key]);
        $this->code = Memcached::RES_SUCCESS;

        return true;
    }

    public function deleteMulti(array $keys, int $time = 0): array
    {
        $this->calls['deleteMulti'] = ($this->calls['deleteMulti'] ?? 0) + 1;
        $results = [];

        foreach ($keys as $key) {
            if ($this->live((string) $key) === null) {
                $results[(string) $key] = Memcached::RES_NOTFOUND;
                continue;
            }

            unset($this->items[(string) $key]);
            $results[(string) $key] = true;
        }

        return $results;
    }

    public function getResultCode(): int
    {
        return $this->code;
    }

    public function getResultMessage(): string
    {
        return match ($this->code) {
            Memcached::RES_SUCCESS => 'SUCCESS',
            Memcached::RES_NOTFOUND => 'NOT FOUND',
            default => sprintf('FAKE FAILURE %d', $this->code),
        };
    }

    public function getServerList(): array
    {
        return $this->servers;
    }

    /**
     * Record a call, and fail it when a failure is queued for it.
     */
    private function failed(string $method): bool
    {
        $this->calls[$method] = ($this->calls[$method] ?? 0) + 1;

        if (($this->failures[$method] ?? []) === []) {
            return false;
        }

        $this->code = (int) array_shift($this->failures[$method]);

        return true;
    }

    /**
     * An item, unless it has expired.
     *
     * @return array{value: mixed, cas: int, expires: int}|null
     */
    private function live(string $key): ?array
    {
        $item = $this->items[$key] ?? null;

        if ($item !== null && $item['expires'] > 0 && $item['expires'] <= time()) {
            unset($this->items[$key]);

            return null;
        }

        return $item;
    }

    /**
     * Write an item, reading the expiry the way Memcached does.
     */
    private function store(string $key, mixed $value, int $expiration): void
    {
        $expires = match (true) {
            $expiration === 0 => 0,
            $expiration <= 2592000 => time() + $expiration,
            default => $expiration,
        };

        $this->items[$key] = ['value' => $value, 'cas' => $this->nextCas++, 'expires' => $expires];
        $this->code = Memcached::RES_SUCCESS;
    }
}
