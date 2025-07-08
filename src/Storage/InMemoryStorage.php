<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

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
     * Stores the offenses.
     * @var array<string, array<mixed>>
     */
    protected array $offenses = [];

    /**
     * {@inheritdoc}
     */
    public function recordOffense(string $key): bool
    {
        if (!array_key_exists($key, $this->offenses)) {
            $this->offenses[$key] = [];
        }

        $this->offenses[$key][] = [
            'timestamp' => date('c'),
        ];
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function set(string $key, array $value, int $expire = 0): bool
    {
        if ($this->exists($key)) {
            $this->store[$key]['value'] = $value;
        } else {
            $this->store[$key] = [
                "value" => $value,
                "expire" => $expire > 0 ? time() + $expire : 0,
            ];
        }

        $this->getLogger()->debug('Value set in memory storage', [
            'key' => $key,
            'expire' => $expire,
            'expire_at' => $expire > 0 ? date('c', time() + $expire) : 'never',
        ]);

        $this->recordOffense($key);

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function delete(string $key): bool
    {
        if ($this->exists($key)) {
            unset($this->store[$key]);
            $this->getLogger()->debug('Key deleted from memory storage', [
                'key' => $key,
            ]);
            return true;
        }

        $this->getLogger()->debug('Key not found for deletion in memory storage', [
            'key' => $key,
        ]);
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $value = $this->store[$key] ?? null;
        if ($value === null || ($value['expire'] > 0 && $value['expire'] < time())) {
            if ($value !== null && $value['expire'] > 0 && $value['expire'] < time()) {
                $this->getLogger()->debug('Key expired in memory storage', [
                    'key' => $key,
                    'expired_at' => date('c', $value['expire']),
                ]);
            }

            $this->delete($key);
            return $default;
        }

        $this->getLogger()->debug('Value retrieved from memory storage', [
            'key' => $key,
            'expires_at' => $value['expire'] > 0 ? date('c', $value['expire']) : 'never',
        ]);

        return $value['value'];
    }

    /**
     * {@inheritdoc}
     */
    public function reset(): bool
    {
        $previousCount = count($this->store);
        $this->store = [];

        $this->getLogger()->info('Memory storage reset', [
            'entries_cleared' => $previousCount,
        ]);

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
    public function expire(): bool
    {
        $cleared = 0;
        $currentTime = time();

        foreach ($this->store as $key => $value) {
            if ($value['expire'] > 0 && $value['expire'] < $currentTime) {
                $this->delete($key);
                $cleared++;
            }
        }

        if ($cleared > 0) {
            $this->getLogger()->debug('Expired entries cleared from memory storage', [
                'entries_cleared' => $cleared,
            ]);
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function addToExpire(string $key, int $amount): bool
    {
        if ($this->exists($key) && intval($this->store[$key]['expire']) > 0) {
            $oldExpire = $this->store[$key]['expire'];
            $this->store[$key]['expire'] = intval($this->store[$key]['expire']) + $amount;

            $this->getLogger()->debug('Expiration extended in memory storage', [
                'key' => $key,
                'old_expire' => date('c', $oldExpire),
                'new_expire' => date('c', $this->store[$key]['expire']),
                'additional_seconds' => $amount,
            ]);

            return true;
        }

        $this->getLogger()->debug('Cannot extend expiration - key not found or no expiration set', [
            'key' => $key,
            'exists' => $this->exists($key),
        ]);

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function countOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX): int
    {
        return count(array_filter($this->offenses[$key] ?? [], function (array $item) use ($start, $end): bool {
            return strtotime((string) $item['timestamp']) >= $start && strtotime((string) $item['timestamp']) <= $end;
        }));
    }
}
