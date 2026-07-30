<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Storage;

use Kanopi\Firewall\Traits\AddressMatchTrait;

/**
 * In-memory key-value store for temporary runtime use.
 */
class InMemoryStorage extends AbstractStorageBase implements QueryableStorageInterface
{
    use AddressMatchTrait;

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

    /**
     * {@inheritdoc}
     */
    public function find(string $pattern): array
    {
        if (!$this->isValidPattern($pattern)) {
            $this->getLogger()->warning('Storage find skipped - not a valid address or CIDR range', [
                'pattern' => $pattern,
            ]);
            return [];
        }

        $now = time();
        $matches = [];

        foreach ($this->store as $address => $record) {
            // $store values are `mixed`, so the shape genuinely has to be
            // checked; the keys are already typed `string` and do not.
            if (!is_array($record)) {
                continue;
            }

            $expire = (int) ($record['expire'] ?? 0);

            // Skip blocks that have lapsed but not yet been collected. An
            // operator asking "why is this customer blocked?" must not be
            // shown a block that expired an hour ago.
            if ($expire > 0 && $expire < $now) {
                continue;
            }

            if (!$this->addressMatches($address, $pattern)) {
                continue;
            }

            $matches[$address] = [
                'value' => $record['value'] ?? null,
                'expire' => $expire,
                'expires_at' => $expire > 0 ? date('c', $expire) : null,
                'offenses' => count($this->offenses[$address] ?? []),
            ];
        }

        $this->getLogger()->debug('Storage find completed', [
            'pattern' => $pattern,
            'matches' => count($matches),
        ]);

        return $matches;
    }

    /**
     * {@inheritdoc}
     */
    public function deleteMatching(array $patterns): int
    {
        $patterns = $this->validPatterns($patterns);

        if ($patterns === []) {
            return 0;
        }

        // Collected before deleting rather than unsetting mid-iteration, so
        // the traversal is not mutated underneath itself.
        $doomed = [];

        foreach (array_keys($this->store) as $address) {
            foreach ($patterns as $pattern) {
                if ($this->addressMatches($address, $pattern)) {
                    $doomed[] = $address;
                    break;
                }
            }
        }

        $deleted = 0;

        foreach ($doomed as $address) {
            // Offenses are dropped alongside the block. Leaving them behind
            // would mean an address un-blocked by an operator gets escalated
            // straight back to a longer ban by `blocking_escalation` on its
            // next offence — the block would look lifted and would not be.
            unset($this->offenses[$address]);

            // Unset directly rather than calling $this->delete().
            //
            // FileStorage overrides delete() to take an exclusive lock, and
            // its deleteMatching() override already holds that same lock.
            // withExclusiveLock() opens a fresh handle per call, and flock()
            // locks attach to the open file description, so a nested call
            // blocks on a lock this very process is holding — a permanent
            // self-deadlock, not a slow path. Verified: a second
            // LOCK_EX|LOCK_NB on the same file in one process returns false.
            if (array_key_exists($address, $this->store)) {
                unset($this->store[$address]);
                $deleted++;
            }
        }

        $this->getLogger()->info('Storage records deleted by pattern', [
            'patterns' => $patterns,
            'deleted' => $deleted,
        ]);

        return $deleted;
    }
}
