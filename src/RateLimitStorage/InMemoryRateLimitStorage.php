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
 * In-memory rate limit storage.
 */
class InMemoryRateLimitStorage extends AbstractRateLimitStorage implements PrunableRateLimitStorageInterface
{
    protected array $requests = [];

    /**
     * {@inheritdoc}
     */
    public function recordRequest(string $key, int $timestamp): void
    {
        $this->requests[$key][] = $timestamp;

        $this->getLogger()->debug('In-memory rate limit request recorded', [
            'key' => $key,
            'timestamp' => $timestamp,
            'total_requests_for_key' => count($this->requests[$key]),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function forget(string $key, int $before): int
    {
        if (!isset($this->requests[$key])) {
            return 0;
        }

        $before = max(0, $before);
        $kept = array_values(array_filter($this->requests[$key], static fn($timestamp): bool => $timestamp >= $before));
        $dropped = count($this->requests[$key]) - count($kept);

        // The key itself is unset when nothing is left, not stored as an empty
        // list. A rate key carries a client address, so a busy site sees an
        // unbounded number of distinct keys over time -- leaving each one
        // behind as an empty array would keep the *key set* growing after the
        // fix that was meant to stop the data growing.
        if ($kept === []) {
            unset($this->requests[$key]);
        } else {
            $this->requests[$key] = $kept;
        }

        if ($dropped > 0) {
            $this->getLogger()->debug('Dropped rate limit records outside the window', [
                'key' => $key,
                'before' => $before,
                'dropped' => $dropped,
                'remaining' => count($kept),
            ]);
        }

        return $dropped;
    }

    /**
     * {@inheritdoc}
     */
    public function countRequests(string $key, int $start, int $end): int
    {
        if (!isset($this->requests[$key])) {
            $this->getLogger()->debug('No requests found for key', [
                'key' => $key,
            ]);
            return 0;
        }

        // Filter timestamps within range.
        $count = count(array_filter($this->requests[$key], fn($t): bool => $t >= $start && $t <= $end));

        $this->getLogger()->debug('In-memory rate limit request count', [
            'key' => $key,
            'start' => $start,
            'end' => $end,
            'count' => $count,
            'window_seconds' => $end - $start,
        ]);

        return $count;
    }
}
