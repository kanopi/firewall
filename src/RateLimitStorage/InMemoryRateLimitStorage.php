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
class InMemoryRateLimitStorage extends AbstractRateLimitStorage
{
    protected array $requests = [];

    /**
     * {@inheritdoc}
     */
    public function recordRequest(string $key, int $timestamp): void
    {
        $this->requests[$key][] = $timestamp;
    }

    /**
     * {@inheritdoc}
     */
    public function countRequests(string $key, int $start, int $end): int
    {
        if (!isset($this->requests[$key])) {
            return 0;
        }

        // Filter timestamps within range.
        return count(array_filter($this->requests[$key], fn($t): bool => $t >= $start && $t <= $end));
    }
}
