<?php

namespace Kanopi\Firewall\Plugins\RateLimitStorage;

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
