<?php

namespace Kanopi\Firewall\Plugins\RateLimitStorage;

/**
 * Rate Limiting Storage Interface.
 */
interface RateLimitStorageInterface
{
    /**
     * Record the request for the provided key.
     *
     * @param string $key
     *   Key to record.
     * @param int $timestamp
     *   Timestamp to record.
     */
    public function recordRequest(string $key, int $timestamp): void;

    /**
     * Count the number of requests for the provided key.
     *
     * @param string $key
     *   Key to search against.
     * @param int $start
     *   Start timestamp.
     * @param int $end
     *   End timestamp.
     *
     * @return int
     *   Return number of requests found.
     */
    public function countRequests(string $key, int $start, int $end): int;
}
