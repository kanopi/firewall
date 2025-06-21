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
