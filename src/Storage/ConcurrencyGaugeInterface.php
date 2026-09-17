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
 * How many of something are happening right now, counted atomically (#329).
 *
 * `StorageInterface` has no atomic increment and `RateLimitStorageInterface`
 * counts a *rate* rather than a concurrency -- "how many requests arrived in
 * the last minute" is not "how many are in flight", and using one for the other
 * is wrong in the direction that matters.
 *
 * This is optional, in the shape `QueryableStorageInterface` already
 * established: a backend that can do it implements it, callers check
 * `instanceof`, and nothing about the existing contract moves. That is what
 * keeps a real concurrency gauge out of a major release.
 *
 * ## A backend that cannot do this atomically must not implement it
 *
 * The point of the gauge is a cap, and the point of the cap is that a tarpit
 * cannot exhaust the worker pool. A gauge that under-counts lets more tarpits
 * through than the cap allows, which is precisely the self-DoS the cap exists
 * to prevent -- so *not implementing this* is the correct answer for a backend
 * that can only approximate it. A tarpit rule configured against such a backend
 * refuses to start, which is loud, rather than running uncapped, which looks
 * like it is working.
 *
 * `InMemoryStorage` is the instructive case: incrementing a PHP array is
 * perfectly atomic *within one process*, and a concurrency cap across php-fpm
 * workers is exactly the thing one process cannot see. It does not implement
 * this.
 *
 * ## Per-host is the right scope, not a compromise
 *
 * What a tarpit consumes is php-fpm workers, and those are per-host. A
 * file-locked counter that only sees one machine is therefore counting the
 * right pool. A Redis-backed one counts the fleet, which is broader than
 * necessary and also fine.
 */
interface ConcurrencyGaugeInterface
{
    /**
     * Claim a slot, and say how many are now held.
     *
     * @param string $key
     *   What is being counted.
     * @param int $ttl
     *   Seconds after which the count clears itself. A backstop for a worker
     *   killed between `enter()` and `leave()` -- set it comfortably above the
     *   longest hold, because while it has not expired the leaked count makes
     *   the cap *stricter*, which is the safe direction.
     *
     * @return int
     *   The number of slots now held, including this one -- so a successful
     *   claim is always 1 or more. **Zero means the count could not be taken
     *   atomically**, and a caller must treat that as "do not proceed" rather
     *   than as "nothing is in flight".
     */
    public function enter(string $key, int $ttl): int;

    /**
     * Release a slot.
     *
     * Must be safe to call when no slot is held -- a caller releasing in a
     * `finally` cannot always know whether the claim succeeded, and the
     * alternative is a leak on every error path. Must never take the count
     * below zero.
     *
     * @param string $key
     *   What is being counted.
     */
    public function leave(string $key): void;

    /**
     * How many slots are held, without claiming one.
     *
     * For reporting. A cap must use `enter()`'s return value instead: reading
     * and then claiming is two operations, and the gap between them is where
     * the cap stops holding.
     *
     * @param string $key
     *   What is being counted.
     *
     * @return int
     *   Slots currently held.
     */
    public function inFlight(string $key): int;
}
