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
 * Rate limit storage that can drop records it will never count again (#183).
 *
 * `RateLimitStorageInterface` only appends. `recordRequest()` writes a
 * timestamp and nothing in the interface, the plugin, or any backend ever
 * removed one, so every backend grew:
 *
 * | Backend | Before | Bounded by |
 * |---|---|---|
 * | `InMemoryRateLimitStorage` | grows | the process ending |
 * | `CacheRateLimitStorage` | grows | its `ttl`, then the whole key is dropped |
 * | `RedisRateLimitStorage` | grows | its `ttl`, then the whole key is dropped |
 * | `FileRateLimitStorage` | grows | **nothing** |
 * | `DatabaseRateLimitStorage` | grows | **nothing** |
 *
 * The two persistent backends were the two with no bound at all, which is not
 * a coincidence: the others inherited one from the store they sit on, so
 * nobody ever had to write a retention rule and the backends that needed an
 * explicit one never got it.
 *
 * A rate limit is a rolling window, so the dead data is easy to identify
 * exactly. `RateLimit::evaluate()` counts over `[now - sample, now]` and then
 * records; every timestamp for that key older than `now - sample` has already
 * stopped affecting the verdict and can never affect a later one, because the
 * window only ever moves forward. That is what `forget()` drops -- not a
 * heuristic retention period an operator has to choose and keep in step with
 * the widest rule they have configured.
 *
 * WHY THIS IS A SEPARATE INTERFACE RATHER THAN PART OF RateLimitStorageInterface:
 *
 * `plugins[].metadata.storage.type` accepts any class implementing
 * `RateLimitStorageInterface`, so adding a method to it would fatal every
 * direct implementor on a `composer update`. It is also genuinely optional:
 * a backend built on a store that expires records itself has nothing to do
 * here, and should not be obliged to write a method that lies. Modelled as a
 * capability for the same reasons `QueryableStorageInterface` is.
 *
 * Callers must therefore check before use:
 *
 * ```php
 * if ($storage instanceof PrunableRateLimitStorageInterface) {
 *     $storage->forget($key, $windowStart);
 * }
 * ```
 *
 * All five shipped backends implement it. `FileRateLimitStorage` overrides
 * what it inherits from `InMemoryRateLimitStorage` so the pruned state reaches
 * disk.
 */
interface PrunableRateLimitStorageInterface
{
    /**
     * Drop recorded requests for a key that are older than a cutoff.
     *
     * Implementations must not touch other keys: the caller knows the window
     * for the key it names and knows nothing about anyone else's.
     *
     * A failure is not worth propagating -- pruning is housekeeping, and a
     * rate limit that still counts correctly against a table it could not tidy
     * is working. Implementations report the failure and return 0.
     *
     * @param string $key
     *   The rate key, as `recordRequest()` was given it.
     * @param int $before
     *   Unix timestamp. Records strictly older than this are dropped; a record
     *   exactly at the cutoff is kept, because `countRequests()` treats its
     *   `$start` as inclusive and dropping it would lose a request the current
     *   window still counts.
     *
     * @return int
     *   How many records were dropped, or 0 when there were none and when the
     *   attempt failed. Callers use it for logging, not for control flow.
     */
    public function forget(string $key, int $before): int;
}
