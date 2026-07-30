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
 * Storage that can be searched and pruned by address (#26).
 *
 * `StorageInterface` is keyed access: you can `get()`, `set()` and `delete()`
 * an address you already know. That covers the firewall's own hot path and
 * nothing else. It leaves an operator with no way to answer "who is currently
 * blocked?", and no way to lift a block across a range — the two things a
 * support request actually needs.
 *
 * WHY THIS IS A SEPARATE INTERFACE RATHER THAN PART OF StorageInterface:
 *
 * Not every backend can enumerate its own keys. `docs/guides/custom-storage.md`
 * uses Memcached as its worked example, and Memcached cannot reliably list
 * keys at all. Folding these methods into `StorageInterface` would oblige
 * every implementor — including that documented example — to supply something
 * they cannot implement correctly, and the honest implementation would be a
 * lie that returns an empty set. Enumeration is a capability, so it is modelled
 * as one.
 *
 * It also keeps the addition non-breaking: `storage.type` accepts any class
 * implementing `StorageInterface`, and adding methods to that interface would
 * fatal every direct implementor on a `composer update`.
 *
 * Callers must therefore check before use:
 *
 * ```php
 * $storage = StorageFactory::create($config);
 *
 * if ($storage instanceof QueryableStorageInterface) {
 *     $storage->deleteMatching(['203.0.113.0/24']);
 * }
 * ```
 *
 * All three shipped storages implement this. `FileStorage` inherits it from
 * `InMemoryStorage`.
 */
interface QueryableStorageInterface
{
    /**
     * Find stored records whose address matches a pattern.
     *
     * Matching is on the record's address. `AbstractStorageBase::getKey()`
     * stores the client IP verbatim rather than hashing it, which is what
     * makes range matching possible at all.
     *
     * Expired-but-not-yet-collected records are excluded, so what comes back
     * is what is actually in force. An operator reading this to answer "why is
     * this customer blocked?" should not be shown a block that lapsed an hour
     * ago.
     *
     * @param string $pattern
     *   A single IPv4/IPv6 address (`203.0.113.5`) or a CIDR range
     *   (`203.0.113.0/24`, `2001:db8::/32`). An empty or malformed pattern
     *   matches nothing and is logged; it never matches everything, because
     *   the caller's next move is usually to delete what came back.
     *
     * @return array<string, array<string, mixed>>
     *   Matching records keyed by address, each carrying at least `expire`
     *   (unix timestamp, 0 for no expiry) alongside the stored payload.
     *   Empty when nothing matches.
     */
    public function find(string $pattern): array;

    /**
     * Delete every record matching any of the given patterns.
     *
     * The intended use is lifting a block that should not have been applied,
     * so this is additive across patterns: a record matching any one of them
     * is removed.
     *
     * @param array<int, string> $patterns
     *   Addresses and/or CIDR ranges, in the form `find()` accepts. Entries
     *   that are malformed are skipped and logged rather than aborting the
     *   whole call — a typo in one of twenty ranges should not silently leave
     *   the other nineteen in place.
     *
     * @return int
     *   How many records were deleted. Zero when nothing matched, which is
     *   not an error.
     */
    public function deleteMatching(array $patterns): int;
}
