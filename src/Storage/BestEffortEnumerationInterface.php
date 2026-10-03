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
 * A queryable storage whose enumeration can be incomplete, and can say when it is.
 *
 * `QueryableStorageInterface` promises that `find()` never passes off an empty
 * set as the truth. A backend that answers from its own index rather than from
 * the keyspace -- because the keyspace cannot be listed at all -- can lose part
 * of that index without losing the records it points at. Its answers are then
 * true and incomplete, and "nothing matched" stops meaning "nothing is blocked".
 *
 * This is how such a backend says so, so `BlockList::backend()` and
 * `bin/firewall block` can warn rather than answer with false confidence (#392).
 *
 * A separate interface for the same reason enumeration is one: adding a method
 * to `QueryableStorageInterface` would break every third-party implementation
 * of it on upgrade, and most backends have nothing to report.
 */
interface BestEffortEnumerationInterface
{
    /**
     * Why enumeration may currently be missing records, or NULL when it is not.
     *
     * Exact-address lookups are unaffected by any gap reported here: a backend
     * implementing this must answer those from the record itself.
     *
     * @return string|null
     *   A sentence an operator can act on, or NULL when every record written is
     *   reachable through `find()`.
     */
    public function enumerationGap(): ?string;
}
