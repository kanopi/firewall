<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Cache;

/**
 * A configured cache pool that could not be built.
 *
 * Two kinds, because the callers treat them differently. A setting that does not name a
 * pool at all is a configuration mistake, and the user-agent cache falls back to its
 * default for it. A pool that was named correctly and could not be built -- a server that
 * is down, an extension that is missing -- is an environment problem. The user-agent and
 * GeoIP caches then run uncached rather than quietly substituting something the operator
 * did not ask for; reverse DNS falls back to its file cache, because without a cache every
 * request pays a DNS round trip.
 *
 * Neither is ever thrown out of a rule. A cache is an optimisation (#394).
 */
final class CachePoolException extends \RuntimeException
{
    private function __construct(string $message, private readonly bool $notAPool, ?\Throwable $throwable = null)
    {
        parent::__construct($message, 0, $throwable);
    }

    /**
     * The setting does not name a PSR-6 pool.
     */
    public static function notAPool(string $message): self
    {
        return new self($message, true);
    }

    /**
     * The setting names a pool, and it could not be built.
     */
    public static function unusable(string $message, ?\Throwable $throwable = null): self
    {
        return new self($message, false, $throwable);
    }

    /**
     * Is this a setting that names no pool, rather than one that could not be built?
     */
    public function isNotAPool(): bool
    {
        return $this->notAPool;
    }
}
