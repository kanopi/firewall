<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Source;

/**
 * What a fetcher learned about an upstream.
 *
 * A `notModified` result carries no body: the upstream confirmed our cached
 * copy is current, which is the cheap path this whole design aims for.
 */
final class FetchResult
{
    /**
     * @param string|null $body
     *   The fetched bytes, or NULL when nothing was transferred.
     * @param bool $notModified
     *   True when the upstream confirmed the cached copy is still current.
     * @param string|null $etag
     *   Entity tag to send back as `If-None-Match` next time.
     * @param string|null $lastModified
     *   Timestamp to send back as `If-Modified-Since` next time.
     */
    public function __construct(
        public readonly ?string $body = null,
        public readonly bool $notModified = false,
        public readonly ?string $etag = null,
        public readonly ?string $lastModified = null,
    ) {
    }

    /**
     * A result meaning "nothing changed".
     *
     * @param string|null $etag
     *   Entity tag to carry forward.
     * @param string|null $lastModified
     *   Timestamp to carry forward.
     *
     * @return self
     *   The result.
     */
    public static function unchanged(?string $etag = null, ?string $lastModified = null): self
    {
        return new self(null, true, $etag, $lastModified);
    }
}
