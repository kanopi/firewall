<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Exception;

/**
 * A rule is sending this visitor somewhere instead of refusing them (#203).
 *
 * The gentler end of a terminal decision: a static notice, a status page, a contact form
 * for somebody who believes they were caught wrongly. A block tells a visitor nothing and
 * leaves them nowhere to go, which is fine for a scanner and poor for the false positive.
 *
 * Raised only in `mode: exception`; every other mode writes the `Location` header and exits.
 */
class FirewallRedirectException extends FirewallException
{
    /**
     * @param string $location
     *   Where to send them. Comes from the rule's `metadata.redirect_to` and
     *   is never built from the request, so it cannot become an open redirect.
     * @param int $statusCode
     *   The redirect status — 302 unless the rule says otherwise.
     * @param \Throwable|null $previous
     *   Previous exception for chaining, if any.
     */
    public function __construct(
        private readonly string $location,
        private readonly int $statusCode = 302,
        ?\Throwable $previous = null
    ) {
        parent::__construct(sprintf('Redirected to %s', $location), $statusCode, $previous);
    }

    /**
     * Where the visitor is being sent.
     *
     * @return string
     *   The `Location` value.
     */
    public function getLocation(): string
    {
        return $this->location;
    }

    /**
     * The redirect status to send.
     *
     * @return int
     *   301, 302, 307 or 308.
     */
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }
}
