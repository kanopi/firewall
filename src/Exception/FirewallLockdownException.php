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
 * The site is in lockdown and this visitor is not on the allowlist (#304).
 *
 * Extends `FirewallBlockedException` on purpose: a host already catching that keeps working
 * without knowing lockdown exists, and one that wants to say something kinder than "banned"
 * can catch this first.
 *
 * Carries `Retry-After` because a lockdown is **temporary and deliberate**, which is exactly
 * what a 503 with that header means — and what a CDN in front of the site will honour rather
 * than caching a refusal it thinks is permanent.
 */
class FirewallLockdownException extends FirewallBlockedException
{
    /**
     * @param string $message
     *   What to tell the visitor.
     * @param int $statusCode
     *   503 unless `global.lockdown_status` says otherwise.
     * @param int $retryAfter
     *   Seconds to put in `Retry-After`. Zero omits the header.
     * @param \Throwable|null $previous
     *   Previous exception for chaining, if any.
     */
    public function __construct(
        string $message,
        int $statusCode = 503,
        private readonly int $retryAfter = 300,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $statusCode, $previous);
    }

    /**
     * How long to tell the visitor to wait.
     *
     * @return int
     *   Seconds, or 0 when no `Retry-After` should be sent.
     */
    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }
}
