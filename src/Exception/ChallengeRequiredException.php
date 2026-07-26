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
 * Thrown in FirewallMode::Exception when a `response: challenge` plugin
 * matches.
 *
 * Mirrors FirewallBlockedException for the challenge path so test suites
 * can assert that an interstitial *would have* been served without the
 * Firewall actually `exit()`-ing the process.
 */
class ChallengeRequiredException extends FirewallException
{
    /**
     * Constructs a new ChallengeRequiredException object.
     *
     * @param string $message
     *   Human-readable reason, naming the plugin that demanded the challenge.
     * @param \Throwable|null $previous
     *   Previous exception for chaining, if any.
     */
    public function __construct(string $message, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
