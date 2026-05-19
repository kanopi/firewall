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
    public function __construct(string $message, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
