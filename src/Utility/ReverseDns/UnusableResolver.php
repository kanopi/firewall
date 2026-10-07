<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility\ReverseDns;

/**
 * Stands in for a resolver that could not be built, and verifies nothing.
 *
 * `Firewall::create()` refuses a configuration whose resolver cannot be built, so this is
 * reached only by a rule built some other way. Every lookup is unknown: the rule does not
 * match, and nothing is sent anywhere the site did not ask for -- which falling back to
 * PHP's own lookups would not guarantee.
 *
 * @internal
 */
final class UnusableResolver implements ReverseDnsResolverInterface
{
    /**
     * @param string $reason
     *   Why the configured resolver could not be built.
     */
    public function __construct(private readonly string $reason)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function reverse(string $ip): LookupResult
    {
        return LookupResult::unknown($this->reason);
    }

    /**
     * {@inheritdoc}
     */
    public function forward(string $hostname, string $type): LookupResult
    {
        return LookupResult::unknown($this->reason);
    }
}
