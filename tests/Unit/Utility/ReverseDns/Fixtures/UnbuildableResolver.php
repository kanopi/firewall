<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility\ReverseDns\Fixtures;

use Kanopi\Firewall\Utility\ReverseDns\LookupResult;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsResolverInterface;

/**
 * A resolver whose constructor wants something configuration cannot give.
 */
final class UnbuildableResolver implements ReverseDnsResolverInterface
{
    public function __construct(\DateTimeInterface $clock)
    {
    }

    public function reverse(string $ip): LookupResult
    {
        return LookupResult::none();
    }

    public function forward(string $hostname, string $type): LookupResult
    {
        return LookupResult::none();
    }
}
