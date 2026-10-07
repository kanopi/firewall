<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility\ReverseDns\Fixtures;

use Kanopi\Firewall\Utility\ReverseDns\LookupResult;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsResolverInterface;

/**
 * A resolver with no constructor, so it takes no options.
 */
final class NoOptionsResolver implements ReverseDnsResolverInterface
{
    public function reverse(string $ip): LookupResult
    {
        return LookupResult::none();
    }

    public function forward(string $hostname, string $type): LookupResult
    {
        return LookupResult::none();
    }
}
