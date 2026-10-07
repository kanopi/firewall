<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility\ReverseDns\Fixtures;

use Kanopi\Firewall\Utility\ReverseDns\LookupResult;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsResolverInterface;

/**
 * A resolver that refuses its options.
 */
final class ThrowingConstructorResolver implements ReverseDnsResolverInterface
{
    /**
     * @param array<string, mixed> $options
     */
    public function __construct(array $options)
    {
        throw new \RuntimeException('no base_url');
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
