<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility\ReverseDns\Fixtures;

use Kanopi\Firewall\Utility\ReverseDns\LookupResult;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsResolverInterface;

/**
 * A resolver taking options, then an optional collaborator configuration does not give.
 */
final class OptionalArgumentResolver implements ReverseDnsResolverInterface
{
    /**
     * @param array<string, mixed> $options
     */
    public function __construct(public readonly array $options = [], public readonly ?\DateTimeInterface $clock = null)
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
