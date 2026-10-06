<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility\ReverseDns;

use Kanopi\Firewall\Utility\ReverseDns\LookupResult;
use Kanopi\Firewall\Utility\ReverseDns\SystemResolver;
use PHPUnit\Framework\TestCase;

/**
 * PHP's own lookups, through their seams (#473).
 */
class SystemResolverTest extends TestCase
{
    /**
     * @param string|false $ptr
     * @param array<int, array<string, mixed>>|false $records
     */
    private function resolver(string|false $ptr, array|false $records = false): SystemResolver
    {
        return new class ($ptr, $records) extends SystemResolver {
            /**
             * @param array<int, array<string, mixed>>|false $records
             */
            public function __construct(private readonly string|false $ptr, private readonly array|false $records)
            {
            }

            protected function reverseLookup(string $ip): string|false
            {
                return $this->ptr;
            }

            protected function forwardLookup(string $host): array|false
            {
                return $this->records;
            }
        };
    }

    public function testAHostnameIsAnAnswer(): void
    {
        $this->assertSame(['crawl.googlebot.com'], $this->resolver('crawl.googlebot.com')->reverse('66.249.66.1')->values);
    }

    public function testTheAddressHandedBackIsNoRecord(): void
    {
        $this->assertSame(LookupResult::NONE, $this->resolver('66.249.66.1')->reverse('66.249.66.1')->status);
    }

    public function testAFailureIsNoRecordBecauseItCannotBeToldApart(): void
    {
        $this->assertSame(LookupResult::NONE, $this->resolver(false)->reverse('66.249.66.1')->status);
        $this->assertSame(LookupResult::NONE, $this->resolver(false, false)->forward('crawl.googlebot.com', 'A')->status);
    }

    public function testAForwardLookupKeepsTheFamilyAskedFor(): void
    {
        $resolver = $this->resolver(false, [
            ['type' => 'A', 'ip' => '66.249.66.1'],
            ['type' => 'AAAA', 'ipv6' => '2001:4860:4801::1'],
            ['type' => 'CNAME', 'target' => 'alias.example'],
        ]);

        $this->assertSame(['66.249.66.1'], $resolver->forward('crawl.googlebot.com', 'A')->values);
        $this->assertSame(['2001:4860:4801::1'], $resolver->forward('crawl.googlebot.com', 'AAAA')->values);
    }
}
