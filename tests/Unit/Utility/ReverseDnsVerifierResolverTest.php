<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Tests\Unit\Utility\ReverseDns\Fixtures\ScriptedResolver;
use Kanopi\Firewall\Utility\DegradedBackends;
use Kanopi\Firewall\Utility\ReverseDns\LookupResult;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsResolverInterface;
use Kanopi\Firewall\Utility\ReverseDnsVerifier;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * The verifier with a resolver making the lookups (#473).
 *
 * What a resolver may not do is the point of most of these: decide a verdict, skip the
 * forward confirmation, or hand back something that is not a hostname.
 */
class ReverseDnsVerifierResolverTest extends AbstractTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        ScriptedResolver::reset();
        DegradedBackends::reset();
    }

    protected function tearDown(): void
    {
        ScriptedResolver::reset();
        DegradedBackends::reset();
        parent::tearDown();
    }

    private function verifier(?CacheItemPoolInterface $cache = null, ?ReverseDnsResolverInterface $resolver = null, float $threshold = 250.0): ReverseDnsVerifier
    {
        return new ReverseDnsVerifier($cache, 3600, 86400, false, $threshold, 300, 0, $resolver ?? new ScriptedResolver(), 60);
    }

    public function testAConfirmedRoundTripVerifies(): void
    {
        ScriptedResolver::$reverse['66.249.66.1'] = LookupResult::answer(['crawl-66-249-66-1.googlebot.com.']);
        ScriptedResolver::$forward['crawl-66-249-66-1.googlebot.com A'] = LookupResult::answer(['66.249.66.1']);

        $this->assertTrue($this->verifier()->verify('66.249.66.1', ['.googlebot.com']));
        $this->assertSame(['reverse 66.249.66.1', 'forward crawl-66-249-66-1.googlebot.com A'], ScriptedResolver::$asked);
    }

    public function testAnIpv6ClientIsConfirmedAgainstAddressRecords(): void
    {
        ScriptedResolver::$reverse['2001:4860:4801::1'] = LookupResult::answer(['crawl.googlebot.com']);
        ScriptedResolver::$forward['crawl.googlebot.com AAAA'] = LookupResult::answer(['2001:4860:4801:0::1']);

        $this->assertTrue($this->verifier()->verify('2001:4860:4801::1', ['googlebot.com']));
    }

    public function testAnyPtrRecordMayConfirm(): void
    {
        ScriptedResolver::$reverse['66.249.66.1'] = LookupResult::answer(['host.example.net', 'crawl.googlebot.com']);
        ScriptedResolver::$forward['crawl.googlebot.com A'] = LookupResult::answer(['66.249.66.1']);

        $this->assertTrue($this->verifier()->verify('66.249.66.1', ['.googlebot.com']));
    }

    public function testAForwardLookupThatDoesNotComeBackFails(): void
    {
        ScriptedResolver::$reverse['203.0.113.9'] = LookupResult::answer(['crawl.googlebot.com']);
        ScriptedResolver::$forward['crawl.googlebot.com A'] = LookupResult::answer(['66.249.66.1']);

        $this->assertFalse($this->verifier()->verify('203.0.113.9', ['.googlebot.com']));
    }

    public function testSomethingThatIsNotAHostnameIsNeverLookedUp(): void
    {
        ScriptedResolver::$reverse['203.0.113.9'] = LookupResult::answer([
            'crawl.googlebot.com&type=TXT',
            'crawl googlebot.com',
            str_repeat('a', 64) . '.googlebot.com',
            str_repeat('a.', 127) . 'googlebot.com',
        ]);

        $this->assertFalse($this->verifier()->verify('203.0.113.9', ['.googlebot.com']));
        $this->assertSame(['reverse 203.0.113.9'], ScriptedResolver::$asked);
    }

    public function testAHostnameOutsideTheDomainsIsNeverLookedUp(): void
    {
        ScriptedResolver::$reverse['203.0.113.9'] = LookupResult::answer(['crawl.evilgooglebot.com']);

        $this->assertFalse($this->verifier()->verify('203.0.113.9', ['.googlebot.com']));
        $this->assertSame(['reverse 203.0.113.9'], ScriptedResolver::$asked);
    }

    public function testNoMoreThanTenHostnamesAreTried(): void
    {
        $hosts = [];

        for ($i = 0; $i < 15; $i++) {
            $hosts[] = 'h' . $i . '.googlebot.com';
        }

        ScriptedResolver::$reverse['203.0.113.9'] = LookupResult::answer($hosts);

        $this->assertFalse($this->verifier()->verify('203.0.113.9', ['.googlebot.com']));
        $this->assertCount(11, ScriptedResolver::$asked);
    }

    public function testAMalformedAddressIsNeverLookedUp(): void
    {
        $this->assertFalse($this->verifier()->verify('not-an-address', ['.googlebot.com']));
        $this->assertSame([], ScriptedResolver::$asked);
    }

    public function testNoRecordIsRememberedForTheNegativeTtl(): void
    {
        $cache = new ArrayAdapter();

        $this->assertFalse($this->verifier($cache)->verify('203.0.113.9', ['.googlebot.com']));

        $this->assertEqualsWithDelta(86400, $this->secondsLeft($cache), 2);
    }

    public function testAReverseLookupThatCannotTellIsRememberedOnlyBriefly(): void
    {
        $cache = new ArrayAdapter();
        ScriptedResolver::$reverse['66.249.66.1'] = LookupResult::unknown('HTTP 503');

        $this->assertFalse($this->verifier($cache)->verify('66.249.66.1', ['.googlebot.com']));

        $this->assertEqualsWithDelta(60, $this->secondsLeft($cache), 2);
    }

    public function testAForwardLookupThatCannotTellIsRememberedOnlyBriefly(): void
    {
        $cache = new ArrayAdapter();
        ScriptedResolver::$reverse['66.249.66.1'] = LookupResult::answer(['crawl.googlebot.com']);
        ScriptedResolver::$forward['crawl.googlebot.com A'] = LookupResult::unknown('timeout');

        $this->assertFalse($this->verifier($cache)->verify('66.249.66.1', ['.googlebot.com']));

        $this->assertEqualsWithDelta(60, $this->secondsLeft($cache), 2);
    }

    public function testAConfirmationAfterAnUnknownStillVerifies(): void
    {
        ScriptedResolver::$reverse['66.249.66.1'] = LookupResult::answer(['a.googlebot.com', 'b.googlebot.com']);
        ScriptedResolver::$forward['a.googlebot.com A'] = LookupResult::unknown('timeout');
        ScriptedResolver::$forward['b.googlebot.com A'] = LookupResult::answer(['66.249.66.1']);

        $this->assertTrue($this->verifier()->verify('66.249.66.1', ['.googlebot.com']));
    }

    public function testAResolverThatThrowsVerifiesNobodyAndIsReported(): void
    {
        $resolver = new class implements ReverseDnsResolverInterface {
            public function reverse(string $ip): LookupResult
            {
                throw new \RuntimeException('platform API is down');
            }

            public function forward(string $hostname, string $type): LookupResult
            {
                return LookupResult::none();
            }
        };

        $this->assertFalse($this->verifier(null, $resolver)->verify('66.249.66.1', ['.googlebot.com']));

        $degraded = DegradedBackends::all();
        $this->assertCount(1, $degraded);
        $this->assertSame('reverse DNS', $degraded[0]['component']);
        $this->assertSame('platform API is down', $degraded[0]['error']);
    }

    public function testASlowResolverTripsTheBreaker(): void
    {
        $cache = new ArrayAdapter();
        $resolver = new class implements ReverseDnsResolverInterface {
            public function reverse(string $ip): LookupResult
            {
                usleep(5000);

                return LookupResult::none();
            }

            public function forward(string $hostname, string $type): LookupResult
            {
                return LookupResult::none();
            }
        };

        $this->verifier($cache, $resolver, 1.0)->verify('66.249.66.1', ['.googlebot.com']);

        $this->assertTrue($cache->getItem('rdns_breaker')->isHit());
    }

    private function secondsLeft(ArrayAdapter $cache): float
    {
        $values = $cache->getValues();
        $this->assertNotEmpty($values);

        $reflection = new \ReflectionProperty(ArrayAdapter::class, 'expiries');
        /** @var array<string, float> $expiries */
        $expiries = $reflection->getValue($cache);

        foreach ($expiries as $key => $expiry) {
            if (str_starts_with((string) $key, 'rdns_') && !str_ends_with((string) $key, '_inflight')) {
                return $expiry - microtime(true);
            }
        }

        $this->fail('No verdict was cached');
    }
}
