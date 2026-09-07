<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\ReverseDnsVerifier;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Cover the round trip that makes a crawler allow rule worth anything (#199).
 *
 * No test here touches the network: both lookups are seams on the class.
 */
class ReverseDnsVerifierTest extends AbstractTestCase
{
    /**
     * A verifier with both DNS lookups stubbed.
     *
     * @param string|false $ptr
     *   What the reverse lookup returns.
     * @param array<int, array<string, mixed>>|false $forward
     *   What the forward lookup returns.
     * @param \Psr\Cache\CacheItemPoolInterface|null $cache
     *   Optional pool.
     */
    private function verifier(string|false $ptr, array|false $forward, $cache = null): ReverseDnsVerifier
    {
        return new class ($ptr, $forward, $cache) extends ReverseDnsVerifier {
            public int $reverseCalls = 0;

            public function __construct(
                private string|false $ptr,
                private array|false $forward,
                $cache = null
            ) {
                parent::__construct($cache, 3600);
            }

            protected function reverseLookup(string $ip): string|false
            {
                $this->reverseCalls++;
                return $this->ptr;
            }

            protected function forwardLookup(string $host): array|false
            {
                return $this->forward;
            }
        };
    }

    /**
     * The happy path: PTR in an accepted domain, forward-confirming.
     */
    public function testAGenuineCrawlerVerifies(): void
    {
        $verifier = $this->verifier(
            'crawl-66-249-66-1.googlebot.com',
            [['ip' => '66.249.66.1']]
        );

        $this->assertTrue($verifier->verify('66.249.66.1', ['.googlebot.com']));
    }

    /**
     * A lookalike domain must not pass.
     *
     * The reason suffixes are matched on a label boundary rather than with a bare
     * str_ends_with: `evilgooglebot.com` is registrable by anyone, and a bare suffix
     * check would hand them a bypass of every rule below an allow.
     */
    public function testALookalikeDomainDoesNotVerify(): void
    {
        $verifier = $this->verifier(
            'crawl.evilgooglebot.com',
            [['ip' => '203.0.113.5']]
        );

        $this->assertFalse($verifier->verify('203.0.113.5', ['googlebot.com']));
    }

    /**
     * The domain itself is accepted, not only subdomains of it.
     */
    public function testTheDomainItselfVerifies(): void
    {
        $verifier = $this->verifier('googlebot.com', [['ip' => '66.249.66.1']]);

        $this->assertTrue($verifier->verify('66.249.66.1', ['googlebot.com']));
    }

    /**
     * Reverse DNS alone is not enough -- anyone can set a PTR record for their
     * own address. Only the forward lookup proves it.
     */
    public function testAForgedPtrWithoutForwardConfirmationFails(): void
    {
        $verifier = $this->verifier(
            'crawl-1-2-3-4.googlebot.com',
            [['ip' => '8.8.8.8']] // resolves somewhere else entirely
        );

        $this->assertFalse($verifier->verify('203.0.113.5', ['.googlebot.com']));
    }

    /**
     * No PTR record: gethostbyaddr() hands the address straight back.
     */
    public function testNoPtrRecordFails(): void
    {
        $verifier = $this->verifier('203.0.113.5', [['ip' => '203.0.113.5']]);

        $this->assertFalse($verifier->verify('203.0.113.5', ['.googlebot.com']));
    }

    /**
     * DNS unreachable must narrow the allow rule, not widen it.
     */
    public function testAFailedLookupFailsClosed(): void
    {
        $verifier = $this->verifier(false, false);

        $this->assertFalse($verifier->verify('66.249.66.1', ['.googlebot.com']));
    }

    /**
     * A forward lookup that returns nothing fails closed too.
     */
    public function testAnEmptyForwardLookupFailsClosed(): void
    {
        $verifier = $this->verifier('crawl.googlebot.com', []);

        $this->assertFalse($verifier->verify('66.249.66.1', ['.googlebot.com']));
    }

    /**
     * An empty suffix list is not "accept anything".
     */
    public function testNoSuffixesVerifiesNothing(): void
    {
        $verifier = $this->verifier('crawl.googlebot.com', [['ip' => '66.249.66.1']]);

        $this->assertFalse($verifier->verify('66.249.66.1', []));
    }

    /**
     * IPv6 confirms through the AAAA record, normalised before comparing.
     */
    public function testIpv6ForwardConfirms(): void
    {
        $verifier = $this->verifier(
            'crawl.googlebot.com',
            [['ipv6' => '2001:0db8:0000:0000:0000:0000:0000:0001']]
        );

        $this->assertTrue($verifier->verify('2001:db8::1', ['.googlebot.com']));
    }

    /**
     * A verdict is cached, so the request path pays for DNS once.
     */
    public function testAVerdictIsCached(): void
    {
        $pool = new ArrayAdapter();
        $verifier = $this->verifier('crawl.googlebot.com', [['ip' => '66.249.66.1']], $pool);

        $this->assertTrue($verifier->verify('66.249.66.1', ['.googlebot.com']));
        $this->assertTrue($verifier->verify('66.249.66.1', ['.googlebot.com']));

        $this->assertSame(1, $verifier->reverseCalls, 'The second call should come from the cache');
    }

    /**
     * A negative verdict is cached too, so a flood of spoofers cannot turn into
     * a flood of DNS lookups.
     */
    public function testANegativeVerdictIsCached(): void
    {
        $pool = new ArrayAdapter();
        $verifier = $this->verifier('crawl.evilgooglebot.com', [['ip' => '203.0.113.5']], $pool);

        $this->assertFalse($verifier->verify('203.0.113.5', ['.googlebot.com']));
        $this->assertFalse($verifier->verify('203.0.113.5', ['.googlebot.com']));

        $this->assertSame(1, $verifier->reverseCalls, 'A refusal should be cached like an acceptance');
    }

    /**
     * A trailing dot on the PTR record, which is legal, must not break matching.
     */
    public function testATrailingDotOnThePtrIsTolerated(): void
    {
        $verifier = $this->verifier('crawl.googlebot.com.', [['ip' => '66.249.66.1']]);

        $this->assertTrue($verifier->verify('66.249.66.1', ['.googlebot.com']));
    }
}
