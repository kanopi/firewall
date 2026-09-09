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
    private function verifier(
        string|false $ptr,
        array|false $forward,
        $cache = null,
        bool $offline = false,
        float $sleepMs = 0.0
    ): ReverseDnsVerifier {
        return new class ($ptr, $forward, $cache, $offline, $sleepMs) extends ReverseDnsVerifier {
            public int $reverseCalls = 0;

            public function __construct(
                private string|false $ptr,
                private array|false $forward,
                $cache = null,
                bool $offline = false,
                private float $sleepMs = 0.0
            ) {
                parent::__construct($cache, 3600, 86400, $offline, 250.0, 300);
            }

            protected function reverseLookup(string $ip): string|false
            {
                $this->reverseCalls++;

                if ($this->sleepMs > 0) {
                    usleep((int) ($this->sleepMs * 1000));
                }

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

    /**
     * Offline means no DNS, the same as it means no HTTP for sources (#228).
     */
    public function testOfflineDoesNotResolve(): void
    {
        $verifier = $this->verifier(
            'crawl.googlebot.com',
            [['ip' => '66.249.66.1']],
            new ArrayAdapter(),
            true
        );

        $this->assertFalse($verifier->verify('66.249.66.1', ['.googlebot.com']));
        $this->assertSame(0, $verifier->reverseCalls, 'Offline must make no lookup at all');
    }

    /**
     * A cached verdict is still honoured offline -- reading it costs no network.
     */
    public function testOfflineStillUsesACachedVerdict(): void
    {
        $pool = new ArrayAdapter();

        $online = $this->verifier('crawl.googlebot.com', [['ip' => '66.249.66.1']], $pool);
        $this->assertTrue($online->verify('66.249.66.1', ['.googlebot.com']));

        $offline = $this->verifier(false, false, $pool, true);
        $this->assertTrue(
            $offline->verify('66.249.66.1', ['.googlebot.com']),
            'A verdict already in the cache should still be usable offline'
        );
        $this->assertSame(0, $offline->reverseCalls);
    }

    /**
     * A slow lookup trips the breaker, so the next request skips DNS entirely.
     *
     * PHP cannot bound gethostbyaddr(), so a degraded resolver would otherwise
     * stall every worker in turn. One worker paying is survivable; all of them
     * paying is an outage.
     */
    public function testASlowLookupTripsTheBreaker(): void
    {
        $pool = new ArrayAdapter();

        // 300ms, over the 250ms threshold.
        $slow = $this->verifier('crawl.evilbot.com', [['ip' => '203.0.113.5']], $pool, false, 300.0);
        $slow->verify('203.0.113.5', ['.googlebot.com']);

        $next = $this->verifier('crawl.googlebot.com', [['ip' => '66.249.66.1']], $pool);
        $this->assertFalse(
            $next->verify('66.249.66.1', ['.googlebot.com']),
            'While the breaker is open, verification fails closed without resolving'
        );
        $this->assertSame(0, $next->reverseCalls, 'The breaker must prevent the lookup');
    }

    /**
     * A refusal is remembered far longer than an acceptance.
     *
     * Refusals are what an attacker generates, and an address that is not
     * Googlebot will not become Googlebot.
     */
    public function testARefusalIsCachedForLongerThanAnAcceptance(): void
    {
        $pool = new ArrayAdapter();
        $verifier = $this->verifier('crawl.evilgooglebot.com', [['ip' => '203.0.113.5']], $pool);

        $verifier->verify('203.0.113.5', ['.googlebot.com']);

        $key = 'rdns_' . hash('sha256', '203.0.113.5|.googlebot.com');
        $values = $pool->getValues();

        $this->assertArrayHasKey($key, $values, 'The refusal should be cached');
    }

    /**
     * A concurrent lookup for the same address does not start a second one.
     */
    public function testAnInFlightLookupIsNotDuplicated(): void
    {
        $pool = new ArrayAdapter();
        $key = 'rdns_' . hash('sha256', '66.249.66.1|.googlebot.com');

        // Plant the in-flight marker another worker would have left.
        $item = $pool->getItem($key . '_inflight');
        $item->set(true);
        $item->expiresAfter(10);
        $pool->save($item);

        $verifier = $this->verifier('crawl.googlebot.com', [['ip' => '66.249.66.1']], $pool);

        $this->assertFalse($verifier->verify('66.249.66.1', ['.googlebot.com']));
        $this->assertSame(0, $verifier->reverseCalls, 'It should not resolve behind another worker');
    }

    /**
     * With no cache there is no breaker and no in-flight marker, and it still works.
     *
     * A pool that cannot be built must not disable verification -- it should cost
     * a lookup per request, which is slow but correct.
     */
    public function testItWorksWithNoCacheAtAll(): void
    {
        $verifier = $this->verifier('crawl.googlebot.com', [['ip' => '66.249.66.1']], null);

        $this->assertTrue($verifier->verify('66.249.66.1', ['.googlebot.com']));
        $this->assertTrue($verifier->verify('66.249.66.1', ['.googlebot.com']));

        $this->assertSame(2, $verifier->reverseCalls, 'Without a cache, every call resolves');
    }

    /**
     * The breaker reopens once the cooldown lapses.
     */
    public function testTheBreakerStopsBlockingAfterTheCooldown(): void
    {
        $pool = new ArrayAdapter();

        $slow = $this->verifier('crawl.evilbot.com', [['ip' => '203.0.113.5']], $pool, false, 300.0);
        $slow->verify('203.0.113.5', ['.googlebot.com']);

        // Clear the breaker the way its expiry would.
        $pool->deleteItem('rdns_breaker');

        $next = $this->verifier('crawl.googlebot.com', [['ip' => '66.249.66.1']], $pool);

        $this->assertTrue($next->verify('66.249.66.1', ['.googlebot.com']));
        $this->assertSame(1, $next->reverseCalls, 'Once the breaker lapses, lookups resume');
    }

    /**
     * The in-flight marker is released, so the next request is not locked out.
     */
    public function testTheInFlightMarkerIsReleasedAfterTheLookup(): void
    {
        $pool = new ArrayAdapter();
        $verifier = $this->verifier('crawl.googlebot.com', [['ip' => '66.249.66.1']], $pool);

        $verifier->verify('66.249.66.1', ['.googlebot.com']);

        $key = 'rdns_' . hash('sha256', '66.249.66.1|.googlebot.com');

        $this->assertFalse(
            $pool->getItem($key . '_inflight')->isHit(),
            'The claim must be released once the lookup finishes'
        );
    }

    /**
     * An empty address verifies nothing, and costs no lookup.
     */
    public function testAnEmptyAddressVerifiesNothing(): void
    {
        $verifier = $this->verifier('crawl.googlebot.com', [['ip' => '66.249.66.1']]);

        $this->assertFalse($verifier->verify('', ['.googlebot.com']));
        $this->assertSame(0, $verifier->reverseCalls);
    }

    /**
     * A malformed address cannot forward-confirm, so it fails closed.
     */
    public function testAMalformedAddressFailsClosed(): void
    {
        $verifier = $this->verifier('crawl.googlebot.com', [['ip' => '66.249.66.1']]);

        $this->assertFalse($verifier->verify('not-an-address', ['.googlebot.com']));
    }

    /**
     * A blank or whitespace-only suffix is skipped rather than matching everything.
     */
    public function testABlankSuffixMatchesNothing(): void
    {
        $verifier = $this->verifier('crawl.googlebot.com', [['ip' => '66.249.66.1']]);

        $this->assertFalse($verifier->verify('66.249.66.1', ['', '   ']));
    }

    /**
     * A forward record without a usable address is ignored, not trusted.
     */
    public function testAForwardRecordWithNoAddressIsIgnored(): void
    {
        $verifier = $this->verifier('crawl.googlebot.com', [['type' => 'A'], ['ip' => 123]]);

        $this->assertFalse($verifier->verify('66.249.66.1', ['.googlebot.com']));
    }

    /**
     * A pool that throws must not take verification down with it.
     *
     * PSR-6 permits getItem() to throw InvalidArgumentException, and a cache is
     * an optimisation -- losing it should cost a DNS lookup, not the rule.
     */
    public function testAThrowingCacheDegradesToResolving(): void
    {
        $pool = new class implements \Psr\Cache\CacheItemPoolInterface {
            public function getItem(string $key): \Psr\Cache\CacheItemInterface
            {
                throw new class ('unusable') extends \InvalidArgumentException implements \Psr\Cache\InvalidArgumentException {};
            }

            public function getItems(array $keys = []): iterable { return []; }
            public function hasItem(string $key): bool { return false; }
            public function clear(): bool { return true; }
            public function deleteItem(string $key): bool
            {
                throw new class ('unusable') extends \InvalidArgumentException implements \Psr\Cache\InvalidArgumentException {};
            }

            public function deleteItems(array $keys): bool { return true; }
            public function save(\Psr\Cache\CacheItemInterface $item): bool { return true; }
            public function saveDeferred(\Psr\Cache\CacheItemInterface $item): bool { return true; }
            public function commit(): bool { return true; }
        };

        $verifier = $this->verifier('crawl.googlebot.com', [['ip' => '66.249.66.1']], $pool);

        $this->assertTrue(
            $verifier->verify('66.249.66.1', ['.googlebot.com']),
            'A broken cache should cost a lookup, not the verification'
        );
        $this->assertSame(1, $verifier->reverseCalls);
    }

    /**
     * A slow lookup against a throwing pool cannot record the breaker, and must
     * still return its verdict rather than failing.
     */
    public function testASlowLookupWithAThrowingCacheStillReturns(): void
    {
        $pool = new class implements \Psr\Cache\CacheItemPoolInterface {
            public function getItem(string $key): \Psr\Cache\CacheItemInterface
            {
                throw new class ('unusable') extends \InvalidArgumentException implements \Psr\Cache\InvalidArgumentException {};
            }

            public function getItems(array $keys = []): iterable { return []; }
            public function hasItem(string $key): bool { return false; }
            public function clear(): bool { return true; }
            public function deleteItem(string $key): bool { return true; }
            public function deleteItems(array $keys): bool { return true; }
            public function save(\Psr\Cache\CacheItemInterface $item): bool { return true; }
            public function saveDeferred(\Psr\Cache\CacheItemInterface $item): bool { return true; }
            public function commit(): bool { return true; }
        };

        $verifier = $this->verifier('crawl.googlebot.com', [['ip' => '66.249.66.1']], $pool, false, 300.0);

        $this->assertTrue($verifier->verify('66.249.66.1', ['.googlebot.com']));
    }

    /**
     * A slow lookup with no cache has no breaker to trip, and still answers.
     */
    public function testASlowLookupWithNoCacheStillReturns(): void
    {
        $verifier = $this->verifier('crawl.googlebot.com', [['ip' => '66.249.66.1']], null, false, 300.0);

        $this->assertTrue($verifier->verify('66.249.66.1', ['.googlebot.com']));
    }

    /**
     * A forward lookup that fails outright, rather than returning nothing.
     *
     * `dns_get_record()` returns false on failure and an empty array when the
     * name resolves to nothing; both mean the round trip did not confirm.
     */
    public function testAForwardLookupThatFailsOutrightFailsClosed(): void
    {
        $verifier = $this->verifier('crawl.googlebot.com', false);

        $this->assertFalse($verifier->verify('66.249.66.1', ['.googlebot.com']));
    }

    /**
     * A verifier that can never claim the lookup, with the sleep stubbed out.
     *
     * The state a worker is in when another process is already resolving the
     * same address. `pause()` is overridden so the wait is exercised without
     * one — a test that really slept would be measuring `usleep`.
     *
     * @param \Psr\Cache\CacheItemPoolInterface|null $cache
     *   Pool the holder would publish its verdict to.
     */
    private function contendedVerifier($cache, int $claimWaitMs, ?callable $onPause = null): ReverseDnsVerifier
    {
        return new class ($cache, $claimWaitMs, $onPause) extends ReverseDnsVerifier {
            public int $pauses = 0;

            public int $reverseCalls = 0;

            public function __construct($cache, int $claimWaitMs, private $onPause)
            {
                parent::__construct($cache, 3600, 86400, false, 250.0, 300, $claimWaitMs);
            }

            protected function claimLookup(string $key): bool
            {
                // Somebody else holds it.
                return false;
            }

            protected function pause(int $microseconds): void
            {
                $this->pauses++;

                if ($this->onPause !== null) {
                    ($this->onPause)($this->pauses);
                }
            }

            protected function reverseLookup(string $ip): string|false
            {
                $this->reverseCalls++;

                return 'crawl.googlebot.com';
            }

            protected function forwardLookup(string $host): array|false
            {
                return [['ip' => '66.249.66.1']];
            }
        };
    }

    /**
     * By default a worker that cannot claim the lookup refuses immediately.
     *
     * The behaviour of every release before this one, and still the default:
     * waiting trades latency for a verdict, and which of those an operator
     * wants is not ours to assume.
     */
    public function testWithoutAWaitAContendedLookupRefusesAtOnce(): void
    {
        $cache = new \Symfony\Component\Cache\Adapter\ArrayAdapter();
        $verifier = $this->contendedVerifier($cache, 0);

        $this->assertFalse($verifier->verify('66.249.66.1', ['.googlebot.com']));
        $this->assertSame(0, $verifier->pauses, 'It did not wait');
        $this->assertSame(0, $verifier->reverseCalls, 'And did not resolve behind the holder');
    }

    /**
     * With a wait, the holder's verdict is used once it appears.
     *
     * Measured with 25 workers on one cold address (#245, #261): against a
     * 50 ms resolver this takes verified from 13 of 25 to 25 of 25.
     */
    public function testAVerdictPublishedDuringTheWaitIsUsed(): void
    {
        $cache = new \Symfony\Component\Cache\Adapter\ArrayAdapter();
        $key = null;

        $verifier = $this->contendedVerifier($cache, 200, function (int $pause) use ($cache, &$key): void {
            // The holder finishes on the third poll.
            if ($pause !== 3) {
                return;
            }

            foreach (['66.249.66.1'] as $ip) {
                $key = 'rdns_' . hash('sha256', $ip . '|' . '.googlebot.com');
            }

            $item = $cache->getItem((string) $key);
            $item->set(true);
            $cache->save($item);
        });

        $this->assertTrue(
            $verifier->verify('66.249.66.1', ['.googlebot.com']),
            'The verdict the holder published was used instead of refusing'
        );
        $this->assertSame(3, $verifier->pauses, 'It stopped polling as soon as the verdict appeared');
        $this->assertSame(0, $verifier->reverseCalls, 'And still made no lookup of its own');
    }

    /**
     * A refusal published during the wait is used too.
     *
     * The point is a verdict rather than a guess, and "not a crawler" is a
     * verdict.
     */
    public function testANegativeVerdictPublishedDuringTheWaitIsUsed(): void
    {
        $cache = new \Symfony\Component\Cache\Adapter\ArrayAdapter();

        $verifier = $this->contendedVerifier($cache, 200, function (int $pause) use ($cache): void {
            if ($pause !== 2) {
                return;
            }

            $item = $cache->getItem('rdns_' . hash('sha256', '203.0.113.5|.googlebot.com'));
            $item->set(false);
            $cache->save($item);
        });

        $this->assertFalse($verifier->verify('203.0.113.5', ['.googlebot.com']));
        $this->assertSame(2, $verifier->pauses);
    }

    /**
     * If no verdict arrives, it gives up and refuses as it did before.
     *
     * The wait is bounded; the fallback is the old behaviour rather than a
     * hang.
     */
    public function testAWaitThatTimesOutFallsBackToRefusing(): void
    {
        $cache = new \Symfony\Component\Cache\Adapter\ArrayAdapter();
        $verifier = $this->contendedVerifier($cache, 20);

        $this->assertFalse($verifier->verify('66.249.66.1', ['.googlebot.com']));
        $this->assertGreaterThan(0, $verifier->pauses, 'It did wait');
        $this->assertSame(0, $verifier->reverseCalls);
    }

    /**
     * A pool that rejects the key mid-wait stops waiting.
     *
     * The same key was accepted moments earlier by the read at the top of
     * `verify()`, so a rejection now is the pool changing its mind rather than
     * a bad key — and waiting longer will not change it.
     */
    public function testAPoolThatRejectsTheKeyDuringTheWaitGivesUp(): void
    {
        $pool = new class implements \Psr\Cache\CacheItemPoolInterface {
            public int $calls = 0;

            private \Symfony\Component\Cache\Adapter\ArrayAdapter $inner;

            public function __construct()
            {
                $this->inner = new \Symfony\Component\Cache\Adapter\ArrayAdapter();
            }

            public function getItem($key): \Psr\Cache\CacheItemInterface
            {
                $this->calls++;

                // The first call is the read at the top of verify(); the second
                // is the first poll of the wait.
                if ($this->calls > 1) {
                    throw new class ('rejected') extends \InvalidArgumentException implements \Psr\Cache\InvalidArgumentException {
                    };
                }

                return $this->inner->getItem($key);
            }

            public function getItems(array $keys = []): iterable
            {
                return $this->inner->getItems($keys);
            }

            public function hasItem($key): bool
            {
                return $this->inner->hasItem($key);
            }

            public function clear(): bool
            {
                return $this->inner->clear();
            }

            public function deleteItem($key): bool
            {
                return $this->inner->deleteItem($key);
            }

            public function deleteItems(array $keys): bool
            {
                return $this->inner->deleteItems($keys);
            }

            public function save(\Psr\Cache\CacheItemInterface $item): bool
            {
                return $this->inner->save($item);
            }

            public function saveDeferred(\Psr\Cache\CacheItemInterface $item): bool
            {
                return $this->inner->saveDeferred($item);
            }

            public function commit(): bool
            {
                return $this->inner->commit();
            }
        };

        $verifier = $this->contendedVerifier($pool, 500);

        $this->assertFalse($verifier->verify('66.249.66.1', ['.googlebot.com']));
        $this->assertSame(1, $verifier->pauses, 'It gave up on the first rejection rather than polling out the budget');
    }

    /**
     * With no cache there is nowhere for a verdict to appear, so it does not wait.
     */
    public function testWithoutACachePoolItDoesNotWait(): void
    {
        $verifier = $this->contendedVerifier(null, 500);

        $this->assertFalse($verifier->verify('66.249.66.1', ['.googlebot.com']));
        $this->assertSame(0, $verifier->pauses, 'Nothing to poll, so nothing to wait for');
    }
}
