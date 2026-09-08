<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Kanopi\Firewall\Storage\RedisStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use Redis;

/**
 * `ext-redis` is a composer `suggest`, not a `require` — only the two Redis backends need
 * it, and every other storage works without it. These tests mock `Redis`, which PHPUnit
 * cannot do when the extension is absent, so the whole case is skipped rather than erroring
 * out a suite that is otherwise green.
 *
 * What a mock can prove is that the right commands are issued with the right arguments.
 * That the sorted set really counts, that a TTL really expires, and that SCAN really
 * enumerates are properties of Redis rather than of this class, and belong to the
 * integration test.
 */
#[RequiresPhpExtension('redis')]
class RedisStorageTest extends AbstractTestCase
{
    /**
     * A storage with a mocked connection, past the constructor's `echo` probe.
     */
    private function storage(Redis $redis, array $config = []): RedisStorage
    {
        return new RedisStorage(array_merge(['instance' => $redis], $config));
    }

    /**
     * A mock that satisfies the constructor and nothing more.
     */
    private function connectedRedis(): Redis
    {
        $redis = $this->createMock(Redis::class);
        $redis->method('echo')->willReturn('Connected');

        return $redis;
    }

    public function testAnInjectedConnectionIsUsed(): void
    {
        $storage = $this->storage($this->connectedRedis());

        $this->assertInstanceOf(RedisStorage::class, $storage);
    }

    /**
     * A block with a lifetime is written with a Redis TTL, not a stored timestamp.
     */
    public function testABlockWithALifetimeIsWrittenWithATtl(): void
    {
        $redis = $this->connectedRedis();
        $redis->expects($this->once())
            ->method('setex')
            ->with('firewall:block:203.0.113.5', 300, $this->stringContains('"reason"'))
            ->willReturn(true);

        $this->assertTrue($this->storage($redis)->set('203.0.113.5', ['reason' => 'test'], 300));
    }

    /**
     * A permanent block is written with no TTL at all.
     */
    public function testAPermanentBlockIsWrittenWithoutATtl(): void
    {
        $redis = $this->connectedRedis();
        $redis->expects($this->once())->method('set')->willReturn(true);
        $redis->expects($this->never())->method('setex');

        $this->assertTrue($this->storage($redis)->set('203.0.113.5', ['reason' => 'forever'], 0));
    }

    /**
     * Values round-trip as given -- `set()` is the interface's general key/value
     * write, not only the block-record writer.
     */
    public function testAValueRoundTripsAsGiven(): void
    {
        $redis = $this->connectedRedis();
        $redis->method('get')->willReturn(json_encode(['consumed_at' => 1234567890]));

        $this->assertSame(
            ['consumed_at' => 1234567890],
            $this->storage($redis)->get('some-token')
        );
    }

    /**
     * An absent key answers with the default.
     */
    public function testAnAbsentKeyReturnsTheDefault(): void
    {
        $redis = $this->connectedRedis();
        $redis->method('get')->willReturn(false);

        $this->assertSame('fallback', $this->storage($redis)->get('nobody', 'fallback'));
    }

    /**
     * A value that cannot be decoded is reported, not silently answered.
     *
     * For a block list, quietly returning the default reads as "this client is
     * not blocked" -- the fail-open shape #225 fixed for file storage.
     */
    public function testAnUndecodableValueIsReported(): void
    {
        $redis = $this->connectedRedis();
        $redis->method('get')->willReturn('{"broken');

        $this->assertNull($this->storage($redis)->get('203.0.113.5'));

        $handler = \Kanopi\Firewall\Logging\LoggingFactory::logger()->getHandlers()[0] ?? null;

        if ($handler !== null) {
            $this->assertTrue($handler->hasErrorContaining('could not be decoded'));
        }
    }

    /**
     * Expiry is the server's job, so the sweep has nothing to do.
     */
    public function testExpireIsANoOp(): void
    {
        $redis = $this->connectedRedis();
        $redis->expects($this->never())->method('del');

        $this->assertTrue($this->storage($redis)->expire());
    }

    /**
     * Extending a ban adds to whatever is left, rather than replacing it.
     */
    public function testExtendingABanAddsToTheRemainingTtl(): void
    {
        $redis = $this->connectedRedis();
        $redis->method('ttl')->willReturn(100);
        $redis->expects($this->once())
            ->method('expire')
            ->with('firewall:block:203.0.113.5', 400)
            ->willReturn(true);

        $this->assertTrue($this->storage($redis)->addToExpire('203.0.113.5', 300));
    }

    /**
     * A key with no expiry is already permanent, and a missing one has nothing
     * to extend. ext-redis reports those as -1 and -2.
     */
    public function testExtendingAPermanentOrMissingBanDoesNothing(): void
    {
        foreach ([-1, -2] as $ttl) {
            $redis = $this->connectedRedis();
            $redis->method('ttl')->willReturn($ttl);
            $redis->expects($this->never())->method('expire');

            $this->assertFalse($this->storage($redis)->addToExpire('203.0.113.5', 300));
        }
    }

    /**
     * Two offenses in the same second are both counted.
     *
     * A sorted set deduplicates by member, so the member has to be unique even
     * when the score is not.
     */
    public function testTwoOffensesInOneSecondUseDistinctMembers(): void
    {
        $members = [];
        $redis = $this->connectedRedis();
        $redis->method('zAdd')->willReturnCallback(
            function (string $key, float|int $score, string $member) use (&$members): int {
                $members[] = $member;

                return 1;
            }
        );

        $storage = $this->storage($redis);
        $storage->recordOffense('203.0.113.5');
        $storage->recordOffense('203.0.113.5');

        $this->assertCount(2, $members);
        $this->assertNotSame($members[0], $members[1], 'A repeated offense must not overwrite the first');
    }

    /**
     * Offenses are kept under their own key, so they outlive the block.
     */
    public function testOffensesUseTheirOwnKeyspace(): void
    {
        $redis = $this->connectedRedis();
        $redis->expects($this->once())
            ->method('zCount')
            ->with('firewall:offense:203.0.113.5', '0', (string) PHP_INT_MAX)
            ->willReturn(3);

        $this->assertSame(3, $this->storage($redis)->countOffenses('203.0.113.5'));
    }

    /**
     * Offense moments come back newest first, and capped.
     */
    public function testListedOffensesAreNewestFirstAndLimited(): void
    {
        $redis = $this->connectedRedis();
        $redis->method('zRangeByScore')->willReturn(['a' => 100, 'b' => 300, 'c' => 200]);

        $this->assertSame([300, 200], $this->storage($redis)->listOffenses('203.0.113.5', 0, PHP_INT_MAX, 2));
    }

    /**
     * A configured prefix namespaces every key this backend owns.
     */
    public function testTheConfiguredPrefixIsUsed(): void
    {
        $redis = $this->connectedRedis();
        $redis->expects($this->once())
            ->method('exists')
            ->with('site-a:block:203.0.113.5')
            ->willReturn(1);

        $storage = $this->storage($redis, ['redis' => ['prefix' => 'site-a:']]);

        $this->assertTrue($storage->exists('203.0.113.5'));
    }

    /**
     * A connection that cannot be established degrades rather than fatalling.
     *
     * A block list that is unreachable must not take the site down with it.
     */
    public function testAnUnusableConnectionDegradesQuietly(): void
    {
        $redis = $this->createMock(Redis::class);
        $redis->method('echo')->willThrowException(new \RuntimeException('connection refused'));

        $storage = $this->storage($redis);

        $this->assertFalse($storage->set('203.0.113.5', ['x' => 1], 60));
        $this->assertNull($storage->get('203.0.113.5'));
        $this->assertFalse($storage->exists('203.0.113.5'));
        $this->assertFalse($storage->delete('203.0.113.5'));
        $this->assertFalse($storage->addToExpire('203.0.113.5', 60));
        $this->assertFalse($storage->reset());
        $this->assertFalse($storage->recordOffense('203.0.113.5'));
        $this->assertSame(0, $storage->countOffenses('203.0.113.5'));
        $this->assertSame([], $storage->listOffenses('203.0.113.5'));
        $this->assertSame([], $storage->find('203.0.113.5'));
        $this->assertSame(0, $storage->deleteMatching(['203.0.113.5']));

        // expire() is the one that still succeeds: there is genuinely nothing
        // for it to do, connection or not.
        $this->assertTrue($storage->expire());
    }

    /**
     * A search for something that is not an address or CIDR is refused.
     */
    public function testAnInvalidFindPatternIsRefused(): void
    {
        $redis = $this->connectedRedis();
        $redis->expects($this->never())->method('scan');

        $this->assertSame([], $this->storage($redis)->find('not-an-address'));
    }

    /**
     * Deleting with no usable pattern touches nothing.
     */
    public function testDeleteMatchingWithNoValidPatternsTouchesNothing(): void
    {
        $redis = $this->connectedRedis();
        $redis->expects($this->never())->method('scan');

        $this->assertSame(0, $this->storage($redis)->deleteMatching(['not-an-address']));
    }

    /**
     * A connection that answers the probe and then fails every command.
     *
     * Distinct from an unusable connection: here the backend believes it is
     * connected, and every operation has to survive the server going away
     * underneath it rather than never having been there.
     */
    private function failingRedis(): Redis
    {
        $redis = $this->createMock(Redis::class);
        $redis->method('echo')->willReturn('Connected');

        $boom = new \RuntimeException('READONLY You can\'t write against a read only replica.');

        foreach ([
            'set', 'setex', 'get', 'del', 'exists', 'ttl', 'expire',
            'zAdd', 'zCount', 'zRangeByScore', 'scan',
        ] as $method) {
            $redis->method($method)->willThrowException($boom);
        }

        return $redis;
    }

    /**
     * Every operation degrades when the server fails mid-command.
     *
     * A block list that has become unreachable must not take the site down --
     * the firewall carries on enforcing every rule that does not depend on it.
     */
    public function testEveryOperationSurvivesAFailingServer(): void
    {
        $storage = $this->storage($this->failingRedis());

        $this->assertFalse($storage->set('203.0.113.5', ['x' => 1], 60));
        $this->assertNull($storage->get('203.0.113.5'));
        $this->assertFalse($storage->exists('203.0.113.5'));
        $this->assertFalse($storage->delete('203.0.113.5'));
        $this->assertFalse($storage->addToExpire('203.0.113.5', 60));
        $this->assertFalse($storage->reset());
        $this->assertFalse($storage->recordOffense('203.0.113.5'));
        $this->assertSame(0, $storage->countOffenses('203.0.113.5'));
        $this->assertSame([], $storage->listOffenses('203.0.113.5'));
        $this->assertSame([], $storage->find('203.0.113.5'));
        $this->assertSame(0, $storage->deleteMatching(['203.0.113.5']));
    }

    /**
     * A permanent block that cannot be written is still reported as a failure.
     */
    public function testAFailedPermanentWriteIsReported(): void
    {
        $this->assertFalse($this->storage($this->failingRedis())->set('203.0.113.5', ['x' => 1], 0));
    }

    /**
     * A block that vanishes between the scan and the read is skipped.
     *
     * SCAN is not a snapshot, and a TTL can lapse in the moment between
     * enumerating a key and reading it.
     */
    public function testFindSkipsAKeyThatVanishesMidScan(): void
    {
        $redis = $this->connectedRedis();
        $redis->method('scan')->willReturnCallback(
            function (&$iterator) {
                if ($iterator === null) {
                    $iterator = 0;

                    return ['firewall:block:198.51.100.7'];
                }

                return false;
            }
        );
        // Gone by the time it is read.
        $redis->method('get')->willReturn(false);

        $this->assertSame([], $this->storage($redis)->find('198.51.100.0/24'));
    }

    /**
     * An empty SCAN page is stepped over rather than ending the walk.
     *
     * Redis can return no keys for a cursor and still have more to give; a
     * loop that stopped there would silently enumerate a fraction of the
     * keyspace.
     */
    public function testAnEmptyScanPageDoesNotEndTheWalk(): void
    {
        $pages = [false, ['firewall:block:198.51.100.8']];
        $redis = $this->connectedRedis();
        $redis->method('scan')->willReturnCallback(
            function (&$iterator) use (&$pages) {
                $page = array_shift($pages);

                if ($pages === []) {
                    $iterator = 0;
                }

                return $page;
            }
        );
        $redis->method('get')->willReturn(json_encode(['reason' => 'found after an empty page']));
        $redis->method('ttl')->willReturn(60);
        $redis->method('zCount')->willReturn(1);

        $matches = $this->storage($redis)->find('198.51.100.0/24');

        $this->assertArrayHasKey('198.51.100.8', $matches, 'The walk must continue past an empty page');
    }

    /**
     * A value that cannot be encoded aborts the write rather than storing junk.
     */
    public function testAnUnencodableValueIsRefused(): void
    {
        $redis = $this->connectedRedis();
        $redis->expects($this->never())->method('setex');
        $redis->expects($this->never())->method('set');

        // NAN has no JSON representation.
        $this->assertFalse($this->storage($redis)->set('203.0.113.5', ['bad' => NAN], 60));
    }

    /**
     * A malformed reply to the offense query is treated as no offenses.
     */
    public function testANonArrayOffenseReplyIsTreatedAsEmpty(): void
    {
        $redis = $this->connectedRedis();
        $redis->method('zRangeByScore')->willReturn(false);

        $this->assertSame([], $this->storage($redis)->listOffenses('203.0.113.5'));
    }
}
