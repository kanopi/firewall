<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration\RateLimitStorage;

use Kanopi\Firewall\RateLimitStorage\RedisRateLimitStorage;
use Kanopi\Firewall\Tests\Integration\IntegrationTestCase;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use Redis;

/**
 * Exercises the Redis rate-limit storage against a real Redis.
 *
 * The unit tests for this class mock `Redis`, which proves the right methods
 * are called with the right arguments and nothing else. It does not prove a
 * count comes back, that a window actually excludes what falls outside it, or
 * that the sorted set is pruned — all of which are properties of Redis rather
 * than of our call sequence.
 *
 * CI already runs a Redis service and installs `ext-redis`, so this costs
 * nothing there. Locally it skips.
 */
#[RequiresPhpExtension('redis')]
class RedisRateLimitStorageIntegrationTest extends IntegrationTestCase
{
    /**
     * A key prefix unique to this run, so a shared Redis stays usable.
     */
    private string $prefix;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->skipIfGroupDisabled('redis');
        $this->prefix = 'fwtest:' . bin2hex(random_bytes(6)) . ':';

        if (!$this->redisIsReachable()) {
            $this->markTestSkipped('No Redis server reachable with the configured settings.');
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        // Leave the server as it was found; a shared Redis is not ours to fill.
        try {
            $redis = $this->connect();

            foreach ($redis->keys($this->prefix . '*') ?: [] as $key) {
                $redis->del($key);
            }
        } catch (\Throwable) {
            // Nothing to clean up if the connection is already gone.
        }

        parent::tearDown();
    }

    /**
     * Open a raw connection using the configured settings.
     */
    private function connect(): Redis
    {
        $config = self::getRedisConfig();
        $redis = new Redis();
        $redis->connect((string) $config['host'], (int) $config['port']);

        if (isset($config['auth'])) {
            $redis->auth($config['auth']);
        }

        return $redis;
    }

    /**
     * Whether a Redis server is actually there.
     */
    private function redisIsReachable(): bool
    {
        try {
            return $this->connect()->ping() !== false;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Build the storage under test.
     */
    private function storage(int $ttl = 3600): RedisRateLimitStorage
    {
        return new RedisRateLimitStorage([
            'redis' => self::getRedisConfig() + ['prefix' => $this->prefix],
            'prefix' => $this->prefix,
            'ttl' => $ttl,
        ]);
    }

    /**
     * A recorded request is counted back.
     */
    public function testRecordedRequestsAreCounted(): void
    {
        $storage = $this->storage();
        $now = time();

        $storage->recordRequest('counted', $now);
        $storage->recordRequest('counted', $now + 1);
        $storage->recordRequest('counted', $now + 2);

        $this->assertSame(3, $storage->countRequests('counted', $now - 10, $now + 10));
    }

    /**
     * Keys do not bleed into one another.
     */
    public function testKeysAreIsolated(): void
    {
        $storage = $this->storage();
        $now = time();

        $storage->recordRequest('one', $now);
        $storage->recordRequest('two', $now);
        $storage->recordRequest('two', $now + 1);

        $this->assertSame(1, $storage->countRequests('one', $now - 10, $now + 10));
        $this->assertSame(2, $storage->countRequests('two', $now - 10, $now + 10));
    }

    /**
     * The window is what a rate limit is actually made of.
     *
     * A mock cannot show this: excluding what falls outside the range is
     * Redis's sorted-set behaviour, not ours.
     */
    public function testOnlyRequestsInsideTheWindowAreCounted(): void
    {
        $storage = $this->storage();
        $now = time();

        $storage->recordRequest('windowed', $now - 600);
        $storage->recordRequest('windowed', $now - 30);
        $storage->recordRequest('windowed', $now);

        $this->assertSame(2, $storage->countRequests('windowed', $now - 60, $now + 10));
        $this->assertSame(3, $storage->countRequests('windowed', $now - 3600, $now + 10));
        $this->assertSame(0, $storage->countRequests('windowed', $now + 100, $now + 200));
    }

    /**
     * A key nobody has touched counts zero rather than erroring.
     */
    public function testUnknownKeyCountsZero(): void
    {
        $this->assertSame(0, $this->storage()->countRequests('never-seen', 0, PHP_INT_MAX));
    }

    /**
     * Recording sets an expiry, so a rate-limit key does not live forever.
     */
    public function testRecordingSetsAnExpiry(): void
    {
        $storage = $this->storage(120);
        $storage->recordRequest('expiring', time());

        $ttl = $this->connect()->ttl($this->prefix . 'expiring');

        $this->assertGreaterThan(0, $ttl, 'A rate-limit key must not outlive its window.');
        $this->assertLessThanOrEqual(120, $ttl);
    }

    /**
     * Requests arriving in the same second are counted separately.
     *
     * This is the test that matters most here. A sorted set holds each member
     * once, and this backend used the timestamp as both score and member — so a
     * burst within one second collapsed to a single entry and no limit finer
     * than one request per second per key could ever fire. Against exactly the
     * traffic rate limiting exists to stop.
     *
     * A mock cannot show it: the call sequence was always correct, and it is
     * Redis's set semantics that discarded the duplicates.
     */
    public function testRequestsSharingATimestampAreCountedSeparately(): void
    {
        $storage = $this->storage();
        $now = time();

        for ($i = 0; $i < 25; $i++) {
            $storage->recordRequest('same-second', $now);
        }

        $this->assertSame(
            25,
            $storage->countRequests('same-second', $now - 10, $now + 10),
            'A burst inside one second must count as 25 requests, not 1.'
        );
    }

    /**
     * A burst still respects the window it falls in.
     */
    public function testABurstIsStillBoundedByTheWindow(): void
    {
        $storage = $this->storage();
        $now = time();

        for ($i = 0; $i < 10; $i++) {
            $storage->recordRequest('bursty', $now - 600);
        }

        for ($i = 0; $i < 3; $i++) {
            $storage->recordRequest('bursty', $now);
        }

        $this->assertSame(3, $storage->countRequests('bursty', $now - 60, $now + 10));
        $this->assertSame(13, $storage->countRequests('bursty', $now - 3600, $now + 10));
    }
}
