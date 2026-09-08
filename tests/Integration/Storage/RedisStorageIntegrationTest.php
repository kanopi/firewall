<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration\Storage;

use Kanopi\Firewall\Storage\RedisStorage;
use Kanopi\Firewall\Tests\Integration\IntegrationTestCase;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use Redis;

/**
 * Exercises the Redis block-list storage against a real Redis.
 *
 * The unit tests mock `Redis`, which proves the right commands are issued with the right
 * arguments and nothing more. It does not prove that a TTL actually expires a block, that
 * the offense sorted set really counts within a window, or that SCAN enumerates what KEYS
 * would — all properties of Redis rather than of our call sequence, and all of them things
 * this backend leans on rather than implements.
 *
 * CI runs a Redis service and installs `ext-redis`, so this costs nothing there. Locally it
 * skips.
 */
#[RequiresPhpExtension('redis')]
class RedisStorageIntegrationTest extends IntegrationTestCase
{
    /**
     * A prefix unique to this run, so a shared Redis stays usable.
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
     * A storage pointed at this run's namespace.
     */
    private function storage(): RedisStorage
    {
        $config = self::getRedisConfig();

        return new RedisStorage([
            'redis' => [
                'host' => (string) $config['host'],
                'port' => (int) $config['port'],
                'prefix' => $this->prefix,
            ],
        ]);
    }

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

    private function redisIsReachable(): bool
    {
        try {
            return $this->connect()->ping() !== false;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * A block written is a block read back, with its structure intact.
     */
    public function testABlockRoundTrips(): void
    {
        $storage = $this->storage();
        $record = ['reason' => 'crs', 'request' => ['path' => '/wp-admin']];

        $this->assertTrue($storage->set('203.0.113.5', $record, 60));
        $this->assertTrue($storage->exists('203.0.113.5'));
        $this->assertSame($record, $storage->get('203.0.113.5'));
        $this->assertSame($record, $storage->isBlocked('203.0.113.5'));
    }

    /**
     * A TTL actually removes the block, which is what lets expire() do nothing.
     */
    public function testATtlExpiresTheBlockWithoutASweep(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.6', ['reason' => 'brief'], 1);

        $this->assertTrue($storage->exists('203.0.113.6'));

        // Redis expiry is not instantaneous to the millisecond; one extra
        // second is the smallest wait that is not flaky.
        sleep(2);

        $this->assertFalse($storage->exists('203.0.113.6'), 'Redis should have expired the key itself');
        $this->assertFalse($storage->isBlocked('203.0.113.6'));
    }

    /**
     * A permanent block has no TTL and stays.
     */
    public function testAPermanentBlockHasNoExpiry(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.7', ['reason' => 'forever'], 0);

        $this->assertSame(-1, $this->connect()->ttl($this->prefix . 'block:203.0.113.7'));
    }

    /**
     * Extending a ban lengthens it rather than replacing it.
     */
    public function testExtendingABanLengthensIt(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.8', ['reason' => 'escalating'], 100);

        $this->assertTrue($storage->addToExpire('203.0.113.8', 200));

        $ttl = $this->connect()->ttl($this->prefix . 'block:203.0.113.8');
        $this->assertGreaterThan(250, $ttl, 'The remaining time should have grown, not been replaced');
    }

    /**
     * Offenses accumulate, and survive the block that earned them.
     *
     * This is the property blocking_escalation depends on: a client whose ban
     * lapsed must still be a repeat offender when it comes back.
     */
    public function testOffensesOutliveTheBlock(): void
    {
        $storage = $this->storage();

        $storage->set('203.0.113.9', ['reason' => 'first'], 1);
        $storage->recordOffense('203.0.113.9');

        $this->assertGreaterThanOrEqual(2, $storage->countOffenses('203.0.113.9'));

        sleep(2);

        $this->assertFalse($storage->exists('203.0.113.9'), 'Precondition: the ban has lapsed');
        $this->assertGreaterThanOrEqual(
            2,
            $storage->countOffenses('203.0.113.9'),
            'History must survive the ban, or escalation resets on every expiry'
        );
    }

    /**
     * Offenses are counted within a window, and listed newest first.
     */
    public function testOffensesAreCountedWithinAWindow(): void
    {
        $storage = $this->storage();
        $storage->recordOffense('203.0.113.10');

        $now = time();

        $this->assertSame(1, $storage->countOffenses('203.0.113.10', $now - 60, $now + 60));
        $this->assertSame(0, $storage->countOffenses('203.0.113.10', 0, $now - 3600));

        $moments = $storage->listOffenses('203.0.113.10');
        $this->assertCount(1, $moments);
        $this->assertEqualsWithDelta($now, $moments[0], 5);
    }

    /**
     * find() enumerates live blocks by address or CIDR, with their offense counts.
     */
    public function testFindEnumeratesLiveBlocks(): void
    {
        $storage = $this->storage();
        $storage->set('198.51.100.4', ['reason' => 'a'], 60);
        $storage->set('198.51.100.9', ['reason' => 'b'], 60);
        $storage->set('203.0.113.44', ['reason' => 'c'], 60);

        $matches = $storage->find('198.51.100.0/24');

        $this->assertArrayHasKey('198.51.100.4', $matches);
        $this->assertArrayHasKey('198.51.100.9', $matches);
        $this->assertArrayNotHasKey('203.0.113.44', $matches, 'A different range must not match');

        $this->assertGreaterThan(time(), $matches['198.51.100.4']['expire']);
        $this->assertNotNull($matches['198.51.100.4']['expires_at']);
        $this->assertGreaterThanOrEqual(1, $matches['198.51.100.4']['offenses']);
    }

    /**
     * deleteMatching() removes the block and the offenses together.
     *
     * The opposite of expiry: an operator lifting a ban should not have it
     * escalated straight back on the next offence.
     */
    public function testDeleteMatchingRemovesBlocksAndOffenses(): void
    {
        $storage = $this->storage();
        $storage->set('198.51.100.20', ['reason' => 'a'], 60);
        $storage->set('203.0.113.20', ['reason' => 'b'], 60);

        $this->assertSame(1, $storage->deleteMatching(['198.51.100.0/24']));

        $this->assertFalse($storage->exists('198.51.100.20'));
        $this->assertSame(0, $storage->countOffenses('198.51.100.20'), 'Lifting a ban clears its history');
        $this->assertTrue($storage->exists('203.0.113.20'), 'An unrelated block is untouched');
    }

    /**
     * reset() clears this backend's namespace and nothing else.
     */
    public function testResetClearsOnlyOurNamespace(): void
    {
        $storage = $this->storage();
        $storage->set('198.51.100.30', ['reason' => 'a'], 60);

        $neighbour = $this->connect();
        $neighbour->set('someone-elses-key', 'left alone');

        try {
            $this->assertTrue($storage->reset());
            $this->assertFalse($storage->exists('198.51.100.30'));
            $this->assertSame('left alone', $neighbour->get('someone-elses-key'));
        } finally {
            $neighbour->del('someone-elses-key');
        }
    }

    /**
     * Enumeration holds up past one SCAN page.
     *
     * SCAN_COUNT is 500, so this crosses it deliberately -- an implementation
     * that stopped after the first cursor would pass every other test here.
     */
    public function testFindEnumeratesBeyondOneScanPage(): void
    {
        $storage = $this->storage();

        for ($i = 0; $i < 600; $i++) {
            $storage->set('10.0.' . intdiv($i, 256) . '.' . ($i % 256), ['reason' => 'bulk'], 120);
        }

        $matches = $storage->find('10.0.0.0/8');

        $this->assertCount(600, $matches, 'Every page of the scan should be walked');
    }
}
