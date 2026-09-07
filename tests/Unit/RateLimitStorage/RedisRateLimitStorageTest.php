<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\RateLimitStorage;

use Kanopi\Firewall\RateLimitStorage\RedisRateLimitStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use Redis;
use RedisException;

/**
 * `ext-redis` is a composer `suggest`, not a `require` — only
 * RedisRateLimitStorage needs it, and every other rate-limit backend works
 * without it. These tests mock `Redis`/`RedisException`, which PHPUnit cannot
 * do when the extension is absent, so the whole case is skipped rather than
 * erroring out a suite that is otherwise green.
 */
#[RequiresPhpExtension('redis')]
class RedisRateLimitStorageTest extends AbstractTestCase
{
    /**
     * Tests the constructor initializes with injected Redis instance.
     */
    public function testConstructorWithInjectedRedis(): void
    {
        $mockRedis = $this->createMock(Redis::class);

        $storage = new RedisRateLimitStorage([
            'instance' => $mockRedis,
        ]);

        $this->assertInstanceOf(RedisRateLimitStorage::class, $storage);
    }

    /**
     * Test recordRequest writes data with expected Redis calls.
     */
    public function testRecordRequest(): void
    {
        $mockRedis = $this->createMock(Redis::class);
        $mockRedis->expects($this->once())
            ->method('zAdd')
            ->with('ratelimit:test-key', 1234567890, $this->stringStartsWith('1234567890:'));
        $mockRedis->expects($this->once())
            ->method('expire')
            ->with('ratelimit:test-key', 3600);

        $storage = new RedisRateLimitStorage([
            'instance' => $mockRedis,
            'redis' => [],
            'ttl' => 3600
        ]);

        $storage->recordRequest('test-key', 1234567890);
    }

    /**
     * Test Redis Exceptions.
     */
    public function testRecordRequestException(): void
    {
        $mockRedis = $this->createMock(Redis::class);
        $mockRedis->expects($this->any())
            ->method('zAdd')
            ->willThrowException(new RedisException());
        $mockRedis->expects($this->any())
            ->method('expire')
            ->willThrowException(new RedisException());
        $mockRedis->expects($this->any())
            ->method('zCount')
            ->willThrowException(new RedisException());

        $storage = new RedisRateLimitStorage([
            'instance' => $mockRedis,
            'redis' => [],
            'ttl' => 3600
        ]);

        $storage->recordRequest('test-key', 1234567890);
        $count = $storage->countRequests('test-key', 0, 1);
        $this->assertEquals(0, $count, 'Confirm no items recorded.');

        $storage = new RedisRateLimitStorage([
            'redis' => [],
            'ttl' => 3600
        ]);

        $storage->recordRequest('test-key', 1234567890);
        $count = $storage->countRequests('test-key', 0, 1);
        $this->assertEquals(0, $count, 'Confirm no items recorded.');
    }

    /**
     * `forget()` issues the exclusive-upper-bound ZREMRANGEBYSCORE (#183).
     *
     * The bound matters: `(` makes it exclusive, so a member scored exactly at
     * the cutoff survives -- `countRequests()` treats its start as inclusive,
     * and dropping that member would lose a request the current window still
     * counts. What Redis actually does with the range is asserted against a
     * real server in `tests/Integration/RateLimitStorage`.
     */
    public function testForgetRemovesTheScoreRangeBelowTheCutoff(): void
    {
        $mockRedis = $this->createMock(Redis::class);
        $mockRedis->expects($this->once())
            ->method('zRemRangeByScore')
            ->with('ratelimit:test-key', '-inf', '(1234567890')
            ->willReturn(4);

        $storage = new RedisRateLimitStorage(['instance' => $mockRedis, 'redis' => []]);

        $this->assertSame(4, $storage->forget('test-key', 1234567890));
    }

    /**
     * A Redis failure while pruning is reported and survived.
     */
    public function testForgetSurvivesARedisFailure(): void
    {
        $mockRedis = $this->createMock(Redis::class);
        $mockRedis->method('zRemRangeByScore')->willThrowException(new RedisException('gone'));

        $storage = new RedisRateLimitStorage(['instance' => $mockRedis, 'redis' => []]);

        $this->assertSame(0, $storage->forget('test-key', 1234567890));
    }

    /**
     * Test countRequests returns Redis zCount value.
     */
    public function testCountRequests(): void
    {
        $mockRedis = $this->createMock(Redis::class);
        $mockRedis->expects($this->once())
            ->method('zCount')
            ->with('ratelimit:test-key', 1000, 2000)
            ->willReturn(5);

        $storage = new RedisRateLimitStorage([
            'instance' => $mockRedis,
            'redis' => [],
        ]);

        $this->assertSame(5, $storage->countRequests('test-key', 1000, 2000));
    }

    /**
     * Tests RedisRateLimitStorage::__construct().
     *
     * Confirms turns port into integer if sent over as a string int.
     */
    public function testConstructorPortReturnsInt(): void
    {
        $config = [
            'redis' => [
                'port' => '5679'
            ],
            'ttl' => 3600
        ];
        $storage = new class ($config) extends RedisRateLimitStorage
        {
            public function getConfig(): array
            {
                return $this->config;
            }
        };

        $this->assertIsInt($storage->getConfig()['redis']['port']);
    }

    /**
     * A configured prefix is used, and not forwarded to ext-redis.
     *
     * `prefix` is this class's own option. Leaving it in the array handed to
     * `Redis::__construct()` made every construction emit "Skip unknown option
     * 'prefix'" — a warning nobody can act on, from a key the documentation
     * tells them to set. Found by the integration test against a real server;
     * a mock never sees the constructor at all.
     */
    public function testConfiguredPrefixIsUsedAndNotPassedToRedis(): void
    {
        $mockRedis = $this->createMock(Redis::class);
        $mockRedis->expects($this->once())
            ->method('zAdd')
            ->with('custom:test-key', 1234567890, $this->stringStartsWith('1234567890:'));

        $storage = new RedisRateLimitStorage([
            'instance' => $mockRedis,
            'redis' => ['prefix' => 'custom:', 'host' => '127.0.0.1'],
        ]);

        $storage->recordRequest('test-key', 1234567890);
    }

    /**
     * Without a configured prefix, the documented default applies.
     */
    public function testDefaultPrefixApplies(): void
    {
        $mockRedis = $this->createMock(Redis::class);
        $mockRedis->expects($this->once())
            ->method('zAdd')
            ->with('ratelimit:test-key', 1234567890, $this->stringStartsWith('1234567890:'));

        $storage = new RedisRateLimitStorage(['instance' => $mockRedis]);

        $storage->recordRequest('test-key', 1234567890);
    }
}
