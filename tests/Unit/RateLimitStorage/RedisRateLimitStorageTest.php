<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\RateLimitStorage;

use Kanopi\Firewall\RateLimitStorage\RedisRateLimitStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Redis;

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
            ->with('ratelimit:test-key', $this->anything(), '1234567890');
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
}
