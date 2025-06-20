<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\RateLimitStorage;

use Kanopi\Firewall\RateLimitStorage\InMemoryRateLimitStorage;
use PHPUnit\Framework\TestCase;

class InMemoryRateLimitStorageTest extends TestCase
{
    /**
     * Test recording a single request and retrieving it within the same range.
     */
    public function testRecordAndCountSingleRequest(): void
    {
        $storage = new InMemoryRateLimitStorage();
        $timestamp = time();
        $storage->recordRequest('user:123', $timestamp);

        $this->assertSame(1, $storage->countRequests('user:123', $timestamp - 10, $timestamp + 10));
    }

    /**
     * Test that countRequests returns 0 for unknown keys.
     */
    public function testCountReturnsZeroForMissingKey(): void
    {
        $storage = new InMemoryRateLimitStorage();
        $this->assertSame(0, $storage->countRequests('missing:key', 0, time()));
    }

    /**
     * Test that countRequests respects the time range correctly.
     */
    public function testCountFiltersByTimeRange(): void
    {
        $storage = new InMemoryRateLimitStorage();
        $now = time();

        $storage->recordRequest('ip:1.2.3.4', $now - 30); // Outside window
        $storage->recordRequest('ip:1.2.3.4', $now - 10); // Inside
        $storage->recordRequest('ip:1.2.3.4', $now);      // Inside
        $storage->recordRequest('ip:1.2.3.4', $now + 10); // Future, outside

        $count = $storage->countRequests('ip:1.2.3.4', $now - 20, $now);

        $this->assertSame(2, $count, 'Should count only timestamps in the given range');
    }

    /**
     * Test that multiple keys are isolated from each other.
     */
    public function testSeparateKeys(): void
    {
        $storage = new InMemoryRateLimitStorage();
        $now = time();

        $storage->recordRequest('user:abc', $now);
        $storage->recordRequest('user:def', $now);

        $this->assertSame(1, $storage->countRequests('user:abc', $now - 1, $now + 1));
        $this->assertSame(1, $storage->countRequests('user:def', $now - 1, $now + 1));
    }

    /**
     * Test that an empty request list doesn't trigger warnings.
     */
    public function testEmptyKeyHandlingIsSafe(): void
    {
        $storage = new InMemoryRateLimitStorage();
        $this->assertSame(0, $storage->countRequests('empty:key', 0, 9999999999));
    }
}
