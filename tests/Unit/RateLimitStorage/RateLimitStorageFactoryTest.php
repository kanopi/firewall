<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\RateLimitStorage;

use Kanopi\Firewall\RateLimitStorage\InMemoryRateLimitStorage;
use Kanopi\Firewall\RateLimitStorage\RateLimitStorageFactory;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Kanopi\Firewall\RateLimitStorage\RateLimitStorageFactory
 */
class RateLimitStorageFactoryTest extends TestCase {
    /**
     * It should default to InMemoryRateLimitStorage when no type is passed.
     */
    public function testCreatesDefaultStorage(): void {
        $storage = RateLimitStorageFactory::create();
        $this->assertInstanceOf(InMemoryRateLimitStorage::class, $storage);
    }

    /**
     * It should instantiate a valid class name that implements the interface.
     */
    public function testCreatesFromValidClassName(): void {
        $storage = RateLimitStorageFactory::create(InMemoryRateLimitStorage::class);
        $this->assertInstanceOf(InMemoryRateLimitStorage::class, $storage);
    }

    /**
     * It should return the object if it already implements the interface.
     */
    public function testReturnsInstanceDirectly(): void {
        $instance = new InMemoryRateLimitStorage();
        $storage = RateLimitStorageFactory::create($instance);
        $this->assertSame($instance, $storage);
    }

    /**
     * It should fallback to default when an invalid class name is given.
     */
    public function testFallsBackForInvalidClass(): void {
        $storage = RateLimitStorageFactory::create('NonExistentClass');
        $this->assertInstanceOf(InMemoryRateLimitStorage::class, $storage);
    }

    /**
     * It should fallback to default when class does not implement the interface.
     */
    public function testFallsBackForClassNotImplementingInterface(): void {
        $storage = RateLimitStorageFactory::create(\stdClass::class);
        $this->assertInstanceOf(InMemoryRateLimitStorage::class, $storage);
    }
}
