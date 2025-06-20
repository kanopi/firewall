<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Kanopi\Firewall\Storage\InMemoryStorage;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the InMemoryStorage class.
 */
final class InMemoryStorageTest extends TestCase
{
    /**
     * Tests that a value can be set and retrieved immediately.
     */
    public function testSetAndGetValue(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('key1', 'value1');

        $this->assertSame('value1', $storage->get('key1'));
    }

    /**
     * Tests that get() returns the default value if the key is missing.
     */
    public function testGetReturnsDefaultForMissingKey(): void
    {
        $storage = new InMemoryStorage();
        $this->assertSame('default', $storage->get('missing', 'default'));
    }

    /**
     * Tests that exists() returns true for existing keys and false otherwise.
     */
    public function testExists(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('existing', 123);

        $this->assertTrue($storage->exists('existing'));
        $this->assertFalse($storage->exists('nonexistent'));
    }

    /**
     * Tests that delete() removes a key and returns true, and false if key does not exist.
     */
    public function testDelete(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('to_delete', 'something');

        $this->assertTrue($storage->delete('to_delete'));
        $this->assertFalse($storage->exists('to_delete'));

        $this->assertFalse($storage->delete('already_gone'));
    }

    /**
     * Tests that reset() clears all stored keys.
     */
    public function testReset(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('key1', 'value1');
        $storage->set('key2', 'value2');

        $this->assertTrue($storage->reset());
        $this->assertFalse($storage->exists('key1'));
        $this->assertFalse($storage->exists('key2'));
    }

    /**
     * Tests that an expired key is automatically cleared and returns the default value.
     */
    public function testGetClearsExpiredValue(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('expiring', 'soon', 1);

        sleep(2); // Wait for expiration
        $this->assertSame('expired', $storage->get('expiring', 'expired'));
        $this->assertFalse($storage->exists('expiring'));
    }

    /**
     * Tests that clearExpire() removes only expired keys and keeps valid ones.
     */
    public function testClearExpire(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('live', 'data');
        $storage->set('stale', 'dead', 1);

        sleep(2); // Let 'stale' expire
        $storage->clearExpire();

        $this->assertTrue($storage->exists('live'));
        $this->assertFalse($storage->exists('stale'));
    }

    /**
     * Tests that addToExpire() extends the expiration of a key.
     */
    public function testAddToExpireExtendsExpiration(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('extendable', 'value', 2);

        $this->assertTrue($storage->addToExpire('extendable', 5));

        // Wait less than the original expiration time
        sleep(3);

        // Should still exist due to extended expiration
        $this->assertSame('value', $storage->get('extendable', 'not found'));
    }

    /**
     * Tests that addToExpire() fails if the key is missing or has no expiration.
     */
    public function testAddToExpireFailsForNonExpiringOrMissingKey(): void
    {
        $storage = new InMemoryStorage();

        // No such key
        $this->assertFalse($storage->addToExpire('missing', 5));

        // Key with no expiration
        $storage->set('permanent', 'value');
        $this->assertFalse($storage->addToExpire('permanent', 5));
    }

    /**
     * Tests that keys with expire=0 never expire.
     */
    public function testSetWithZeroExpireNeverExpires(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('forever', 'immortal', 0);

        sleep(2); // Key should still be available
        $this->assertTrue($storage->exists('forever'));
        $this->assertSame('immortal', $storage->get('forever', 'fallback'));
    }

    /**
     * Tests that get() deletes the key if it has expired.
     */
    public function testGetDeletesExpiredKey(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('temp', 'vanish', 1);

        sleep(2);
        $this->assertSame('fallback', $storage->get('temp', 'fallback'));
        $this->assertFalse($storage->exists('temp')); // Confirm deletion
    }

    /**
     * Tests that addToExpire() does not create an expiration if none was set originally.
     */
    public function testAddToExpireDoesNotCreateExpireIfNone(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('permanent', 'value', 0);

        $this->assertFalse($storage->addToExpire('permanent', 5));
        $this->assertSame('value', $storage->get('permanent'));
    }

    /**
     * Tests that get() returns the default value and deletes the key if expired.
     */
    public function testGetReturnsDefaultAndRemovesExpiredKey(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('session', 'old', 1);

        sleep(2);
        $this->assertSame('new', $storage->get('session', 'new'));
        $this->assertFalse($storage->exists('session'));
    }

}
