<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;

/**
 * Unit tests for the InMemoryStorage class.
 */
final class InMemoryStorageTest extends AbstractTestCase
{
    /**
     * Tests that a value can be set and retrieved immediately.
     */
    public function testSetAndGetValue(): void
    {
        $request = $this->getRequest();
        $storage = new InMemoryStorage();
        $storage->set($request);

        $this->assertIsArray($storage->get($request));
        $this->assertArrayHasKey('event_id', $storage->get($request));
        $this->assertSame('abc', $storage->get($request)['event_id']);
    }

    /**
     * Tests that get() returns the default value if the key is missing.
     */
    public function testGetReturnsDefaultForMissingKey(): void
    {
        $storage = new InMemoryStorage();
        $request = $this->getRequest();
        $this->assertSame('default', $storage->get($request, 'default'));
    }

    /**
     * Tests that exists() returns true for existing keys and false otherwise.
     */
    public function testExists(): void
    {
        $storage = new InMemoryStorage();

        $request1 = $this->getRequest('127.0.0.1');
        $request2 = $this->getRequest('127.0.0.2');
        $storage->set($request1);

        $this->assertTrue($storage->exists($request1));
        $this->assertFalse($storage->exists($request2));
    }

    /**
     * Tests that delete() removes a key and returns true, and false if key does not exist.
     */
    public function testDelete(): void
    {
        $storage = new InMemoryStorage();
        $request = $this->getRequest();
        $storage->set($request);

        $this->assertTrue($storage->delete($request));
        $this->assertFalse($storage->exists($request));

        $this->assertFalse($storage->delete($request));
    }

    /**
     * Tests that reset() clears all stored keys.
     */
    public function testReset(): void
    {
        $storage = new InMemoryStorage();
        $request1 = $this->getRequest();
        $request2 = $this->getRequest('127.0.0.2');
        $storage->set($request1);
        $storage->set($request2);

        $this->assertTrue($storage->reset());
        $this->assertFalse($storage->exists($request1));
        $this->assertFalse($storage->exists($request2));
    }

    /**
     * Tests that an expired key is automatically cleared and returns the default value.
     */
    public function testGetClearsExpiredValue(): void
    {
        $storage = new InMemoryStorage();
        $request = $this->getRequest();
        $storage->set($request, 1);

        sleep(2); // Wait for expiration
        $this->assertSame('expired', $storage->get($request, 'expired'));
        $this->assertFalse($storage->exists($request));
    }

    /**
     * Tests that clearExpire() removes only expired keys and keeps valid ones.
     */
    public function testClearExpire(): void
    {
        $storage = new InMemoryStorage();
        $request1 = $this->getRequest();
        $request2 = $this->getRequest('127.0.0.2');
        $storage->set($request1);
        $storage->set($request2, 1);

        sleep(2); // Let 'stale' expire
        $storage->clearExpire();

        $this->assertTrue($storage->exists($request1));
        $this->assertFalse($storage->exists($request2));
    }

    /**
     * Tests that addToExpire() extends the expiration of a key.
     */
    public function testAddToExpireExtendsExpiration(): void
    {
        $storage = new InMemoryStorage();
        $request1 = $this->getRequest();
        $storage->set($request1, 2);

        $this->assertTrue($storage->addToExpire($request1, 5));

        // Wait less than the original expiration time
        sleep(3);

        // Should still exist due to extended expiration
        $this->assertSame('abc', $storage->get($request1, 'not found')['event_id']);
    }

    /**
     * Tests that addToExpire() fails if the key is missing or has no expiration.
     */
    public function testAddToExpireFailsForNonExpiringOrMissingKey(): void
    {
        $storage = new InMemoryStorage();
        $request = $this->getRequest();

        // No such key
        $this->assertFalse($storage->addToExpire($request, 5));

        // Key with no expiration
        $storage->set($request);
        $this->assertFalse($storage->addToExpire($request, 5));
    }

    /**
     * Tests that keys with expire=0 never expire.
     */
    public function testSetWithZeroExpireNeverExpires(): void
    {
        $storage = new InMemoryStorage();
        $request1 = $this->getRequest();
        $storage->set($request1, 0);

        sleep(2); // Key should still be available
        $this->assertTrue($storage->exists($request1));
        $this->assertSame('abc', $storage->get($request1, 'fallback')['event_id']);
    }

    /**
     * Tests that get() deletes the key if it has expired.
     */
    public function testGetDeletesExpiredKey(): void
    {
        $storage = new InMemoryStorage();
        $request1 = $this->getRequest();
        $storage->set($request1, 1);

        sleep(2);
        $this->assertSame('fallback', $storage->get($request1, 'fallback'));
        $this->assertFalse($storage->exists($request1)); // Confirm deletion
    }

    /**
     * Tests that addToExpire() does not create an expiration if none was set originally.
     */
    public function testAddToExpireDoesNotCreateExpireIfNone(): void
    {
        $storage = new InMemoryStorage();
        $request = $this->getRequest();
        $storage->set($request, 0);

        $this->assertFalse($storage->addToExpire($request, 5));
        $this->assertSame('abc', $storage->get($request)['event_id']);
    }

    /**
     * Tests that get() returns the default value and deletes the key if expired.
     */
    public function testGetReturnsDefaultAndRemovesExpiredKey(): void
    {
        $storage = new InMemoryStorage();
        $request1 = $this->getRequest();
        $storage->set($request1, 1);

        sleep(2);
        $this->assertSame('new', $storage->get($request1, 'new'));
        $this->assertFalse($storage->exists($request1));
    }

    /**
     * Test formatUploadedFiles() handles flat, nested, and null structures.
     */
    public function testFormatUploadedFilesHandlesVariousStructures(): void
    {
        $mockFile1 = $this->createMock(UploadedFile::class);
        $mockFile1->method('getClientOriginalName')->willReturn('flat.jpg');
        $mockFile1->method('getClientMimeType')->willReturn('image/jpeg');
        $mockFile1->method('getSize')->willReturn(1111);
        $mockFile1->method('getError')->willReturn(0);

        $mockFile2 = $this->createMock(UploadedFile::class);
        $mockFile2->method('getClientOriginalName')->willReturn('nested.png');
        $mockFile2->method('getClientMimeType')->willReturn('image/png');
        $mockFile2->method('getSize')->willReturn(2222);
        $mockFile2->method('getError')->willReturn(0);

        $input = [
            'flat' => $mockFile1,
            'nested' => [
                'inner' => $mockFile2,
                'empty' => null,
            ],
            'nullFile' => null,
        ];

        $storage = new class () extends InMemoryStorage {
            public function formatUploadedFilesWrapper(array $files): array
            {
                return $this->formatUploadedFiles($files);
            }
        };

        $result = $storage->formatUploadedFilesWrapper($input);

        $this->assertEquals([
            'flat' => [
                'originalName' => 'flat.jpg',
                'mimeType' => 'image/jpeg',
                'size' => 1111,
                'error' => 0
            ],
            'nested' => [
                'inner' => [
                    'originalName' => 'nested.png',
                    'mimeType' => 'image/png',
                    'size' => 2222,
                    'error' => 0
                ],
                'empty' => null
            ],
            'nullFile' => null
        ], $result);
    }

    /**
     * Ensure uploaded files are normalized correctly into arrays.
     */
    public function testFormatUploadedFiles(): void {
        $file = $this->createMock(UploadedFile::class);
        $file->method('getClientOriginalName')->willReturn('test.jpg');
        $file->method('getClientMimeType')->willReturn('image/jpeg');
        $file->method('getSize')->willReturn(1234);
        $file->method('getError')->willReturn(0);

        $storage = new class () extends InMemoryStorage {
            public function formatUploadedFilesWrapper(array $files): array
            {
                return $this->formatUploadedFiles($files);
            }
        };

        $result = $storage->formatUploadedFilesWrapper(['file' => $file]);
        $this->assertEquals([
            'file' => [
                'originalName' => 'test.jpg',
                'mimeType' => 'image/jpeg',
                'size' => 1234,
                'error' => 0,
            ]
        ], $result);
    }

    /**
     * Ensure blockIp() stores all expected data and returns false.
     */
    public function testBlockIpReturnsFalse(): void {
        $request = Request::create('/', 'GET', [], ['foo' => 'bar'], [], ['REMOTE_ADDR' => '1.1.1.1']);
        $request->attributes->set('x-request-id', 'abc123');
        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('TestPlugin');
        $plugin->method('getExpirationTime')->willReturn(600);

        $storage = new class () extends InMemoryStorage {
            public function set(Request $request, int $expire = 0): bool
            {
                return false;
            }
        };

        $result = $storage->blockIp($request, $plugin);
        $this->assertFalse($result);
    }

    /**
     * Ensure blockIp() stores all expected data and returns true.
     */
    public function testBlockIpReturnsTrue(): void {
        $request = Request::create('/', 'GET', [], ['foo' => 'bar'], [], ['REMOTE_ADDR' => '1.1.1.1']);
        $request->attributes->set('x-request-id', 'abc123');
        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('TestPlugin');
        $plugin->method('getExpirationTime')->willReturn(600);

        $storage = new class () extends InMemoryStorage {
        };
        $result = $storage->blockIp($request, $plugin);
        $this->assertTrue($result);
    }

    /**
     * Confirm that is blocked returns true.
     */
    public function testIsBlocked(): void {
        $request = Request::create('/', 'GET', [], ['foo' => 'bar'], [], ['REMOTE_ADDR' => '1.1.1.1']);
        $request->attributes->set('x-request-id', 'abc123');
        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('TestPlugin');
        $plugin->method('getExpirationTime')->willReturn(600);

        $storage = new class () extends InMemoryStorage {
        };

        $result = $storage->isBlocked($request);
        $this->assertFalse($result);

        $storage->blockIp($request, $plugin);
        $result = $storage->isBlocked($request);
        $this->assertTrue($result);
    }

    /**
     * Confirm that is blocked returns true.
     */
    public function testDetermineExpirationTime(): void {
        $request = Request::create('/', 'GET', [], ['foo' => 'bar'], [], ['REMOTE_ADDR' => '1.1.1.1']);
        $request->attributes->set('x-request-id', 'abc123');
        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('TestPlugin');
        $plugin->method('getExpirationTime')->willReturn(600);

        $config = [
            'blocking_escalation' => [
                [
                    'window' => 600,
                    'offense' => 0,
                ],
                [
                    'window' => 3600,
                    'offense' => 1,
                    'duration' => 300,
                ]
            ],
        ];
        $storage = new class ($config) extends InMemoryStorage {
            public function determineExpirationTime(Request $request, int $initialTime): int
            {
                return parent::determineExpirationTime($request, $initialTime);
            }
        };

        $result = $storage->determineExpirationTime($request, 0);
        $this->assertEquals(0, $result);

        $result = $storage->determineExpirationTime($request, 100);
        $this->assertEquals(100, $result);
    }
}
