<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\File\UploadedFile;

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
        $storage = new InMemoryStorage();

        $storage->set('example-key', ['value' => 1, 'event_id' => 'abc']);

        $this->assertIsArray($storage->get('example-key'));
        $this->assertArrayHasKey('event_id', $storage->get('example-key'));
        $this->assertSame('abc', $storage->get('example-key')['event_id']);
    }

    /**
     * Tests that get() returns the default value if the key is missing.
     */
    public function testGetReturnsDefaultForMissingKey(): void
    {
        $storage = new InMemoryStorage();
        $this->assertSame('default', $storage->get('example-key', 'default'));
    }

    /**
     * Tests that exists() returns true for existing keys and false otherwise.
     */
    public function testExists(): void
    {
        $storage = new InMemoryStorage();

        $storage->set('example-key', ['value' => 1, 'event_id' => 'abc']);

        $this->assertTrue($storage->exists('example-key'));
        $this->assertFalse($storage->exists('example-key2'));
    }

    /**
     * Tests that delete() removes a key and returns true, and false if key does not exist.
     */
    public function testDelete(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('example-key', ['value' => 1, 'event_id' => 'abc']);

        $this->assertTrue($storage->delete('example-key'));
        $this->assertFalse($storage->exists('example-key'));

        $this->assertFalse($storage->delete('example-key'));
    }

    /**
     * Tests that reset() clears all stored keys.
     */
    public function testReset(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('example-key', ['value' => 1, 'event_id' => 'abc']);
        $storage->set('example-key2', ['value' => 1, 'event_id' => 'abc']);

        $this->assertTrue($storage->reset());
        $this->assertFalse($storage->exists('example-key'));
        $this->assertFalse($storage->exists('example-key2'));
    }

    /**
     * Tests that an expired key is automatically cleared and returns the default value.
     */
    public function testGetClearsExpiredValue(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('example-key', ['value' => 1, 'event_id' => 'abc'], 1);

        sleep(2); // Wait for expiration
        $this->assertSame('expired', $storage->get('example-key', 'expired'));
        $this->assertFalse($storage->exists('example-key'));
    }

    /**
     * Tests that clearExpire() removes only expired keys and keeps valid ones.
     */
    public function testClearExpire(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('example-key', ['value' => 1, 'event_id' => 'abc']);
        $storage->set('example-key2', ['value' => 1, 'event_id' => 'abc'], 1);

        sleep(2); // Let 'stale' expire
        $storage->expire();

        $this->assertTrue($storage->exists('example-key'));
        $this->assertFalse($storage->exists('example-key2'));
    }

    /**
     * Tests that addToExpire() extends the expiration of a key.
     */
    public function testAddToExpireExtendsExpiration(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('example-key', ['value' => 1, 'event_id' => 'abc'], 2);

        $this->assertTrue($storage->addToExpire('example-key', 5));

        // Wait less than the original expiration time
        sleep(3);

        // Should still exist due to extended expiration
        $this->assertSame('abc', $storage->get('example-key', 'not found')['event_id']);
    }

    /**
     * Tests that addToExpire() fails if the key is missing or has no expiration.
     */
    public function testAddToExpireFailsForNonExpiringOrMissingKey(): void
    {
        $storage = new InMemoryStorage();

        // No such key
        $this->assertFalse($storage->addToExpire('example-key', 5));

        // Key with no expiration
        $storage->set('example-key', ['value' => 1]);
        $this->assertFalse($storage->addToExpire('example-key', 5));
    }

    /**
     * Tests that keys with expire=0 never expire.
     */
    public function testSetWithZeroExpireNeverExpires(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('example-key', ['value' => 1, 'event_id' => 'abc'], 0);


        sleep(2); // Key should still be available
        $this->assertTrue($storage->exists('example-key'));
        $this->assertSame('abc', $storage->get('example-key', 'fallback')['event_id']);
    }

    /**
     * Tests that get() deletes the key if it has expired.
     */
    public function testGetDeletesExpiredKey(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('example-key', ['value' => 1], 1);

        sleep(2);
        $this->assertSame('fallback', $storage->get('example-key', 'fallback'));
        $this->assertFalse($storage->exists('example-key')); // Confirm deletion
    }

    /**
     * Tests that addToExpire() does not create an expiration if none was set originally.
     */
    public function testAddToExpireDoesNotCreateExpireIfNone(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('example-key', ['value' => 1, 'event_id' => 'abc'], 0);

        $this->assertFalse($storage->addToExpire('example-key', 5));
        $this->assertSame('abc', $storage->get('example-key')['event_id']);
    }

    /**
     * Tests that get() returns the default value and deletes the key if expired.
     */
    public function testGetReturnsDefaultAndRemovesExpiredKey(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('example-key', ['value' => 1], 1);

        sleep(2);
        $this->assertSame('new', $storage->get('example-key', 'new'));
        $this->assertFalse($storage->exists('example-key'));
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
    public function testFormatUploadedFiles(): void
    {
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
     * Test isBlocked to ensure an array returns if value is only a string.
     */
    public function testIsBlockedConditional(): void
    {
        $storage = new class () extends InMemoryStorage {
            protected array $store = ['127.0.0.1' => ['value' => 'abc', 'expire' => 0], '127.0.0.2' => ['value' => ['test' => 1], 'expire' => 0]];
        };

        $this->assertEquals(['value' => 'abc'], $storage->isBlocked('127.0.0.1'));
        $this->assertIsArray($storage->isBlocked('127.0.0.2'));
        $this->assertEquals(['test' => 1], $storage->isBlocked('127.0.0.2'));
    }

    /**
     * Test Value updates if key already exists.
     */
    public function testSetOnExistingItem(): void
    {
        $storage = new class () extends InMemoryStorage {
            protected array $store = ['127.0.0.1' => ['value' => 'abc', 'expire' => 0], '127.0.0.2' => ['value' => ['test' => 1], 'expire' => 0]];
        };

        $this->assertEquals('abc', $storage->get('127.0.0.1'));
        $storage->set('127.0.0.1', ['test' => 1]);
        $this->assertEquals(['test' => 1], $storage->get('127.0.0.1'));
    }

    /**
     * A record that is not an array is skipped rather than trusted.
     *
     * `set()` only accepts arrays, so this shape cannot arise through the
     * public API — but the store is `mixed` and a subclass or a corrupted
     * import can put anything in it. The guard exists so `find()` cannot be
     * made to read `$record['expire']` off a string.
     */
    public function testFindSkipsRecordsThatAreNotArrays(): void
    {
        $storage = new class () extends InMemoryStorage {
            protected array $store = [
                '127.0.0.1' => 'not-a-record',
                '127.0.0.2' => ['value' => ['ok' => true], 'expire' => 0],
            ];
        };

        $matches = $storage->find('127.0.0.0/24');

        $this->assertArrayNotHasKey('127.0.0.1', $matches, 'A non-array record must not be returned.');
        $this->assertArrayHasKey('127.0.0.2', $matches, 'Valid records alongside it must still match.');
    }

    /**
     * An empty stored key cannot be matched by any pattern.
     *
     * `getKey()` returns a client IP so this should not happen, but a custom
     * storage backend or a bad import can leave an empty key behind, and
     * matching it against a CIDR range would be meaningless.
     */
    public function testFindIgnoresAnEmptyStoredKey(): void
    {
        $storage = new class () extends InMemoryStorage {
            protected array $store = [
                '' => ['value' => ['orphan' => true], 'expire' => 0],
                '10.0.0.7' => ['value' => ['ok' => true], 'expire' => 0],
            ];
        };

        $matches = $storage->find('10.0.0.0/8');

        $this->assertArrayNotHasKey('', $matches);
        $this->assertArrayHasKey('10.0.0.7', $matches);
    }

    /**
     * A CIDR pattern whose network part is not an address is not a pattern.
     *
     * `10.0.0.0/8` is valid; `nonsense/8` has the right shape but cannot be
     * compared to anything, so it is refused before any record is examined
     * rather than silently matching nothing.
     */
    public function testFindRejectsCidrWithANonAddressSubnet(): void
    {
        $storage = new class () extends InMemoryStorage {
            protected array $store = ['10.0.0.7' => ['value' => ['ok' => true], 'expire' => 0]];
        };

        $this->assertSame([], $storage->find('nonsense/8'));
    }
}
