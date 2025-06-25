<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\RateLimitStorage;

use Kanopi\Firewall\RateLimitStorage\CacheRateLimitStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Psr\Cache\CacheItemInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

class CacheRateLimitStorageTest extends AbstractTestCase
{
    /**
     * Tests constructor with valid CacheInterface object.
     */
    public function testConstructorWithValidCache(): void
    {
        $cache = new ArrayAdapter();
        $storage = new CacheRateLimitStorage([
            'adaptor' => $cache,
            'ttl' => 120
        ]);

        $this->assertInstanceOf(CacheRateLimitStorage::class, $storage);
    }

    /**
     * Tests constructor with null adaptor (should not fail).
     */
    public function testConstructorWithNullAdaptor(): void
    {
        $storage = new CacheRateLimitStorage([
            'adaptor' => null,
        ]);

        $this->assertInstanceOf(CacheRateLimitStorage::class, $storage);
        $storage->recordRequest('any', time());
        // Should not crash, but internal cache is null
        $this->assertSame(0, $storage->countRequests('any', 0, time()));
    }

    /**
     * Testing save error on Cache Rate Limit Storage test.
     */
    public function testSaveWithError(): void
    {
        $adaptor = new class() extends ArrayAdapter {
            public function save(CacheItemInterface $item): bool {
                return false;
            }
        };
        $storage = new CacheRateLimitStorage([
            'adaptor' => $adaptor,
        ]);

        $storage->recordRequest('any', time());
        $this->assertSame(0, $storage->countRequests('any', 0, time()));
    }

    /**
     * Tests recording and counting requests using ArrayAdapter.
     */
    public function testRecordAndCountRequests(): void
    {
        $cache = new ArrayAdapter();
        $storage = new CacheRateLimitStorage([
            'adaptor' => $cache,
            'ttl' => 300
        ]);

        $key = 'user:1';
        $now = time();

        $storage->recordRequest($key, $now - 15);
        $storage->recordRequest($key, $now - 5);
        $storage->recordRequest($key, $now - 2);
        $storage->recordRequest($key, $now + 2);

        $count = $storage->countRequests($key, $now - 10, $now + 5);
        $this->assertSame(3, $count, 'Should count 3 requests in range');

        $countNarrow = $storage->countRequests($key, $now + 1, $now + 5);
        $this->assertSame(1, $countNarrow, 'Should count 1 request in narrow range');
    }

    /**
     * Tests fallback behavior when internal cache is not set.
     */
    public function testRecordAndCountWithoutCache(): void
    {
        $storage = new CacheRateLimitStorage([
            'adaptor' => ArrayAdapter::class,
        ]);
        $storage->recordRequest('key', time());

        $this->assertSame(1, $storage->countRequests('key', 0, time()));
    }

    /**
     * Tests constructor using class-string CacheInterface.
     */
    public function testConstructorWithCacheClassName(): void
    {
        $storage = new CacheRateLimitStorage([
            'adaptor' => ArrayAdapter::class,
            'args' => [],
        ]);

        $this->assertInstanceOf(CacheRateLimitStorage::class, $storage);
    }

    /**
     * Tests constructor with invalid class name fails gracefully.
     */
    public function testConstructorWithInvalidClassName(): void
    {
        $storage = new CacheRateLimitStorage([
            'adaptor' => 'NonExistent\\Cache\\Class',
        ]);

        // Should not throw
        $this->assertSame(0, $storage->countRequests('x', 0, time()));
    }
}
