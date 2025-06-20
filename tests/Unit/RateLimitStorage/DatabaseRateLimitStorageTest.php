<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\RateLimitStorage;

use Doctrine\DBAL\Connection;
use Kanopi\Firewall\RateLimitStorage\DatabaseRateLimitStorage;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use PDO;

/**
 * Full integration test for DatabaseRateLimitStorage using shared in-memory SQLite.
 */
class DatabaseRateLimitStorageTest extends TestCase
{
    /**
     * Create a new instance of DatabaseRateLimitStorage with a shared SQLite memory connection.
     */
    protected function getStorage(): DatabaseRateLimitStorage
    {
        return new DatabaseRateLimitStorage(['connection' => ['dsn' => 'sqlite3:///:memory:']]);
    }

    /**
     * Returns an instance without creating the schema/table.
     */
    protected function getBrokenStorage(): DatabaseRateLimitStorage
    {
        return new class extends DatabaseRateLimitStorage {
            public function __construct()
            {
                parent::__construct([
                    'connection' => [
                        'driver' => 'pdo_sqlite',
                        'memory' => true,
                    ],
                ]);

                // Change the storage table to trigger not found exceptions.
                $this->config['storage_table'] = 'firewall_rate_limit_storage_notfound';
            }

        };
    }

    /**
     * Tests that recordRequest silently handles insertion errors.
     */
    public function testRecordRequestCatchesException(): void
    {
        $storage = $this->getBrokenStorage();

        try {
            $storage->recordRequest('bad:key', time());
            $this->assertTrue(true, 'recordRequest should catch and suppress exception');
        } catch (\Throwable $e) {
            $this->fail('recordRequest should not throw exception: ' . $e->getMessage());
        }
    }

    /**
     * Tests that countRequests silently returns 0 on query errors.
     */
    public function testCountRequestsCatchesException(): void
    {
        $storage = $this->getBrokenStorage();
        $count = $storage->countRequests('bad:key', time() - 10, time());
        $this->assertSame(0, $count, 'Expected 0 when countRequests encounters an exception');
    }

    /**
     * Test that recording and counting requests works correctly.
     */
    public function testRecordsAndCountsRequests(): void
    {
        $storage = $this->getStorage();
        $key = 'ip:127.0.0.1';
        $now = time();

        $storage->recordRequest($key, $now - 10);
        $storage->recordRequest($key, $now - 5);
        $storage->recordRequest($key, $now);

        $count = $storage->countRequests($key, $now - 20, $now);
        $this->assertSame(3, $count);
    }

    /**
     * Test that requests outside the given time range are ignored.
     */
    public function testCountsOnlyInWindow(): void
    {
        $storage = $this->getStorage();
        $key = 'rate:/api/data';
        $now = time();

        $storage->recordRequest($key, $now - 100);
        $storage->recordRequest($key, $now - 50);
        $storage->recordRequest($key, $now - 10);

        $count = $storage->countRequests($key, $now - 30, $now);
        $this->assertSame(1, $count);
    }

    /**
     * Test that requests from different keys are isolated.
     */
    public function testDifferentKeysAreIsolated(): void
    {
        $storage = $this->getStorage();
        $now = time();

        $storage->recordRequest('user:1', $now);
        $storage->recordRequest('user:1', $now - 1);
        $storage->recordRequest('user:2', $now);

        $count1 = $storage->countRequests('user:1', $now - 10, $now + 1);
        $count2 = $storage->countRequests('user:2', $now - 10, $now + 1);

        $this->assertSame(2, $count1);
        $this->assertSame(1, $count2);
    }

    /**
     * Test that recordRequest handles exceptions without crashing.
     */
    public function testHandlesInsertFailureGracefully(): void
    {
        $storage = $this->getStorage();
        try {
            $storage->recordRequest('fail:key', time());
            $this->assertTrue(true, 'Should not throw exception even if insert fails');
        } catch (\Throwable $e) {
            $this->fail('Exception should not bubble during insert failure');
        }
    }
}
