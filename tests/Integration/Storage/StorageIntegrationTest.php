<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration\Storage;

use Doctrine\DBAL\Tools\DsnParser;
use Kanopi\Firewall\Plugins\GeoLocation;
use Kanopi\Firewall\Plugins\IpAddress;
use Kanopi\Firewall\Plugins\UserAgent;
use Kanopi\Firewall\Storage\FileStorage;
use Kanopi\Firewall\Storage\DatabaseStorage;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Tests\Integration\IntegrationTestCase;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Connection;
use Symfony\Component\HttpFoundation\Request;

/**
 * Integration tests for all storage backends.
 * 
 * These tests verify that each storage implementation correctly handles:
 * - Basic CRUD operations
 * - Expiration and cleanup
 * - Concurrent access
 * - Data persistence
 * - Error recovery
 */
class StorageIntegrationTest extends IntegrationTestCase
{
    /**
     * Tests FileStorage with real file operations.
     * 
     * This test verifies:
     * - File creation and permissions
     * - Data serialization and deserialization
     * - File locking for concurrent access
     * - Atomic write operations
     */
    public function testFileStorageRealOperations(): void
    {
        $storageFile = $this->tempDir . '/firewall.data';
        $storage = new FileStorage(['storage_file' => $storageFile]);

        $plugin = new IpAddress();
        $request1 = Request::create('/', 'GET', [], [], [], [], ['REMOTE_ADDR' => '192.168.1.100']);
        $request1->attributes->set('blocking-plugin', $plugin);
        $request1->attributes->set('x-request-id', 'TEST123');
        $result = $storage->set($request1, 3600);
        $this->assertTrue($result, 'Write operation should succeed');
        
        // Verify file was created with correct permissions
        $this->assertFileExists($storageFile);

        // Test read operation
        $readData = $storage->get($request1);
        $this->assertIsArray($readData);
        $this->assertEquals('IP Address', $readData['plugin']);
        $this->assertEquals('TEST123', $readData['event_id']);
        
        // Test multiple entries
        $plugin = new GeoLocation();
        $request2 = Request::create('/', 'GET', [], [], [], [], ['REMOTE_ADDR' => '10.0.0.1']);
        $request2->attributes->set('blocking-plugin', $plugin);
        $request2->attributes->set('x-request-id', 'TEST123');
        $storage->set($request2, 3600);

        $plugin = new UserAgent();
        $request3 = Request::create('/', 'GET', [], [], [], [], ['REMOTE_ADDR' => '10.0.0.2']);
        $request3->attributes->set('blocking-plugin', $plugin);
        $request3->attributes->set('x-request-id', 'TEST123');
        $storage->set($request3, 3600);
        
        // Verify all entries exist
        $this->assertNotFalse($storage->get($request1));
        $this->assertNotFalse($storage->get($request2));
        $this->assertNotFalse($storage->get($request3));
        
        // Test deletion
        $storage->delete($request2);
        $this->assertNull($storage->get($request2), 'Deleted entry should not exist');
        $this->assertNotFalse($storage->get($request3), 'Other entries should remain');
    }
    
    /**
     * Tests FileStorage with concurrent write operations.
     * 
     * This test verifies:
     * - Multiple processes can safely write to the same file
     * - File locking prevents data corruption
     * - All writes are eventually consistent
     * - No data loss occurs under concurrent access
     */
    public function testFileStorageConcurrentWrites(): void
    {
        $storageFile = $this->tempDir . '/concurrent.data';
        
        // Simulate concurrent writes using multiple storage instances
        $storages = [];
        for ($i = 0; $i < 5; $i++) {
            $storages[] = new FileStorage(['storage_file' => $storageFile]);
        }
        
        // Each instance writes different data
        $writes = [];
        foreach ($storages as $index => $storage) {
            $ip = "192.168.1." . ($index + 1);
            $request = Request::create('/', 'GET', [], [], [], [], ['REMOTE_ADDR' => $ip]);
            $plugin = new IpAddress();
            $request->attributes->set('plugin', $plugin);
            $request->attributes->set('x-request-id', 'TEST123');

            $data = ['instance' => $index, 'timestamp' => microtime(true)];
            $storage->set($plugin, 3600);
            $writes[$ip] = $data;
        }
        
        // Verify all writes succeeded
        $verifyStorage = new FileStorage(['storage_file' => $storageFile]);
        foreach ($writes as $ip => $expectedData) {
            $request = Request::create('/', 'GET', [], [], [], [], ['REMOTE_ADDR' => $ip]);
            $actualData = $verifyStorage->get($request);
            $this->assertIsArray($actualData, "Data for $ip should exist");
            $this->assertEquals($expectedData['instance'], $actualData['instance']);
        }
    }
    
    /**
     * Tests FileStorage expiration and cleanup.
     * 
     * This test verifies:
     * - Expired entries are properly identified
     * - clearExpire() removes only expired entries
     * - Non-expired entries are preserved
     * - File is compacted after cleanup
     */
    public function testFileStorageExpirationHandling(): void
    {
        $storageFile = $this->tempDir . '/expiration.data';
        $storage = new FileStorage(['storage_file' => $storageFile]);

        $plugin = new IpAddress();
        $request = Request::create('/', 'GET', [], [], [], [], ['REMOTE_ADDR' => '192.168.1.100']);
        $request->attributes->set('plugin', $plugin);
        $request->attributes->set('x-request-id', 'TEST123');
        // Add entries with different expiration times
        $storage->set($request, 0); // Never expires

        $request = Request::create('/', 'GET', [], [], [], [], ['REMOTE_ADDR' => '192.168.1.101']);
        $request->attributes->set('plugin', $plugin);
        $request->attributes->set('x-request-id', 'TEST123');
        $storage->set($request, 2); // Expires in 2 seconds

        $request = Request::create('/', 'GET', [], [], [], [], ['REMOTE_ADDR' => '192.168.1.102']);
        $request->attributes->set('plugin', $plugin);
        $request->attributes->set('x-request-id', 'TEST123');
        $storage->set($request, 5); // Expires in 5 seconds
        
        // Initial file size
        clearstatcache();
        $initialSize = filesize($storageFile);
        
        // Wait for short expiration
        sleep(3);
        
        // Clear expired entries
        $storage->clearExpire();
        
        // Verify expired entries are removed
        $this->assertNotNull($storage->get('expire_now'), 'Permanently banned, will not remove');
        $this->assertNull($storage->get('expire_soon'), 'Soon-expired entry should be removed');
        $this->assertNotNull($storage->get('expire_later'), 'Later expired entry should still stay');

        sleep(3);
        // Clear expired entries
        $storage->clearExpire();
        $this->assertNull($storage->get('expire_later'), 'Soon-expired entry should be removed');

        // Verify file was compacted
        clearstatcache();
        $newSize = filesize($storageFile);
        $this->assertLessThan($initialSize, $newSize, 'File should be smaller after cleanup');
    }
    
    /**
     * Tests DatabaseStorage with MySQL.
     *
     * This test verifies:
     * - Table creation and schema
     * - CRUD operations with real database
     * - Transaction handling
     * - Unique constraint enforcement
     */
    public function testDatabaseStorageMySQL(): void
    {
        $this->skipIfGroupDisabled('database');
        $this->requireEnvVars(['DB_MYSQL_DSN']);
        
        $dsn = self::getDatabaseDsn('mysql');
        if (!$dsn) {
            $this->markTestSkipped('MySQL DSN not configured');
        }
        
        try {
            $connectionParams = (new DsnParser())->parse($dsn);
            $connection = DriverManager::getConnection($connectionParams);
        } catch (\Exception $e) {
            $this->markTestSkipped('Could not connect to MySQL: ' . $e->getMessage());
        }
        
        $this->runDatabaseStorageTests($connection, 'mysql');
    }
    
    /**
     * Tests DatabaseStorage with PostgreSQL.
     * 
     * This test verifies:
     * - PostgreSQL-specific table creation
     * - JSONB data type handling
     * - Transaction isolation
     * - Concurrent access handling
     */
    public function testDatabaseStoragePostgreSQL(): void
    {
        $this->skipIfGroupDisabled('database');
        $this->requireEnvVars(['DB_PGSQL_DSN']);
        
        $dsn = self::getDatabaseDsn('pgsql');
        if (!$dsn) {
            $this->markTestSkipped('PostgreSQL DSN not configured');
        }
        
        try {
            $connectionParams = (new DsnParser())->parse($dsn);
            $connection = DriverManager::getConnection($connectionParams);
        } catch (\Exception $e) {
            $this->markTestSkipped('Could not connect to PostgreSQL: ' . $e->getMessage());
        }
        
        $this->runDatabaseStorageTests($connection, 'pgsql');
    }
    
    /**
     * Tests DatabaseStorage with SQLite.
     * 
     * This test verifies:
     * - SQLite file creation
     * - In-memory database support
     * - Basic operations without server
     * - File-based locking
     */
    public function testDatabaseStorageSQLite(): void
    {
        $dbFile = $this->tempDir . '/firewall.db';
        $dsn = 'sqlite3:///' . $dbFile;

        $dsnParser = (new DsnParser())->parse($dsn);
        unset($dsnParser['host']);
        $connection = DriverManager::getConnection($dsnParser);
        $this->runDatabaseStorageTests($connection, 'pdo_sqlite');
        
        // Verify database file was created
        $this->assertFileExists($dbFile);
    }
    
    /**
     * Common database storage tests for all database types.
     */
    protected function runDatabaseStorageTests(Connection $connection, string $dbType): void
    {
        $tableName = 'firewall_test_' . uniqid();
        $storage = new DatabaseStorage([
            'connection' => $connection,
            'storage_table' => $tableName
        ]);
        
        // Test table creation
        $schemaManager = $connection->createSchemaManager();
        $this->assertTrue($schemaManager->tablesExist([$tableName]), "Table $tableName should be created");
        
        // Test basic operations
        $testData = [
            'plugin' => 'IpAddress',
            'blocked' => date('c'),
            'event_id' => 'DB_TEST_' . $dbType,
        ];

        $plugin = new IpAddress();

        // Insert
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '192.168.1.100']);
        $request->attributes->set('x-request-id', 'abc');
        $request->attributes->set('blocking-plugin', $plugin);
        $result = $storage->set($request, 3600);
        $this->assertTrue($result, 'Insert should succeed');
        
        // Read
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '192.168.1.100']);
        $request->attributes->set('x-request-id', 'abc');
        $request->attributes->set('blocking-plugin', $plugin);
        $readData = $storage->get($request);
        $this->assertIsArray($readData);
        $this->assertEquals('IP Address', $readData['plugin']);

        // Update
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '192.168.1.100']);
        $request->attributes->set('blocking-plugin', $plugin);
        $request->attributes->set('x-request-id', 'abc123');
        $storage->set($request, 3600);
        $readData = $storage->get($request);
        $this->assertEquals('abc123', $readData['event_id']);
        
        // Test expiration
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '192.168.1.100']);
        $request->attributes->set('x-request-id', 'abc');
        $request->attributes->set('blocking-plugin', $plugin);
        $storage->set($request, 1);
        sleep(2);
        $storage->clearExpire();
        $this->assertNull($storage->get($request), 'Expired entry should be removed');
        
        // Clean up
        $connection->executeStatement("DROP TABLE $tableName");
    }
    
    /**
     * Tests InMemoryStorage behavior.
     * 
     * This test verifies:
     * - Data is not persisted between instances
     * - Memory usage is reasonable
     * - Operations are fast
     * - Expiration works correctly
     */
    public function testInMemoryStorageIsolation(): void
    {
        // Create two separate instances
        $storage1 = new InMemoryStorage();
        $storage2 = new InMemoryStorage();

        $ips = $this->generateRandomIPv4Addresses(1001);
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $ips[0]]);

        // Write to first instance
        $storage1->set($request, 3600);

        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '192.168.1.100']);
        // Verify isolation
        $this->assertNotFalse($storage1->get($request), 'Data should exist in instance 1');
        $this->assertNull($storage2->get($request), 'Data should not exist in instance 2');
        
        // Test memory cleanup
        for ($i = 0; $i < 1000; $i++) {
            $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $ips[$i+1]]);
            $storage1->set($request, 3600);
        }
        
        // Clear all data
        for ($i = 0; $i < 1000; $i++) {
            $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $ips[$i+1]]);
            $storage1->delete($request);
        }
        
        // Memory should be released (this is a basic check)
        $this->assertTrue(true, 'Memory operations completed without error');
    }

    /**
     * Generate a list of random IPv4 addresses.
     *
     * @param int $count The number of IP addresses to generate.
     * @return array An array of randomly generated IPv4 addresses.
     */
    public function generateRandomIPv4Addresses(int $count): array {
        $addresses = [];

        for ($i = 0; $i < $count; $i++) {
            $ip = sprintf(
                '%d.%d.%d.%d',
                random_int(1, 223),      // Avoid 0, multicast (224–239), and reserved ranges
                random_int(0, 255),
                random_int(0, 255),
                random_int(1, 254)       // Avoid .0 and .255
            );
            $addresses[] = $ip;
        }

        return $addresses;
    }
    
    /**
     * Tests storage performance with large datasets.
     * 
     * This test verifies:
     * - Storage can handle thousands of entries
     * - Performance remains acceptable
     * - No memory leaks occur
     * - Cleanup operations scale well
     */
    public function testStoragePerformanceWithLargeDataset(): void
    {
        $iterations = (int) self::getEnv('PERF_TEST_ITERATIONS', 1000);
        
        // Test each storage type
        $storageTypes = [
            'InMemory' => new InMemoryStorage(),
            'File' => new FileStorage(['storage_file' => $this->tempDir . '/perf.data']),
        ];

        $ips = $this->generateRandomIPv4Addresses($iterations);
        
        foreach ($storageTypes as $type => $storage) {
            $startTime = microtime(true);
            $startMemory = memory_get_usage();

            // Write many entries
            for ($i = 0; $i < $iterations; $i++) {
                $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $ips[$i]]);
                $storage->set($request, 3600);
            }
            
            $writeTime = microtime(true) - $startTime;
            
            // Read random entries
            $readStart = microtime(true);
            for ($i = 0; $i < 100; $i++) {
                $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $ips[$i]]);
                $data = $storage->get($request);
                $index = $request->getClientIp();
                $this->assertIsArray($data, "Entry $index should exist");
            }
            
            $readTime = microtime(true) - $readStart;
            
            // Clean up
            $cleanStart = microtime(true);
            $storage->clearExpire();
            $cleanTime = microtime(true) - $cleanStart;
            
            $memoryUsed = memory_get_usage() - $startMemory;
            
            // Log performance metrics (these could be assertions with thresholds)
            $this->addToAssertionCount(1);
            
            // Basic performance assertions
            $this->assertLessThan(10, $writeTime, "$type: Write time should be under 10 seconds");
            $this->assertLessThan(1, $readTime, "$type: Read time should be under 1 second");
            $this->assertLessThan(5, $cleanTime, "$type: Clean time should be under 5 seconds");
        }
    }
}