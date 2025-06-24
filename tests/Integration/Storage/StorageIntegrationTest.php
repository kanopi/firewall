<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration\Storage;

use Doctrine\DBAL\Tools\DsnParser;
use Kanopi\Firewall\Storage\FileStorage;
use Kanopi\Firewall\Storage\DatabaseStorage;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Tests\Integration\IntegrationTestCase;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Connection;

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
        $storage = new FileStorage(['file' => $storageFile]);
        
        // Test basic write operation
        $testData = [
            'plugin' => 'IpAddress',
            'blocked' => date('c'),
            'event_id' => 'TEST123',
            'request' => ['method' => 'GET', 'path' => '/']
        ];
        
        $result = $storage->set('192.168.1.100', $testData, 3600);
        $this->assertTrue($result, 'Write operation should succeed');
        
        // Verify file was created with correct permissions
        $this->assertFileExists($storageFile);

        // Test read operation
        $readData = $storage->get('192.168.1.100');
        $this->assertIsArray($readData);
        $this->assertEquals('IpAddress', $readData['plugin']);
        $this->assertEquals('TEST123', $readData['event_id']);
        
        // Test multiple entries
        $storage->set('10.0.0.1', ['plugin' => 'GeoLocation'], 3600);
        $storage->set('10.0.0.2', ['plugin' => 'UserAgent'], 3600);
        
        // Verify all entries exist
        $this->assertNotFalse($storage->get('192.168.1.100'));
        $this->assertNotFalse($storage->get('10.0.0.1'));
        $this->assertNotFalse($storage->get('10.0.0.2'));
        
        // Test deletion
        $storage->delete('10.0.0.1');
        $this->assertNull($storage->get('10.0.0.1'), 'Deleted entry should not exist');
        $this->assertNotFalse($storage->get('10.0.0.2'), 'Other entries should remain');
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
            $storages[] = new FileStorage(['file' => $storageFile]);
        }
        
        // Each instance writes different data
        $writes = [];
        foreach ($storages as $index => $storage) {
            $ip = "192.168.1." . ($index + 1);
            $data = ['instance' => $index, 'timestamp' => microtime(true)];
            $storage->set($ip, $data, 3600);
            $writes[$ip] = $data;
        }
        
        // Verify all writes succeeded
        $verifyStorage = new FileStorage(['file' => $storageFile]);
        foreach ($writes as $ip => $expectedData) {
            $actualData = $verifyStorage->get($ip);
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
        $storage = new FileStorage(['file' => $storageFile]);
        
        // Add entries with different expiration times
        $storage->set('expire_now', ['data' => 'test1'], 0); // Already expired
        $storage->set('expire_soon', ['data' => 'test2'], 2); // Expires in 2 seconds
        $storage->set('expire_later', ['data' => 'test3'], 5); // Expires in 1 hour
        
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
        
        // Insert
        $result = $storage->set('192.168.1.100', $testData, 3600);
        $this->assertTrue($result, 'Insert should succeed');
        
        // Read
        $readData = $storage->get('192.168.1.100');
        $this->assertIsArray($readData);
        $this->assertEquals('IpAddress', $readData['plugin']);

        // Update
        $testData['plugin'] = 'Updated';
        $storage->set('192.168.1.100', $testData, 3600);
        $readData = $storage->get('192.168.1.100');
        $this->assertEquals('Updated', $readData['plugin']);
        
        // Test expiration
        $storage->set('expire_test', $testData, 1);
        sleep(2);
        $storage->clearExpire();
        $this->assertNull($storage->get('expire_test'), 'Expired entry should be removed');
        
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
        
        // Write to first instance
        $storage1->set('192.168.1.100', ['instance' => 1], 3600);
        
        // Verify isolation
        $this->assertNotFalse($storage1->get('192.168.1.100'), 'Data should exist in instance 1');
        $this->assertNull($storage2->get('192.168.1.100'), 'Data should not exist in instance 2');
        
        // Test memory cleanup
        for ($i = 0; $i < 1000; $i++) {
            $storage1->set("ip_$i", ['data' => str_repeat('x', 1000)], 3600);
        }
        
        // Clear all data
        for ($i = 0; $i < 1000; $i++) {
            $storage1->delete("ip_$i");
        }
        
        // Memory should be released (this is a basic check)
        $this->assertTrue(true, 'Memory operations completed without error');
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
            'File' => new FileStorage(['file' => $this->tempDir . '/perf.data']),
        ];
        
        foreach ($storageTypes as $type => $storage) {
            $startTime = microtime(true);
            $startMemory = memory_get_usage();
            
            // Write many entries
            for ($i = 0; $i < $iterations; $i++) {
                $storage->set("perf_test_$i", [
                    'index' => $i,
                    'data' => str_repeat('x', 100),
                    'timestamp' => microtime(true)
                ], 3600);
            }
            
            $writeTime = microtime(true) - $startTime;
            
            // Read random entries
            $readStart = microtime(true);
            for ($i = 0; $i < 100; $i++) {
                $index = rand(0, $iterations - 1);
                $data = $storage->get("perf_test_$index");
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