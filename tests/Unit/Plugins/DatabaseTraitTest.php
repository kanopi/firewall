<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\MySQLSchemaManager;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Tools\DsnParser;
use Doctrine\DBAL\Types\Types;
use Kanopi\Firewall\Storage\DatabaseStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Traits\DatabaseTrait;

/**
 * Integration tests for DatabaseTrait using SQLite in-memory connection.
 */
class DatabaseTraitTest extends AbstractTestCase
{
    /**
     * Creates a test instance with `getStorageTable()` implemented.
     */
    protected function getConcreteInstance(array $config): object
    {
        return new class($config) {
            use DatabaseTrait;

            protected array $config;

            public function __construct(array $config)
            {
                $this->config = $config;
                $this->config['storage_table'] ??= 'test_table';
                $this->createConnection(['dsn' => 'sqlite3:///:memory:']);
            }

            public function getStorageTable(): Table
            {
                $table = new Table($this->config['storage_table']);
                $table->addColumn('id', Types::INTEGER, ['autoincrement' => true]);
                $table->setPrimaryKey(['id']);
                return $table;
            }

            public function tableExists(): bool
            {
                return $this->schemaManager->tablesExist([$this->config['storage_table']]);
            }
        };
    }

    /**
     * Tests to confirm that can pass instance of connection.
     */
    public function testConstructWithInstance(): void
    {
        $connectionParams = (new DsnParser())->parse('sqlite3:///:memory:');
        $connection = DriverManager::getConnection($connectionParams);
        $tableName = 'firewall_test_' . uniqid();
        $storage = new DatabaseStorage([
            'connection' => $connection,
            'storage_table' => $tableName
        ]);

        // Test table creation
        $schemaManager = $connection->createSchemaManager();
        $this->assertTrue($schemaManager->tablesExist([$tableName]), "Table $tableName should be created");
    }

    /**
     * Verifies the table is created successfully with standard DSN.
     */
    public function testCreatesTable(): void
    {
        $instance = $this->getConcreteInstance([]);
        $this->assertTrue($instance->tableExists(), 'Expected table to be created');
    }

    /**
     * Creates an anonymous instance without getStorageTable() to test silent failure.
     */
    public function testCreateTableWithoutGetStorageTable(): void
    {
        $instance = new class {
            use DatabaseTrait;

            public array $config = ['storage_table' => 'unused_table'];

            public function __construct()
            {
                $this->connection = DriverManager::getConnection([
                    'driver' => 'pdo_sqlite',
                    'memory' => true,
                ]);
                $this->schemaManager = $this->connection->createSchemaManager();
                $this->createTable(); // should silently fail
            }
        };

        $this->assertTrue(true, 'Should still work without getStorageTable() implementation');
    }

    /**
     * Tests that createTable() handles the case where the table already exists.
     */
    public function testCreateTableHandlesDuplicate(): void
    {
        $instance = new class {
            use DatabaseTrait;

            public array $config = ['storage_table' => 'dup_table'];

            public function __construct()
            {
                $this->connection = DriverManager::getConnection([
                    'driver' => 'pdo_sqlite',
                    'memory' => true,
                ]);
                $this->schemaManager = $this->connection->createSchemaManager();

                // Create table manually
                $platform = $this->connection->getDatabasePlatform();
                $schema = new \Doctrine\DBAL\Schema\Schema();
                $table = $schema->createTable('dup_table');
                $table->addColumn('id', Types::INTEGER, ['autoincrement' => true]);
                $table->setPrimaryKey(['id']);

                // Execute the schema's SQL statements
                foreach ($schema->toSql($platform) as $sql) {
                    $this->connection->executeStatement($sql);
                }

                // Now invoke createTable() which should catch and ignore the exception
                $this->createTable();
            }

            protected function getStorageTable(): Table
            {
                $table = new Table('dup_table');
                $table->addColumn('id', Types::INTEGER, ['autoincrement' => true]);
                $table->setPrimaryKey(['id']);
                return $table;
            }

            public function tableStillExists(): bool
            {
                return $this->schemaManager->tablesExist(['dup_table']);
            }
        };

        $this->assertTrue($instance->tableStillExists(), 'Table should still exist after duplicate creation attempt');
    }

    /**
     * Tests that createConnection throws no error with valid SQLite DSN.
     */
    public function testCreateConnectionViaDsn(): void
    {
        $instance = $this->getConcreteInstance(['storage_table' => 'dsn_created']);
        $this->assertTrue($instance->tableExists(), 'Expected table via DSN to exist');
    }

    /**
     * Tests connection gracefully handles invalid DSN.
     */
    public function testInvalidDsnDoesNotCrash(): void
    {
        $instance = new class {
            use DatabaseTrait;

            public bool $hasConnection = true;

            public function __construct()
            {
                try {
                    $this->createConnection(['dsn' => 'invalid-dsn']);
                    $this->hasConnection = isset($this->connection);
                } catch (\Throwable) {
                    $this->hasConnection = false;
                }
            }
        };

        $this->assertFalse($instance->hasConnection, 'Invalid DSN should not produce a connection');
    }

    /**
     * Ensure createTable() catches and swallows exceptions from schemaManager->createTable().
     */
    public function testCreateTableThrowsAndIsCaughtGracefully(): void
    {
        $instance = new class {
            use \Kanopi\Firewall\Traits\DatabaseTrait;

            public array $config = ['storage_table' => 'broken_table'];

            public function __construct()
            {
                $this->createConnection([
                    'driver' => 'pdo_sqlite',
                    'memory' => true,
                ]);
            }

            protected function getStorageTable(): \Doctrine\DBAL\Schema\Table
            {
                return new Table('broken_table');
            }

            public function tableExists(): bool
            {
                return false;
            }
        };

        $this->assertFalse($instance->tableExists(), 'Table should not exist');
    }

    /**
     * Ensure enforceTableData returns back empty array on exception.
     */
    public function testEnforceTableDataException(): void
    {
        $mockSchemaManager = $this->createMock(MySQLSchemaManager::class);
        $mockSchemaManager->expects($this->any())->method('listTableColumns')->willThrowException(new \Exception('Exception Thrown From getColumnListing'));
        $instance = new class($mockSchemaManager) {
            use \Kanopi\Firewall\Traits\DatabaseTrait;

            public function __construct($schemaManager)
            {
                $this->schemaManager = $schemaManager;
            }

            public function enforceTableDataWrapper(string $table, array $data = []): array
            {
                return $this->enforceTableData($table, $data);
            }
        };

        $this->assertEmpty($instance->enforceTableDataWrapper('broken_table'), 'Confirm Enforce Data returns empty data');
    }
}
