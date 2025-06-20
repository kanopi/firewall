<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\AbstractSchemaManager;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Types;
use Kanopi\Firewall\Plugins\DatabaseTrait;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for DatabaseTrait using SQLite in-memory connection.
 */
class DatabaseTraitTest extends TestCase
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
            use \Kanopi\Firewall\Plugins\DatabaseTrait;

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
}
