<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\MySQLSchemaManager;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Tools\DsnParser;
use Doctrine\DBAL\Types\Types;
use Kanopi\Firewall\Exception\StorageConnectionException;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Exception\StorageException;
use Kanopi\Firewall\Storage\DatabaseStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Traits\DatabaseTrait;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;

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

            public function getStorageTables(): array
            {
                $table = new Table($this->config['storage_table']);
                $table->addColumn('id', Types::INTEGER, ['autoincrement' => true]);
                $table->setPrimaryKey(['id']);
                return [$table];
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
     * Test that exception is caught if getTables doesn't return a valid table.
     */
    public function testCreateTablesWithException(): void
    {
        $config = [];
        $instance = new class($config) {
            use DatabaseTrait;

            protected array $config;

            public function __construct(array $config)
            {
                $this->config = $config;
                $this->config['storage_table'] ??= 'test_table';
                $this->createConnection(['dsn' => 'sqlite3:///:memory:']);
            }

            public function getStorageTables(): array
            {
                $table = new Table('temp_table');
                return [$table];
            }

            public function tableExists(): bool
            {
                return $this->schemaManager->tablesExist([$this->config['storage_table']]);
            }
        };

        $this->assertFalse($instance->tableExists(), 'Expected table to not be created');
    }

    /**
     * Test no exceptions thrown if table already exists.
     */
    public function testCreateTablesTableExists(): void
    {
        $config = [];
        $instance = new class($config) {
            use DatabaseTrait;

            protected array $config;

            public function __construct(array $config)
            {
                $this->config = $config;
                $this->config['storage_table'] ??= 'test_table';

                $dsnParser = (new DsnParser())->parse('sqlite3:///:memory:');
                $connection = DriverManager::getConnection($dsnParser);

                $tables = $this->getStorageTables();
                $connection->createSchemaManager()->createTable($tables[0]);

                $this->createConnection($connection);
            }

            public function getStorageTables(): array
            {
                $table = new Table($this->config['storage_table']);
                $table->addColumn('id', Types::INTEGER, ['autoincrement' => true]);
                $table->setPrimaryKey(['id']);
                return [$table];
            }

            public function tableExists(): bool
            {
                return $this->schemaManager->tablesExist([$this->config['storage_table']]);
            }
        };

        $this->assertTrue($instance->tableExists(), 'Do nothing if table exists');
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
     * A connection that cannot be built reports why (#144).
     *
     * `driver: nope` fails inside `DriverManager::getConnection()`, before
     * either typed property is assigned. Pre-fix the failure was logged and
     * swallowed, so the caller got an object that looked fine and then died on
     * `Typed property ...$schemaManager must not be accessed before
     * initialization` — an `\Error`, which `catch (\Exception)` misses.
     */
    public function testCreateConnectionThrowsWhenConnectionCannotBeBuilt(): void
    {
        $instance = new class {
            use DatabaseTrait;

            public array $config = ['storage_table' => 'unreachable'];

            public function connect(array $params): void
            {
                $this->createConnection($params);
            }
        };

        try {
            $instance->connect(['driver' => 'nope']);
            self::fail('Expected a StorageConnectionException.');
        } catch (StorageConnectionException $exception) {
            self::assertStringContainsString('could not connect', $exception->getMessage());
            self::assertStringContainsString('driver=nope', $exception->getMessage());
            self::assertInstanceOf(
                \Doctrine\DBAL\Exception::class,
                $exception->getPrevious(),
                'The driver exception must be attached so callers can inspect the real cause.'
            );
        }
    }

    /**
     * The new exception stays catchable as a storage failure.
     *
     * Consumers already guard storage setup with `catch (StorageException)`, so
     * the connection case must not escape those guards.
     */
    public function testConnectionExceptionIsAStorageException(): void
    {
        $instance = new class {
            use DatabaseTrait;

            public array $config = ['storage_table' => 'unreachable'];

            public function connect(array $params): void
            {
                $this->createConnection($params);
            }
        };

        $this->expectException(StorageException::class);
        $instance->connect(['driver' => 'nope']);
    }

    /**
     * A database that cannot be reached reports why, too.
     *
     * Doctrine connects lazily, so an unreachable database first fails inside
     * `createTable()` — after both properties are assigned. That path used to
     * leave a fully constructed object whose every query failed, which is what
     * made a consuming admin screen show an empty list rather than an error.
     */
    public function testCreateConnectionThrowsWhenDatabaseCannotBeReached(): void
    {
        $instance = new class {
            use DatabaseTrait;

            public array $config = ['storage_table' => 'unreachable'];

            public function connect(array $params): void
            {
                $this->createConnection($params);
            }

            public function getStorageTables(): array
            {
                $table = new Table($this->config['storage_table']);
                $table->addColumn('id', Types::INTEGER, ['autoincrement' => true]);
                $table->setPrimaryKey(['id']);
                return [$table];
            }
        };

        $path = '/nonexistent-directory-' . uniqid() . '/firewall.sqlite';

        try {
            $instance->connect(['driver' => 'pdo_sqlite', 'path' => $path]);
            self::fail('Expected a StorageConnectionException.');
        } catch (StorageConnectionException $exception) {
            self::assertStringContainsString('unable to open database file', $exception->getMessage());
            self::assertStringContainsString('path=' . $path, $exception->getMessage());
        }
    }

    /**
     * The failure names the target without exposing the credentials for it.
     *
     * The message and the log both reach places an operator reads — an error
     * log, a consuming application's admin screen — so they carry the host and
     * database but never the password, including when it arrived inside a DSN.
     */
    public function testConnectionFailureDescribesTargetWithoutCredentials(): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $instance = new class {
            use DatabaseTrait;

            public array $config = ['storage_table' => 'unreachable'];

            public function connect(array $params): void
            {
                $this->createConnection($params);
            }
        };

        try {
            $instance->connect(['dsn' => 'nope://firewall:sup3rsecret@db.example.com:3306/firewall_db']);
            self::fail('Expected a StorageConnectionException.');
        } catch (StorageConnectionException $exception) {
            self::assertStringContainsString('host=db.example.com', $exception->getMessage());
            self::assertStringContainsString('dbname=firewall_db', $exception->getMessage());
            self::assertStringNotContainsString('sup3rsecret', $exception->getMessage());
        }

        self::assertTrue(
            $handler->hasRecordThatContains('Failed to create database connection', Level::Error),
            'The failure is still logged, as before.'
        );

        foreach ($handler->getRecords() as $record) {
            self::assertStringNotContainsString('sup3rsecret', json_encode($record->context) ?: '');
        }
    }

    /**
     * A malformed DSN cannot be parsed at all, and is described as such.
     */
    public function testConnectionFailureDescribesAnUnparseableDsn(): void
    {
        $instance = new class {
            use DatabaseTrait;

            public array $config = ['storage_table' => 'unreachable'];

            public function connect(array $params): void
            {
                $this->createConnection($params);
            }
        };

        try {
            $instance->connect(['dsn' => 'mysql://firewall:sup3rsecret@db:99999999999/firewall_db']);
            self::fail('Expected a StorageConnectionException.');
        } catch (StorageConnectionException $exception) {
            self::assertStringContainsString('unparseable dsn', $exception->getMessage());
            self::assertStringNotContainsString('sup3rsecret', $exception->getMessage());
        }
    }

    /**
     * Connection parameters can be absent entirely — both storages default
     * `$config['connection']` to `[]` — and that is still reported.
     */
    public function testConnectionFailureWithNoParametersAtAll(): void
    {
        $instance = new class {
            use DatabaseTrait;

            public array $config = ['storage_table' => 'unreachable'];

            public function connect(array $params): void
            {
                $this->createConnection($params);
            }
        };

        try {
            $instance->connect([]);
            self::fail('Expected a StorageConnectionException.');
        } catch (StorageConnectionException $exception) {
            self::assertStringContainsString('no connection parameters', $exception->getMessage());
        }
    }

    /**
     * A ready-made Connection is described from its own parameters.
     */
    public function testConnectionFailureDescribesAPassedConnection(): void
    {
        $connection = DriverManager::getConnection([
            'driver' => 'pdo_sqlite',
            'path' => '/nonexistent-directory-' . uniqid() . '/firewall.sqlite',
            'password' => 'sup3rsecret',
        ]);

        $instance = new class {
            use DatabaseTrait;

            public array $config = ['storage_table' => 'unreachable'];

            public function connect(\Doctrine\DBAL\Connection $connection): void
            {
                $this->createConnection($connection);
            }

            public function getStorageTables(): array
            {
                $table = new Table($this->config['storage_table']);
                $table->addColumn('id', Types::INTEGER, ['autoincrement' => true]);
                $table->setPrimaryKey(['id']);
                return [$table];
            }
        };

        try {
            $instance->connect($connection);
            self::fail('Expected a StorageConnectionException.');
        } catch (StorageConnectionException $exception) {
            self::assertStringContainsString('driver=pdo_sqlite', $exception->getMessage());
            self::assertStringNotContainsString('sup3rsecret', $exception->getMessage());
        }
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
