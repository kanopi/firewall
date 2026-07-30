<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Query\QueryBuilder;
use Doctrine\DBAL\Result;
use Doctrine\DBAL\Schema\AbstractSchemaManager;
use Kanopi\Firewall\Plugins\IpAddress;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Storage\DatabaseStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Unit tests for DatabaseStorage.
 */
class DatabaseStorageTest extends AbstractTestCase
{
    private Connection $mockConnection;
    private AbstractSchemaManager $mockSchema;
    private QueryBuilder $mockBuilder;
    private Result $mockResult;
    private DatabaseStorage $storage;

    private function injectProtectedProperty(object $object, string $property, mixed $value): void
    {
        $refClass = new \ReflectionClass($object);
        $refProp = $refClass->getProperty($property);
        $refProp->setAccessible(true);
        $refProp->setValue($object, $value);
    }

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        // Mocks
        $this->mockConnection = $this->createMock(Connection::class);
        $this->mockSchema = $this->createMock(AbstractSchemaManager::class);
        $this->mockBuilder = $this->createMock(QueryBuilder::class);
        $this->mockResult = $this->createMock(Result::class);

        // Partial mock
        $this->storage = $this->getMockBuilder(DatabaseStorage::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['createConnection', 'getStorageTables'])
            ->getMock();

        // Prevent constructor from connecting, but fake it anyway
        $this->storage->expects($this->once())
            ->method('createConnection')
            ->willReturnCallback(function () {
                $this->injectProtectedProperty($this->storage, 'connection', $this->mockConnection);
                $this->injectProtectedProperty($this->storage, 'schemaManager', $this->mockSchema);
                $this->injectProtectedProperty($this->storage, 'config', [
                    'storage_table' => 'firewall_storage',
                    'offenses_table' => 'firewall_offense',
                ]);
            });

        // Trigger constructor logic
        $this->storage->__construct([
            'connection' => [],
            'storage_table' => 'firewall_storage',
            'offenses_table' => 'firewall_offense',
        ]);
    }

    /**
     * Tests set() inserts a new record if key doesn't exist.
     */
    public function testSetInsertsIfNotExists(): void
    {
        $this->mockConnection->method('insert')->willReturn(1);
        $this->mockConnection->method('update')->willReturn(0);
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);

        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);

        $this->mockResult->method('fetchAssociative')->willReturn([]);

        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('TestPlugin');
        $request = $this->getRequest();
        $result = $this->storage->set($request->getClientIp(), $this->storage->getStorageData($request, $plugin));

        $this->assertTrue($result);
    }

    /**
     * Regression for #62: the `request` column must be JSON, not the
     * output of `serialize()`. The previous behaviour was a latent
     * CWE-502 footgun — any future caller who decided to `unserialize()`
     * that column would be feeding row contents into PHP object
     * instantiation.
     */
    public function testSetStoresRequestColumnAsJson(): void
    {
        // Capture only the insert into the storage table — set() also inserts
        // into the offenses table via recordOffense(), which would otherwise
        // clobber the captured payload.
        $captured = null;
        $this->mockConnection->method('insert')
            ->willReturnCallback(function (string $table, array $data) use (&$captured): int {
                if ($table === 'firewall_storage') {
                    $captured = $data;
                }

                return 1;
            });
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);

        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);
        // `exists()` runs first via fetchAllAssociative; return empty so set() takes the insert branch.
        $this->mockResult->method('fetchAllAssociative')->willReturn([]);

        // `enforceTableData()` filters $data against the column list returned
        // by the schema manager. Return a stub-column map so the `request`
        // key actually survives to the insert() call.
        $stubColumn = $this->createMock(\Doctrine\DBAL\Schema\Column::class);
        $this->mockSchema->method('listTableColumns')->willReturn([
            'remote_address' => $stubColumn,
            'plugin' => $stubColumn,
            'event_id' => $stubColumn,
            'timestamp' => $stubColumn,
            'request' => $stubColumn,
            'expire' => $stubColumn,
            'metadata' => $stubColumn,
        ]);

        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('TestPlugin');

        $request = $this->getRequest('1.2.3.4');
        $this->assertTrue($this->storage->set($request->getClientIp(), $this->storage->getStorageData($request, $plugin)));

        $this->assertIsArray($captured);
        $this->assertArrayHasKey('request', $captured);
        $stored = $captured['request'];
        $this->assertIsString($stored);
        // JSON must begin with `{` (associative) or `[` (list), never PHP's serialize() prefixes.
        $this->assertTrue(in_array($stored[0] ?? '', ['{', '['], true), 'Stored request column is not JSON');
        $this->assertStringStartsNotWith('a:', $stored, 'Stored request must not be serialize() array payload');
        $this->assertStringStartsNotWith('O:', $stored, 'Stored request must not be serialize() object payload');

        $decoded = json_decode($stored, true, 512, JSON_THROW_ON_ERROR);
        $this->assertIsArray($decoded);
        $this->assertSame('GET', $decoded['method']);
    }

    /**
     * Tests delete() succeeds and returns true.
     */
    public function testDelete(): void
    {
        $this->mockConnection->expects($this->once())
            ->method('delete')
            ->with('firewall_storage', ['remote_address' => '1.2.3.4']);

        $request = $this->getRequest('1.2.3.4');
        $this->assertTrue($this->storage->delete($request->getClientIp()));
    }

    /**
     * Tests get() returns a row when key exists.
     */
    public function testGetReturnsDataIfExists(): void
    {
        $row = ['remote_address' => '1.2.3.4', 'plugin' => 'TestPlugin'];
        $request = $this->getRequest('1.2.3.4');

        // Partial mock
        $storage = $this->getMockBuilder(DatabaseStorage::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['createConnection', 'getStorageTables', 'exists'])
            ->getMock();

        // Prevent constructor from connecting, but fake it anyway
        $storage->expects($this->once())
            ->method('createConnection')
            ->willReturnCallback(function () use ($storage) {
                $this->injectProtectedProperty($storage, 'connection', $this->mockConnection);
                $this->injectProtectedProperty($storage, 'schemaManager', $this->mockSchema);
                $this->injectProtectedProperty($storage, 'config', [
                    'storage_table' => 'firewall_storage',
                    'offenses_table' => 'firewall_offense',
                ]);
            });

        $storage->expects($this->once())
            ->method('exists')
            ->with($request->getClientIp())
            ->willReturn(true);

        // Trigger constructor logic
        $storage->__construct([
            'connection' => [],
            'storage_table' => 'firewall_storage',
            'offenses_table' => 'firewall_offense',
        ]);

        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);
        $this->mockResult->method('fetchAssociative')->willReturn($row);

        $this->assertSame($row, $storage->get($request->getClientIp()));
    }

    /**
     * Tests reset() deletes all entries and returns true.
     */
    public function testResetClearsStorage(): void
    {
        $this->mockConnection->expects($this->once())
            ->method('delete')
            ->with('firewall_storage');

        $this->assertTrue($this->storage->reset());
    }

    /**
     * Tests exists() returns true when rowCount > 0.
     */
    public function testExistsReturnsTrue(): void
    {
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);

        $this->mockResult->method('fetchAllAssociative')->willReturn([['remote_address' => '1.2.3.4']]);

        $request = $this->getRequest('1.2.3.4');
        $this->assertTrue($this->storage->exists($request->getClientIp()));
    }

    /**
     * Tests clearExpire() runs delete query without errors.
     */
    public function testClearExpireRuns(): void
    {
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);

        $this->mockBuilder->method('delete')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();

        // ✅ Ensure executeQuery returns a valid Result mock
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);

        $this->assertTrue($this->storage->expire());
    }

    /**
     * Tests addToExpire() builds update query correctly and returns true.
     */
    public function testAddToExpireWorks(): void
    {
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);

        $this->mockBuilder->method('update')->willReturnSelf();
        $this->mockBuilder->method('set')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('andWhere')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();

        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);

        $request = $this->getRequest('1.2.3.4');
        $this->assertTrue($this->storage->addToExpire($request->getClientIp(), 300));
    }

    /**
     * Regression for #61: addToExpire() must pass the bare table name to
     * QueryBuilder::update(), not a string-concatenated alias. The pre-fix
     * code did `->update($table . ' u')` and qualified column refs as
     * `u.expire`, sidestepping DBAL's identifier-quoting path entirely.
     * Asserting on the arguments protects against a regression to the
     * alias style on a table name that needs quoting.
     */
    public function testAddToExpirePassesUnqualifiedTableAndColumns(): void
    {
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);

        $this->mockBuilder->expects($this->once())
            ->method('update')
            ->with('firewall_storage')
            ->willReturnSelf();
        $this->mockBuilder->expects($this->once())
            ->method('set')
            ->with('expire', 'expire + :expire')
            ->willReturnSelf();
        $this->mockBuilder->expects($this->once())
            ->method('where')
            ->with('remote_address = :remote_address')
            ->willReturnSelf();
        $this->mockBuilder->expects($this->once())
            ->method('andWhere')
            ->with('expire > 0')
            ->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);

        $this->assertTrue($this->storage->addToExpire('1.2.3.4', 60));
    }

    /**
     * Tests that getStorageTables() returns a valid Table with expected columns and indexes.
     */
    public function testGetStorageTablesStructure(): void
    {
        $storage = new \Kanopi\Firewall\Storage\DatabaseStorage(['connection' => [
            'dsn' => 'sqlite3:///:memory:'
        ], 'storage_table' => 'firewall_storage']);
        $table = (new \ReflectionClass($storage))
            ->getMethod('getStorageTables');
        $table->setAccessible(true);

        /** @var \Doctrine\DBAL\Schema\Table[] $tables */
        $tables = $table->invoke($storage);
        $result = $tables[array_key_first($tables)];

        $this->assertSame('firewall_storage', $result->getName());
        $this->assertTrue($result->hasColumn('remote_address'));
        $this->assertTrue($result->hasColumn('plugin'));
        $this->assertTrue($result->hasColumn('event_id'));
        $this->assertTrue($result->hasColumn('timestamp'));
        $this->assertTrue($result->hasColumn('request'));
        $this->assertTrue($result->hasColumn('expire'));
        $this->assertTrue($result->hasIndex('remote_address'));
    }

    /**
     * Tests that set() returns false when an exception occurs.
     */
    public function testSetHandlesException(): void
    {
        $request = $this->getRequest('1.2.3.4');
        // Partial mock
        $storage = $this->getMockBuilder(DatabaseStorage::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['createConnection', 'getStorageTables', 'exists'])
            ->getMock();

        // Prevent constructor from connecting, but fake it anyway
        $storage->expects($this->once())
            ->method('createConnection')
            ->willReturnCallback(function () use ($storage) {
                $this->injectProtectedProperty($storage, 'connection', $this->mockConnection);
                $this->injectProtectedProperty($storage, 'schemaManager', $this->mockSchema);
                $this->injectProtectedProperty($storage, 'config', [
                    'storage_table' => 'firewall_storage',
                    'offenses_table' => 'firewall_offense',
                ]);
            });

        $storage->expects($this->once())
            ->method('exists')
            ->with($request->getClientIp())
            ->willReturn(true);

        // Trigger constructor logic
        $storage->__construct([
            'connection' => [],
            'storage_table' => 'firewall_storage',
            'offenses_table' => 'firewall_offense',
        ]);

        // Simulate that the key exists (so it takes the update path)
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);
        $this->mockResult->method('fetchAssociative')->willReturn([]); // Simulate key exists

        // Simulate update() failing
        $this->mockConnection->method('update')->willThrowException(new \Exception('Simulated failure'));

        $result = $storage->set($request->getClientIp(), $storage->getStorageData($request, null));

        $this->assertFalse($result);
    }

    /**
     * Tests that set() returns true when an exception occurs.
     */
    public function testSetHandlesUpdate(): void
    {
        $request = $this->getRequest('1.2.3.4');

        // Partial mock
        $storage = $this->getMockBuilder(DatabaseStorage::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['createConnection', 'getStorageTables', 'exists'])
            ->getMock();

        // Prevent constructor from connecting, but fake it anyway
        $storage->expects($this->once())
            ->method('createConnection')
            ->willReturnCallback(function () use ($storage) {
                $this->injectProtectedProperty($storage, 'connection', $this->mockConnection);
                $this->injectProtectedProperty($storage, 'schemaManager', $this->mockSchema);
                $this->injectProtectedProperty($storage, 'config', [
                    'storage_table' => 'firewall_storage',
                    'offenses_table' => 'firewall_offense',
                ]);
            });

        $storage->expects($this->once())
            ->method('exists')
            ->with($request->getClientIp())
            ->willReturn(true);

        // Trigger constructor logic
        $storage->__construct([
            'connection' => [],
            'storage_table' => 'firewall_storage',
            'offenses_table' => 'firewall_offense',
        ]);

        // Simulate that the key exists (so it takes the update path)
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);
        $this->mockResult->method('fetchAllAssociative')->willReturn([[]]); // Simulate key exists

        $this->mockConnection->method('update')->willReturn(1);

        $result = $storage->set($request->getClientIp(), $storage->getStorageData($request, null));

        $this->assertTrue($result);
    }

    /**
     * Tests that delete() returns false when an exception is thrown.
     */
    public function testDeleteHandlesException(): void
    {
        $this->mockConnection->method('delete')->willThrowException(new \Exception());
        $request = $this->getRequest('1.2.3.4');
        $this->assertFalse($this->storage->delete($request->getClientIp()));
    }

    /**
     * Tests that get() returns default when an exception is thrown.
     */
    public function testGetHandlesException(): void
    {
        $this->mockConnection->method('createQueryBuilder')->willThrowException(new \Exception());
        $request = $this->getRequest('1.2.3.4');
        $result = $this->storage->get($request->getClientIp(), 'default');
        $this->assertSame('default', $result);
    }

    /**
     * Tests that reset() returns false on failure.
     */
    public function testResetHandlesException(): void
    {
        $this->mockConnection->method('delete')->willThrowException(new \Exception());
        $this->assertFalse($this->storage->reset());
    }

    /**
     * Tests that exists() returns false if exception is thrown.
     */
    public function testExistsHandlesException(): void
    {
        $this->mockConnection->method('createQueryBuilder')->willThrowException(new \Exception());
        $request = $this->getRequest('1.2.3.4');
        $this->assertFalse($this->storage->exists($request->getClientIp()));
    }

    /**
     * Tests that addToExpire() returns false if exception is thrown.
     */
    public function testAddToExpireHandlesException(): void
    {
        $this->mockConnection->method('createQueryBuilder')->willThrowException(new \Exception());
        $request = $this->getRequest('1.2.3.4');
        $this->assertFalse($this->storage->addToExpire($request->getClientIp(), 60));
    }

    /**
     * Tests that clearExpire() returns false when an exception is thrown during query execution.
     */
    public function testClearExpireHandlesException(): void
    {
        // Simulate failure during query execution
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('delete')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willThrowException(new \Exception('delete failed'));

        $this->assertFalse($this->storage->expire());
    }

    /**
     * Tests that get() returns the default value if an exception occurs during lookup.
     */
    public function testGetHandlesDefaultException(): void
    {
        // Simulate exception inside exists() check (which calls executeQuery)
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willThrowException(new \Exception('read failed'));

        $defaultValue = ['fallback' => true];

        $request = $this->getRequest('1.2.3.4');
        $result = $this->storage->get($request->getClientIp(), $defaultValue);

        $this->assertSame($defaultValue, $result);
    }

    /**
     * Tests that get() returns default if fetching data fails after confirming key exists.
     */
    public function testGetHandlesExceptionDuringFetch(): void
    {
        // Simulate key exists
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);
        $this->mockResult->method('rowCount')->willReturn(1); // Key exists
        $this->mockResult->method('fetchAssociative')->willThrowException(new \Exception('DB fetch failed'));

        $default = ['safe' => 'fallback'];
        $request = $this->getRequest('1.2.3.4');
        $this->assertSame($default, $this->storage->get($request->getClientIp(), $default));
    }

    /**
     * Test Recording Offense Throws Exception and Returns False.
     */
    public function testRecordOffenseThrowsExceptionReturnsFalse(): void
    {
        $this->mockConnection->method('insert')->willThrowException(new \Exception());
        $request = $this->getRequest('1.2.3.4');
        $this->assertFalse($this->storage->recordOffense($request->getClientIp()));
    }

    /**
     * Test Recording Offense Throws Exception and Returns False.
     */
    public function testCountOffensesThrowsExceptionReturns0(): void
    {
        $this->mockConnection->method('createQueryBuilder')->willThrowException(new \Exception());
        $request = $this->getRequest('1.2.3.4');
        $this->assertEquals(0, $this->storage->countOffenses($request->getClientIp()));
    }

    /**
     * Test Recording Offense Throws Exception and Returns False.
     */
    public function testCountOffensesThrowsExceptionReturnsCount(): void
    {
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('andWhere')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);
        $this->mockResult->method('fetchAllAssociative')->willReturn([['remote_address' => '1.2.3.4']]);

        $request = $this->getRequest('1.2.3.4');
        $this->assertEquals(1, $this->storage->countOffenses($request->getClientIp()));
    }

    /**
     * Test Get returns default if item not already found.
     */
    public function testGetExceptionThrownReturnDefault(): void
    {
        $request = $this->getRequest('1.2.3.4');

        // Partial mock
        $storage = $this->getMockBuilder(DatabaseStorage::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['createConnection', 'getStorageTables', 'exists'])
            ->getMock();

        // Prevent constructor from connecting, but fake it anyway
        $storage->expects($this->once())
            ->method('createConnection')
            ->willReturnCallback(function () use ($storage){
                $this->injectProtectedProperty($storage, 'connection', $this->mockConnection);
                $this->injectProtectedProperty($storage, 'schemaManager', $this->mockSchema);
                $this->injectProtectedProperty($storage, 'config', [
                    'storage_table' => 'firewall_storage',
                    'offenses_table' => 'firewall_offense',
                ]);
            });

        $storage->expects($this->once())
            ->method('exists')
            ->with($request->getClientIp())
            ->willReturn(true);

        // Trigger constructor logic
        $storage->__construct([
            'connection' => [],
            'storage_table' => 'firewall_storage',
            'offenses_table' => 'firewall_offense',
        ]);

        $this->mockConnection->method('createQueryBuilder')->willThrowException(new \Exception());

        $this->assertEquals('not found', $storage->get($request->getClientIp(), 'not found'));
    }

    /**
     * Tests DatabaseStorage::__construct().
     *
     * Confirms port is turned into an integer.
     */
    public function testConstructorHandlingPort(): void
    {
        $config = ['connection' => ['dsn' => 'sqlite3:///:memory:', 'port' => '3306']];
        $plugin = new class ($config) extends DatabaseStorage
        {
            public function getConfig(): array
            {
                return $this->config;
            }
        };
        $this->assertIsInt($plugin->getConfig()['connection']['port']);
    }

    /**
     * Point the mocked query builder at a fixed set of rows.
     *
     * @param array<int, array<string, mixed>> $rows
     */
    private function stubRows(array $rows): void
    {
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('andWhere')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);
        $this->mockResult->method('fetchAllAssociative')->willReturn($rows);
    }

    /**
     * #26: CIDR containment has no portable SQL form across MySQL, PostgreSQL
     * and SQLite, so candidate rows are matched in PHP. Rows outside the range
     * must be filtered out rather than returned.
     */
    public function testFindFiltersCandidateRowsByCidr(): void
    {
        $this->stubRows([
            ['remote_address' => '203.0.113.5', 'expire' => 0],
            ['remote_address' => '203.0.113.99', 'expire' => 0],
            ['remote_address' => '8.8.8.8', 'expire' => 0],
        ]);

        $found = $this->storage->find('203.0.113.0/24');

        $this->assertEqualsCanonicalizing(['203.0.113.5', '203.0.113.99'], array_keys($found));
    }

    /**
     * #26: a malformed pattern must not reach the database at all, and must
     * match nothing — the caller's next move is usually to delete the result.
     */
    public function testFindRejectsMalformedPatternWithoutQuerying(): void
    {
        $this->mockConnection->expects($this->never())->method('createQueryBuilder');

        $this->assertSame([], $this->storage->find('not-a-range'));
    }

    /**
     * #26: a failed query reports nothing found rather than surfacing a
     * partial result an operator might then delete against.
     */
    public function testFindReturnsEmptyOnQueryFailure(): void
    {
        $this->mockConnection->method('createQueryBuilder')->willThrowException(new \Exception('boom'));

        $this->assertSame([], $this->storage->find('203.0.113.0/24'));
    }

    /**
     * #26: deleting by range removes each matched address, and clears its
     * offense history alongside so `blocking_escalation` cannot re-escalate an
     * address an operator just un-blocked.
     */
    public function testDeleteMatchingRemovesBlocksAndOffenses(): void
    {
        $this->stubRows([
            ['remote_address' => '203.0.113.5'],
            ['remote_address' => '203.0.113.99'],
            ['remote_address' => '8.8.8.8'],
        ]);

        $deletes = [];
        $this->mockConnection->method('delete')
            ->willReturnCallback(function (string $table, array $criteria) use (&$deletes): int {
                $deletes[] = $table . ':' . $criteria['remote_address'];
                return 1;
            });

        $deleted = $this->storage->deleteMatching(['203.0.113.0/24']);

        $this->assertSame(2, $deleted);
        $this->assertContains('firewall_storage:203.0.113.5', $deletes);
        $this->assertContains('firewall_storage:203.0.113.99', $deletes);
        $this->assertContains('firewall_offense:203.0.113.5', $deletes);
        // Outside the range, so untouched in both tables.
        $this->assertNotContains('firewall_storage:8.8.8.8', $deletes);
        $this->assertNotContains('firewall_offense:8.8.8.8', $deletes);
    }

    /**
     * #26: a bare address is an indexed equality lookup, so it must not
     * trigger the full-table enumeration that only CIDR ranges require.
     */
    public function testDeleteMatchingByExactAddressSkipsEnumeration(): void
    {
        $this->mockConnection->expects($this->never())->method('createQueryBuilder');
        $this->mockConnection->method('delete')->willReturn(1);

        $this->assertSame(1, $this->storage->deleteMatching(['203.0.113.5']));
    }

    /**
     * #26: one bad range must not strand the good ones.
     */
    public function testDeleteMatchingSkipsMalformedPatterns(): void
    {
        $this->mockConnection->method('delete')->willReturn(1);

        $this->assertSame(0, $this->storage->deleteMatching(['garbage', '', '203.0.113.0/33']));
    }
}
