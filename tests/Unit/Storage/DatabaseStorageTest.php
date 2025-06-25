<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Query\QueryBuilder;
use Doctrine\DBAL\Result;
use Doctrine\DBAL\Schema\AbstractSchemaManager;
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
            ->onlyMethods(['createConnection', 'getStorageTable'])
            ->getMock();

        // Prevent constructor from connecting, but fake it anyway
        $this->storage->expects($this->once())
            ->method('createConnection')
            ->willReturnCallback(function () {
                $this->injectProtectedProperty($this->storage, 'connection', $this->mockConnection);
                $this->injectProtectedProperty($this->storage, 'schemaManager', $this->mockSchema);
                $this->injectProtectedProperty($this->storage, 'config', [
                    'storage_table' => 'firewall_storage',
                ]);
            });

        // Trigger constructor logic
        $this->storage->__construct([
            'connection' => [],
            'storage_table' => 'firewall_storage',
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

        $this->mockResult->method('rowCount')->willReturn(0);

        $result = $this->storage->set('1.2.3.4', [
            'plugin' => 'TestPlugin',
            'event_id' => 'EVT',
            'request' => ['foo' => 'bar'],
            'blocked' => 'now',
        ]);

        $this->assertTrue($result);
    }

    /**
     * Tests delete() succeeds and returns true.
     */
    public function testDelete(): void
    {
        $this->mockConnection->expects($this->once())
            ->method('delete')
            ->with('firewall_storage', ['remote_address' => '1.2.3.4']);

        $this->assertTrue($this->storage->delete('1.2.3.4'));
    }

    /**
     * Tests get() returns a row when key exists.
     */
    public function testGetReturnsDataIfExists(): void
    {
        $row = ['remote_address' => '1.2.3.4', 'plugin' => 'TestPlugin'];

        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);

        $this->mockResult->method('fetchAssociative')->willReturn($row);
        $this->mockResult->method('rowCount')->willReturn(1);

        $this->assertSame($row, $this->storage->get('1.2.3.4'));
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

        $this->mockResult->method('rowCount')->willReturn(1);

        $this->assertTrue($this->storage->exists('1.2.3.4'));
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

        $this->assertTrue($this->storage->clearExpire());
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

        // ✅ Ensure executeQuery returns a valid Result mock
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);

        $this->assertTrue($this->storage->addToExpire('1.2.3.4', 300));
    }

    /**
     * Tests that getStorageTable() returns a valid Table with expected columns and indexes.
     */
    public function testGetStorageTableStructure(): void
    {
        $storage = new \Kanopi\Firewall\Storage\DatabaseStorage(['connection' => [
            'dsn' => 'sqlite3:///:memory:'
        ], 'storage_table' => 'firewall_storage']);
        $table = (new \ReflectionClass($storage))
            ->getMethod('getStorageTable');
        $table->setAccessible(true);

        /** @var \Doctrine\DBAL\Schema\Table $result */
        $result = $table->invoke($storage);

        $this->assertSame('firewall_storage', $result->getName());
        $this->assertTrue($result->hasColumn('remote_address'));
        $this->assertTrue($result->hasColumn('plugin'));
        $this->assertTrue($result->hasColumn('event_id'));
        $this->assertTrue($result->hasColumn('blocked'));
        $this->assertTrue($result->hasColumn('request'));
        $this->assertTrue($result->hasColumn('expire'));
        $this->assertTrue($result->hasIndex('remote_address'));
    }

    /**
     * Tests that set() returns false when an exception occurs.
     */
    public function testSetHandlesException(): void
    {
        // Simulate that the key exists (so it takes the update path)
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);
        $this->mockResult->method('rowCount')->willReturn(1); // Simulate key exists

        // Simulate update() failing
        $this->mockConnection->method('update')->willThrowException(new \Exception('Simulated failure'));

        $result = $this->storage->set('1.2.3.4', [
            'plugin' => 'TestPlugin',
            'event_id' => 'TestEvent',
            'request' => ['example' => 'data'],
            'blocked' => 'now',
        ]);

        $this->assertFalse($result);
    }

    /**
     * Tests that delete() returns false when an exception is thrown.
     */
    public function testDeleteHandlesException(): void
    {
        $this->mockConnection->method('delete')->willThrowException(new \Exception());
        $this->assertFalse($this->storage->delete('x.x.x.x'));
    }

    /**
     * Tests that get() returns default when an exception is thrown.
     */
    public function testGetHandlesException(): void
    {
        $this->mockConnection->method('createQueryBuilder')->willThrowException(new \Exception());
        $result = $this->storage->get('1.2.3.4', 'default');
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
        $this->assertFalse($this->storage->exists('1.2.3.4'));
    }

    /**
     * Tests that addToExpire() returns false if exception is thrown.
     */
    public function testAddToExpireHandlesException(): void
    {
        $this->mockConnection->method('createQueryBuilder')->willThrowException(new \Exception());
        $this->assertFalse($this->storage->addToExpire('1.2.3.4', 60));
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

        $this->assertFalse($this->storage->clearExpire());
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
        $result = $this->storage->get('nonexistent-key', $defaultValue);

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
        $this->assertSame($default, $this->storage->get('1.2.3.4', $default));
    }
}
