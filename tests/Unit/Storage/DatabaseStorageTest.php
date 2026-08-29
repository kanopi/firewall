<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Query\QueryBuilder;
use Doctrine\DBAL\Result;
use Doctrine\DBAL\Schema\AbstractSchemaManager;
use Kanopi\Firewall\Exception\StorageConnectionException;
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
     * Regression: `set()` is the storage interface's general key/value write, not
     * only the block-record writer.
     *
     * `Firewall::consumeSingleUseSolution()` stores `['consumed_at' => ...]` through
     * it to make a solved challenge single-use. Reading `request` and `timestamp`
     * unconditionally emitted two PHP warnings — which land in the challenge
     * endpoint's response ahead of its JSON body, so the browser reports
     * "Verification failed" on a challenge that was actually passed — and left
     * `plugin` unset, which is NOT NULL with no default, so the insert failed and the
     * replay guard recorded nothing at all.
     */
    public function testSetAcceptsAValueThatIsNotABlockRecord(): void
    {
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
        $this->mockResult->method('fetchAllAssociative')->willReturn([]);

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

        // Exactly what the challenge replay guard writes.
        $key = 'fw_challenge_solution:' . hash('sha256', 'solution');

        $before = time();
        $result = $this->storage->set($key, ['consumed_at' => 1_700_000_000], 60);

        $this->assertTrue($result, 'A non-block-record write must succeed');
        $this->assertIsArray($captured);

        // Every NOT NULL column carries a usable value rather than being absent.
        $this->assertSame('', $captured['plugin']);
        $this->assertSame('', $captured['event_id']);
        $this->assertSame('null', $captured['request']);
        $this->assertGreaterThanOrEqual($before, $captured['timestamp']);
    }

    /**
     * Regression: a solution record must not be filed as an offense.
     *
     * The offenses table drives repeat-offender escalation and is never pruned, so
     * recording one per consumed challenge solution would grow it without bound under
     * keys that are hashes rather than addresses.
     */
    public function testSetDoesNotRecordAnOffenseForANonBlockRecord(): void
    {
        $tables = [];
        $this->mockConnection->method('insert')
            ->willReturnCallback(function (string $table) use (&$tables): int {
                $tables[] = $table;

                return 1;
            });
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);

        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);
        $this->mockResult->method('fetchAllAssociative')->willReturn([]);

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

        $this->storage->set('fw_challenge_solution:abc', ['consumed_at' => time()], 60);
        $this->assertNotContains('firewall_offense', $tables);

        // ...while a real block still records one, which is the behaviour that must
        // not regress in the other direction.
        $tables = [];
        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('TestPlugin');
        $request = $this->getRequest('1.2.3.4');

        $this->storage->set($request->getClientIp(), $this->storage->getStorageData($request, $plugin));
        $this->assertContains('firewall_offense', $tables);
    }

    /**
     * Regression: what `set()` encoded, the read path must decode.
     *
     * `set()` JSON-encodes `request` so it fits a text column, and nothing decoded
     * it again — so an array went in and a string came back. `request` is the record
     * of *why* a client was blocked (method, path, URI, query, headers), and every
     * reader that tests `is_array($value['request'])` therefore saw nothing on
     * database storage while working correctly on FileStorage and InMemoryStorage.
     */
    public function testGetDecodesTheRequestColumnBackToAnArray(): void
    {
        $stored = [
            'remote_address' => '1.2.3.4',
            'plugin' => 'User Agent',
            'event_id' => 'ABC123',
            'timestamp' => 1_700_000_000,
            'request' => json_encode(['method' => 'GET', 'path' => '/wp-login.php']),
            'expire' => 0,
            'metadata' => '{}',
        ];

        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('andWhere')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);

        // `exists()` uses fetchAllAssociative; `get()` uses fetchAssociative.
        $this->mockResult->method('fetchAllAssociative')->willReturn([$stored]);
        $this->mockResult->method('fetchAssociative')->willReturn($stored);

        $record = $this->storage->get('1.2.3.4');

        $this->assertIsArray($record);
        $this->assertIsArray($record['request'], 'request must come back as an array, not JSON text');
        $this->assertSame('/wp-login.php', $record['request']['path']);
        $this->assertSame('GET', $record['request']['method']);
    }

    /**
     * Regression: the same decode must apply to the rows `find()` wraps, which is
     * what the admin block list is built from.
     */
    public function testFindDecodesTheRequestColumnBackToAnArray(): void
    {
        $stored = [
            'remote_address' => '1.2.3.4',
            'plugin' => 'Rate Limit',
            'event_id' => 'DEF456',
            'timestamp' => 1_700_000_000,
            'request' => json_encode(['method' => 'POST', 'path' => '/xmlrpc.php']),
            'expire' => 0,
            'metadata' => '{}',
        ];

        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('andWhere')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);
        $this->mockResult->method('fetchAllAssociative')->willReturn([$stored]);

        $matches = $this->storage->find('1.2.3.4');

        $this->assertArrayHasKey('1.2.3.4', $matches);
        $value = $matches['1.2.3.4']['value'];
        $this->assertIsArray($value['request'], 'request must come back as an array, not JSON text');
        $this->assertSame('/xmlrpc.php', $value['request']['path']);
    }

    /**
     * A row holding something that is not JSON — written by hand, or before the
     * decode existed — is left as it is rather than failing the read.
     */
    public function testGetLeavesAnUndecodableRequestColumnAlone(): void
    {
        $stored = [
            'remote_address' => '1.2.3.4',
            'plugin' => 'Manual',
            'request' => 'not json at all',
            'timestamp' => 1_700_000_000,
            'expire' => 0,
        ];

        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('andWhere')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);
        $this->mockResult->method('fetchAllAssociative')->willReturn([$stored]);
        $this->mockResult->method('fetchAssociative')->willReturn($stored);

        $record = $this->storage->get('1.2.3.4');

        $this->assertSame('not json at all', $record['request']);
    }

    /**
     * Regression: a value with no column of its own must still read back.
     *
     * `enforceTableData()` drops keys the schema does not model, so they survive
     * only inside `metadata`, which `set()` encodes before that stripping happens.
     * `reason` is the one that matters — it is what an administrator typed to explain
     * a manual block, so it is the whole answer to "why is this client blocked", and
     * it was written and then never readable again.
     */
    public function testGetRestoresFieldsThatHaveNoColumnFromMetadata(): void
    {
        $stored = [
            'remote_address' => '1.2.3.4',
            'plugin' => 'Manual',
            'event_id' => 'GHI789',
            'timestamp' => 1_700_000_000,
            'request' => json_encode(['method' => 'GET', 'path' => '/']),
            'expire' => 0,
            // As `set()` builds it: the full value, including what the row cannot hold.
            'metadata' => json_encode([
                'plugin' => 'Manual',
                'reason' => 'Reported by the client',
                'request' => '{"method":"GET","path":"\/"}',
            ]),
        ];

        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
        $this->mockBuilder->method('select')->willReturnSelf();
        $this->mockBuilder->method('from')->willReturnSelf();
        $this->mockBuilder->method('where')->willReturnSelf();
        $this->mockBuilder->method('andWhere')->willReturnSelf();
        $this->mockBuilder->method('setParameter')->willReturnSelf();
        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);
        $this->mockResult->method('fetchAllAssociative')->willReturn([$stored]);
        $this->mockResult->method('fetchAssociative')->willReturn($stored);

        $record = $this->storage->get('1.2.3.4');

        $this->assertSame('Reported by the client', $record['reason']);

        // The columns stay authoritative: `request` must be the decoded column, not
        // the encoded copy metadata also carries.
        $this->assertIsArray($record['request']);
        $this->assertSame('/', $record['request']['path']);
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
     * Construction fails loudly when the database is unreachable (#144).
     *
     * The constructor used to log the connection failure, then log
     * `Database storage initialized`, and hand back an object whose first query
     * died on an uninitialized `$schemaManager`. `FileStorage` already refuses
     * a backing file it cannot use; this now matches.
     */
    public function testConstructorThrowsWhenTheDatabaseIsUnreachable(): void
    {
        $this->expectException(StorageConnectionException::class);
        $this->expectExceptionMessage('driver=nope');

        new DatabaseStorage(['connection' => ['driver' => 'nope']]);
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

    /**
     * An exact address is looked up with a WHERE clause, not a table scan.
     *
     * The distinction is the point of the branch: `remote_address` carries a
     * unique index, so a single address is one row fetch. Only a CIDR range
     * has to pull every candidate back and match in PHP, because CIDR
     * containment is not portable SQL across MySQL, PostgreSQL and SQLite.
     * Losing the narrowing would turn every exact lookup into a full scan.
     */
    public function testFindByExactAddressNarrowsInSql(): void
    {
        $this->stubQueryBuilderChain([]);

        $this->mockBuilder->expects($this->once())
            ->method('andWhere')
            ->with('remote_address = :remote_address')
            ->willReturnSelf();

        $this->assertSame([], $this->storage->find('203.0.113.7'));
    }

    /**
     * The counterpart: a CIDR range must NOT narrow in SQL.
     *
     * Pinning both directions is what makes the pair meaningful — asserting
     * only that an exact address narrows would still pass if the code narrowed
     * unconditionally, which would make every range query return nothing.
     */
    public function testFindByCidrRangeDoesNotNarrowInSql(): void
    {
        $this->stubQueryBuilderChain([]);

        $this->mockBuilder->expects($this->never())->method('andWhere');

        $this->assertSame([], $this->storage->find('203.0.113.0/24'));
    }

    /**
     * A row with no address is skipped rather than keyed on an empty string.
     *
     * The column is NOT NULL in the schema this creates, but the table may
     * predate it or have been written to by something else, and an empty key
     * in the result map would be matched by nothing and confuse the caller.
     */
    public function testFindSkipsRowsWithAnEmptyAddress(): void
    {
        // A matching row alongside them, so an empty result cannot pass by
        // accident — the point is that the good row survives and the blank
        // ones do not.
        $this->stubQueryBuilderChain([
            ['remote_address' => '', 'expire' => 0, 'value' => '[]'],
            ['remote_address' => null, 'expire' => 0, 'value' => '[]'],
            ['remote_address' => '203.0.113.7', 'expire' => 0, 'value' => '[]'],
        ]);

        $matches = $this->storage->find('203.0.113.0/24');

        $this->assertSame(['203.0.113.7'], array_keys($matches));
    }

    /**
     * A failed pattern query is logged and skipped, not fatal.
     *
     * `deleteMatching()` takes several patterns. One unusable pattern — a
     * table that vanished mid-run, a lost connection — must not abandon the
     * others, or an operator un-blocking a list of addresses would silently
     * get a partial result.
     */
    public function testDeleteMatchingContinuesWhenAPatternQueryFails(): void
    {
        $this->mockConnection->method('createQueryBuilder')
            ->willThrowException(new \RuntimeException('connection lost'));

        $this->assertSame(0, $this->storage->deleteMatching(['203.0.113.0/24']));
    }

    /**
     * A delete that throws is logged and skipped, and the count stays honest.
     *
     * Reporting a deletion that did not happen would tell an operator an
     * address was un-blocked while it is still blocked.
     */
    public function testDeleteMatchingReportsNothingWhenTheDeleteFails(): void
    {
        $this->stubQueryBuilderChain([['remote_address' => '203.0.113.7']]);
        $this->mockConnection->method('delete')
            ->willThrowException(new \RuntimeException('table is read-only'));

        $this->assertSame(0, $this->storage->deleteMatching(['203.0.113.0/24']));
    }

    /**
     * Failing to clear offense history warns but keeps the deletion.
     *
     * Deliberately not an error: the block itself is gone, which is what the
     * operator asked for. The leftover history matters because
     * `blocking_escalation` would escalate this address straight back to a
     * longer ban on its next offence — so it has to be visible — but undoing
     * the successful delete would be worse.
     */
    public function testDeleteMatchingWarnsWhenOffenseHistoryCannotBeCleared(): void
    {
        $this->stubQueryBuilderChain([['remote_address' => '203.0.113.7']]);

        // First delete (the block) succeeds; the second (offenses) throws.
        $this->mockConnection->method('delete')
            ->willReturnCallback(function (string $table): int {
                if ($table === 'firewall_offense') {
                    throw new \RuntimeException('offense table is gone');
                }

                return 1;
            });

        $this->assertSame(
            1,
            $this->storage->deleteMatching(['203.0.113.0/24']),
            'The block was removed, so it still counts as deleted.'
        );
    }

    /**
     * Stub the whole QueryBuilder chain so `$builder` stays this mock.
     *
     * Every fluent method has to be stubbed, not just the ones a test cares
     * about: PHPUnit auto-generates a return value for a typed return, so an
     * unstubbed `where()` hands back a *different* QueryBuilder mock and the
     * assertions are made against an object the code under test never used.
     * That failure mode is silent — the test passes while exercising nothing.
     *
     * @param array<int, array<string, mixed>> $rows
     *   Rows the query should return.
     */
    private function stubQueryBuilderChain(array $rows): void
    {
        foreach (['select', 'from', 'where', 'andWhere', 'setParameter'] as $fluent) {
            $this->mockBuilder->method($fluent)->willReturnSelf();
        }

        $this->mockBuilder->method('executeQuery')->willReturn($this->mockResult);
        $this->mockResult->method('fetchAllAssociative')->willReturn($rows);
        $this->mockConnection->method('createQueryBuilder')->willReturn($this->mockBuilder);
    }
}
