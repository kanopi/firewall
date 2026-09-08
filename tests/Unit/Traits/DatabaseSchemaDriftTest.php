<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Traits;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Schema\Index;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Type;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\RateLimitStorage\DatabaseRateLimitStorage;
use Kanopi\Firewall\Storage\DatabaseStorage;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Reporting and applying schema drift from the storage classes (#217).
 *
 * The case throughout is the real one: a rate limit table created before
 * v2.19.0 added the `(rule, timestamp)` index, which that release's notes ask
 * the operator to add by hand.
 */
class DatabaseSchemaDriftTest extends AbstractTestCase
{
    private string $path;

    protected function setUp(): void
    {
        parent::setUp();

        LoggingFactory::setLogger(LoggingFactory::create([
            ['class' => TestLogHandler::class],
        ]));

        $this->path = tempnam(sys_get_temp_dir(), 'fwdrift') . '.sqlite';
        $this->forgetStatics();
    }

    protected function tearDown(): void
    {
        $this->forgetStatics();
        @unlink($this->path);
        parent::tearDown();
    }

    /**
     * Both statics outlive an instance, so tests would otherwise answer for
     * each other. Reflected on each using class, since a static trait property
     * belongs to the class rather than the trait.
     */
    private function forgetStatics(): void
    {
        foreach ([DatabaseStorage::class, DatabaseRateLimitStorage::class] as $class) {
            foreach (['tablesKnownToExist', 'schemasChecked'] as $name) {
                $property = new \ReflectionProperty($class, $name);
                $property->setAccessible(true);
                $property->setValue(null, []);
            }
        }
    }

    private function config(): array
    {
        return ['connection' => ['driver' => 'pdo_sqlite', 'path' => $this->path]];
    }

    private function handler(): TestLogHandler
    {
        $handlers = LoggingFactory::logger()->getHandlers();

        return $handlers[0];
    }

    /**
     * A rate limit table as v2.19.0 left it: no `(rule, timestamp)` index.
     */
    private function createLegacyRateLimitTable(): void
    {
        $connection = DriverManager::getConnection($this->config()['connection']);
        $connection->createSchemaManager()->createTable(new Table('firewall_rate_limit_storage', [
            new Column('id', Type::getType('integer'), ['autoincrement' => true, 'unsigned' => true]),
            new Column('rule', Type::getType('string'), ['length' => 255]),
            new Column('timestamp', Type::getType('integer'), ['unsigned' => true, 'length' => 10, 'default' => 0]),
        ], [new Index('PRIMARY', ['id'], true, true)]));
        $connection->executeStatement("INSERT INTO firewall_rate_limit_storage (rule, timestamp) VALUES ('r', 1)");
    }

    /**
     * An out-of-date table says so at startup, where an operator will see it.
     *
     * Warning rather than error: everything the table is asked to do today it
     * still does. A missing index makes a query slow, not wrong.
     */
    public function testAnOutOfDateTableWarnsOnStartup(): void
    {
        $this->createLegacyRateLimitTable();

        new DatabaseRateLimitStorage($this->config());

        $this->assertTrue($this->handler()->hasWarningContaining('behind the schema this release declares'));
    }

    /**
     * A table that matches the declaration says nothing.
     */
    public function testACurrentTableIsSilent(): void
    {
        new DatabaseRateLimitStorage($this->config());
        $this->forgetStatics();
        new DatabaseRateLimitStorage($this->config());

        $this->assertFalse($this->handler()->hasWarningContaining('behind the schema'));
    }

    /**
     * The warning is not repeated for the life of the process.
     *
     * An operator who cannot run the migration -- a read-only database user,
     * a DBA-gated change -- should not be told once a minute by every worker.
     */
    public function testTheWarningIsNotRepeatedWithinTheProcess(): void
    {
        $this->createLegacyRateLimitTable();

        new DatabaseRateLimitStorage($this->config());
        new DatabaseRateLimitStorage($this->config());
        new DatabaseRateLimitStorage($this->config());

        $this->assertSame(1, $this->countWarnings('behind the schema this release declares'));
    }

    /**
     * The drift check runs once per process, not once per memo window.
     *
     * The existence check is memoised for 60 seconds because a table can be
     * dropped underneath a running worker. Drift cannot appear that way: the
     * declaration is fixed in the code that is running, and the only thing
     * that changes the live table is a migration, which brings it closer. So
     * the introspection -- 0.48 ms against 0.02 ms for the existence check --
     * is worth paying exactly once.
     */
    public function testTheDriftCheckIsNotRepeatedWhenTheExistenceMemoExpires(): void
    {
        $this->createLegacyRateLimitTable();
        new DatabaseRateLimitStorage($this->config());

        // Age the existence memo past its window, leaving the drift flag set.
        $memo = new \ReflectionProperty(DatabaseRateLimitStorage::class, 'tablesKnownToExist');
        $memo->setAccessible(true);
        $memo->setValue(null, array_map(static fn(): int => 0, $memo->getValue()));

        new DatabaseRateLimitStorage($this->config());

        $this->assertSame(1, $this->countWarnings('behind the schema this release declares'));
    }

    /**
     * The pending changes are reportable, which is what --dry-run prints.
     */
    public function testPendingSchemaChangesReportsTheMissingIndex(): void
    {
        $this->createLegacyRateLimitTable();

        $pending = (new DatabaseRateLimitStorage($this->config()))->pendingSchemaChanges();

        $this->assertSame(
            [['index', 'firewall_rate_limit_storage_rule_window_idx']],
            array_map(static fn(array $c): array => [$c['kind'], $c['name']], $pending)
        );
    }

    /**
     * Migrating adds the index and keeps the rows.
     */
    public function testMigratingAddsTheIndexWithoutLosingRows(): void
    {
        $this->createLegacyRateLimitTable();
        $storage = new DatabaseRateLimitStorage($this->config());

        $results = $storage->migrateSchema();

        $this->assertSame([true], array_column($results, 'applied'));
        $this->assertSame([], $storage->pendingSchemaChanges());

        $connection = DriverManager::getConnection($this->config()['connection']);
        $this->assertSame(1, (int) $connection->fetchOne('SELECT COUNT(*) FROM firewall_rate_limit_storage'));
    }

    /**
     * A migrated table stops warning in the same process.
     */
    public function testAMigratedTableStopsWarningInTheSameProcess(): void
    {
        $this->createLegacyRateLimitTable();
        (new DatabaseRateLimitStorage($this->config()))->migrateSchema();

        $before = $this->countWarnings('behind the schema this release declares');
        new DatabaseRateLimitStorage($this->config());

        $this->assertSame($before, $this->countWarnings('behind the schema this release declares'));
    }

    /**
     * A class declaring several tables answers for all of them.
     */
    public function testAllDeclaredTablesAreCovered(): void
    {
        $storage = new DatabaseStorage($this->config());

        $this->assertSame([], $storage->pendingSchemaChanges());

        $connection = DriverManager::getConnection($this->config()['connection']);
        $tables = $connection->createSchemaManager()->listTableNames();

        $this->assertContains('firewall_storage', $tables);
        $this->assertContains('firewall_offenses', $tables);
    }

    /**
     * An in-memory database has nothing to be behind.
     *
     * Its tables were created moments ago from this same declaration, and it
     * is the one connection the memo key deliberately refuses to identify.
     */
    public function testAnInMemoryDatabaseIsNotChecked(): void
    {
        new DatabaseRateLimitStorage(['connection' => ['driver' => 'pdo_sqlite', 'memory' => true]]);

        $this->assertFalse($this->handler()->hasWarningContaining('behind the schema'));
    }

    /**
     * A schema that cannot be introspected is noted and stepped over.
     *
     * Reading `information_schema` needs a privilege that reading and writing
     * the rows does not, so a database user locked down to exactly what the
     * firewall needs at runtime can fail here. Comparing the schema is not the
     * job; enforcing the rules is, and it must carry on.
     */
    public function testASchemaThatCannotBeIntrospectedIsNotFatal(): void
    {
        $storage = new DatabaseRateLimitStorage($this->config());
        $this->handler()->records = [];

        // Introspection refused, existence still answerable -- the shape a
        // restricted grant produces.
        $manager = $this->createMock(\Doctrine\DBAL\Schema\AbstractSchemaManager::class);
        $manager->method('tablesExist')->willReturn(true);
        $manager->method('introspectTable')->willThrowException(
            new \RuntimeException('SELECT command denied to user for table information_schema.columns')
        );

        $swap = new \ReflectionProperty($storage, 'schemaManager');
        $swap->setAccessible(true);
        $swap->setValue($storage, $manager);

        $this->forgetStatics();

        $report = new \ReflectionMethod($storage, 'reportSchemaDrift');
        $report->setAccessible(true);

        $tables = new \ReflectionMethod($storage, 'getStorageTables');
        $tables->setAccessible(true);

        foreach ($tables->invoke($storage) as $table) {
            $report->invoke($storage, $table);
        }

        $this->assertFalse(
            $this->handler()->hasWarningContaining('behind the schema'),
            'A schema it could not read is not a schema it may call out of date'
        );
    }

    /**
     * How many warnings carried this message, where the handler only answers
     * whether any did.
     */
    private function countWarnings(string $needle): int
    {
        $count = 0;

        foreach ($this->handler()->records as $record) {
            if ($record->level->value >= 300 && $record->level->value < 400 && str_contains((string) $record->message, $needle)) {
                $count++;
            }
        }

        return $count;
    }
}
