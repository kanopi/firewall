<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\AbstractSchemaManager;
use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Schema\Index;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Type;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\SchemaMigrator;

/**
 * Additive schema migration (#217).
 *
 * Against a real SQLite file rather than a mocked schema manager. The whole
 * subject here is what a database platform actually does with a request to add
 * something -- asked through a table diff, SQLite answers "rebuild the table",
 * which no mock would have told us.
 */
class SchemaMigratorTest extends AbstractTestCase
{
    private string $path;

    private Connection $connection;

    /** @var AbstractSchemaManager<\Doctrine\DBAL\Platforms\AbstractPlatform> */
    private AbstractSchemaManager $schemaManager;

    protected function setUp(): void
    {
        parent::setUp();
        $this->path = tempnam(sys_get_temp_dir(), 'fwschema') . '.sqlite';
        $this->connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'path' => $this->path]);
        $this->schemaManager = $this->connection->createSchemaManager();
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
        parent::tearDown();
    }

    private function migrator(): SchemaMigrator
    {
        return new SchemaMigrator($this->connection, $this->schemaManager);
    }

    /**
     * The table as an installation created before the new column and index has it.
     */
    private function createLegacyTable(string $name = 'firewall_rate_limit_storage'): void
    {
        $this->schemaManager->createTable(new Table($name, [
            new Column('id', Type::getType('integer'), ['autoincrement' => true, 'unsigned' => true]),
            new Column('rule', Type::getType('string'), ['length' => 255]),
            new Column('timestamp', Type::getType('integer'), ['unsigned' => true, 'default' => 0]),
        ], [new Index('PRIMARY', ['id'], true, true)]));
    }

    /**
     * The table as this release declares it.
     */
    private function declaredTable(string $name = 'firewall_rate_limit_storage', bool $withRefusable = false): Table
    {
        $columns = [
            new Column('id', Type::getType('integer'), ['autoincrement' => true, 'unsigned' => true]),
            new Column('rule', Type::getType('string'), ['length' => 255]),
            new Column('timestamp', Type::getType('integer'), ['unsigned' => true, 'default' => 0]),
            new Column('note', Type::getType('string'), ['length' => 64, 'default' => '']),
        ];

        if ($withRefusable) {
            // NOT NULL with no default, which is what a text column declared
            // without one amounts to.
            $columns[] = new Column('required', Type::getType('text'));
        }

        return new Table($name, $columns, [
            new Index('PRIMARY', ['id'], true, true),
            new Index($name . '_rule_window_idx', ['rule', 'timestamp']),
        ]);
    }

    /**
     * A table that does not exist is not behind anything.
     *
     * Creating it is `DatabaseTrait::createTable()`'s job, from this same
     * declaration, so there is nothing to migrate.
     */
    public function testAnAbsentTableHasNothingPending(): void
    {
        $this->assertSame([], $this->migrator()->pending($this->declaredTable()));
    }

    /**
     * A table just created from a declaration does not report drift against it.
     *
     * The property the whole feature rests on. Introspecting a table back
     * reports a platform collation the declaration never set, so every string
     * column compares as "changed" on a table with no drift at all -- which is
     * why only the existence of a column or index is ever asked about.
     */
    public function testAFreshlyCreatedTableReportsNoDrift(): void
    {
        $declared = $this->declaredTable();
        $this->schemaManager->createTable($declared);

        $this->assertSame([], $this->migrator()->pending($declared));
    }

    /**
     * A missing column and a missing index are both found.
     */
    public function testAMissingColumnAndIndexAreReported(): void
    {
        $this->createLegacyTable();

        $pending = $this->migrator()->pending($this->declaredTable());

        $this->assertSame(
            [['column', 'note'], ['index', 'firewall_rate_limit_storage_rule_window_idx']],
            array_map(static fn(array $c): array => [$c['kind'], $c['name']], $pending)
        );
        $this->assertTrue($pending[0]['safe']);
        $this->assertTrue($pending[1]['safe']);
    }

    /**
     * An index is added with CREATE INDEX, never a table rebuild.
     *
     * Asked to add an index through a table diff, the SQLite platform emits
     * CREATE TEMPORARY TABLE / DROP TABLE / CREATE TABLE / INSERT ... SELECT.
     * That is destructive, and it rebuilds from the table as introspected --
     * so run after a column was added, it silently reverted that column.
     */
    public function testAnIndexIsAddedWithoutRebuildingTheTable(): void
    {
        $this->createLegacyTable();

        $pending = $this->migrator()->pending($this->declaredTable());
        $indexSql = $pending[1]['sql'];

        $this->assertCount(1, $indexSql, 'One statement, not a rebuild sequence');
        $this->assertStringStartsWith('CREATE INDEX', $indexSql[0]);
        $this->assertStringNotContainsStringIgnoringCase('DROP TABLE', $indexSql[0]);
    }

    /**
     * A NOT NULL column with no default is refused rather than attempted.
     *
     * SQLite and PostgreSQL both reject adding one to a table with rows, and
     * MySQL invents a value instead, which is worse.
     */
    public function testANotNullColumnWithNoDefaultIsRefused(): void
    {
        $this->createLegacyTable();

        $pending = $this->migrator()->pending($this->declaredTable(withRefusable: true));
        $refused = array_values(array_filter($pending, static fn(array $c): bool => !$c['safe']));

        $this->assertCount(1, $refused);
        $this->assertSame('required', $refused[0]['name']);
        $this->assertStringContainsString('NOT NULL with no default', $refused[0]['reason']);
    }

    /**
     * It is refused on an empty table too, where it would have worked.
     *
     * A migration whose outcome depends on whether the table happens to have
     * rows yet passes in staging and fails in production.
     */
    public function testTheRefusalDoesNotDependOnTheTableBeingPopulated(): void
    {
        $this->createLegacyTable();
        $this->assertSame(0, (int) $this->connection->fetchOne('SELECT COUNT(*) FROM firewall_rate_limit_storage'));

        $pending = $this->migrator()->pending($this->declaredTable(withRefusable: true));

        $this->assertContains(false, array_column($pending, 'safe'));
    }

    /**
     * Applying adds what is missing and keeps every row.
     */
    public function testApplyingAddsWhatIsMissingAndKeepsTheData(): void
    {
        $this->createLegacyTable();
        $this->connection->executeStatement("INSERT INTO firewall_rate_limit_storage (rule, timestamp) VALUES ('a', 1), ('b', 2)");

        $results = $this->migrator()->apply($this->declaredTable());

        $this->assertSame([true, true], array_column($results, 'applied'));
        $this->assertSame(2, (int) $this->connection->fetchOne('SELECT COUNT(*) FROM firewall_rate_limit_storage'));
        $this->assertContains('note', array_map(
            static fn(Column $c): string => $c->getName(),
            $this->schemaManager->listTableColumns('firewall_rate_limit_storage')
        ));
        $this->assertContains('firewall_rate_limit_storage_rule_window_idx', array_map(
            static fn(Index $i): string => $i->getName(),
            $this->schemaManager->listTableIndexes('firewall_rate_limit_storage')
        ));
    }

    /**
     * Running it twice changes nothing the second time.
     */
    public function testApplyingIsIdempotent(): void
    {
        $this->createLegacyTable();
        $declared = $this->declaredTable();

        $this->migrator()->apply($declared);

        $this->assertSame([], $this->migrator()->pending($declared));
        $this->assertSame([], $this->migrator()->apply($declared));
    }

    /**
     * A refused change does not stop the others.
     *
     * One column that cannot be added safely is not a reason to leave an index
     * missing as well.
     */
    public function testARefusedChangeDoesNotBlockTheRest(): void
    {
        $this->createLegacyTable();

        $results = $this->migrator()->apply($this->declaredTable(withRefusable: true));

        $applied = array_column(array_filter($results, static fn(array $r): bool => $r['applied']), 'name');
        $skipped = array_column(array_filter($results, static fn(array $r): bool => !$r['applied']), 'name');

        $this->assertSame(['note', 'firewall_rate_limit_storage_rule_window_idx'], $applied);
        $this->assertSame(['required'], $skipped);
    }

    /**
     * A statement the database rejects is reported, not thrown.
     *
     * The index name is already taken by a table here, which SQLite refuses.
     * A migration script that fataled halfway would leave the operator with no
     * idea which changes had landed.
     */
    public function testAStatementTheDatabaseRejectsIsReported(): void
    {
        $this->createLegacyTable();
        $this->connection->executeStatement('CREATE TABLE firewall_rate_limit_storage_rule_window_idx (x INTEGER)');

        $results = $this->migrator()->apply($this->declaredTable());
        $failed = array_values(array_filter($results, static fn(array $r): bool => !$r['applied']));

        $this->assertCount(1, $failed);
        $this->assertSame('firewall_rate_limit_storage_rule_window_idx', $failed[0]['name']);
        $this->assertFalse($failed[0]['safe']);
        $this->assertNotSame('', $failed[0]['reason']);
    }

    /**
     * Anything that is not a plain addition is refused.
     *
     * The last line of defence, and deliberately unreachable through the public
     * path: `pending()` builds a column diff carrying one added column and asks
     * the platform for an index with `getCreateIndexSQL()`, so neither can
     * produce a destructive statement today. It exists because that is a
     * property of the platforms as they behave now, and a statement is the only
     * thing that can be checked for certain.
     */
    public function testAnyStatementThatIsNotAnAdditionIsRefused(): void
    {
        $migrator = $this->migrator();
        $refuse = new \ReflectionMethod(SchemaMigrator::class, 'refuseUnlessAdditive');
        $refuse->setAccessible(true);

        $this->assertSame('', $refuse->invoke($migrator, [
            'ALTER TABLE t ADD COLUMN c VARCHAR(8) DEFAULT \'\' NOT NULL',
            'CREATE INDEX i ON t (c)',
            'create unique index i2 on t (c)',
        ]));

        $rebuild = $refuse->invoke($migrator, [
            'CREATE TEMPORARY TABLE __temp__t AS SELECT id FROM t',
            'DROP TABLE t',
        ]);

        $this->assertStringContainsString('not a plain addition', $rebuild);
        $this->assertStringContainsString('CREATE TEMPORARY TABLE', $rebuild);
        $this->assertNotSame('', $refuse->invoke($migrator, ['ALTER TABLE t DROP COLUMN c']));
    }
}
