<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Traits;

use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Schema\Table;
use Kanopi\Firewall\Logging\Handler\DatabaseHandler;
use Kanopi\Firewall\RateLimitStorage\DatabaseRateLimitStorage;
use Kanopi\Firewall\Storage\DatabaseStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * The schema this package declares must be one it can migrate to (#278).
 *
 * #217 added `bin/firewall-migrate`, which refuses a column declared `NOT NULL`
 * with no default -- SQLite and PostgreSQL both reject adding one to a table
 * that has rows, and MySQL invents a value. That refusal is right.
 *
 * What nothing checked was whether the library's *own* declarations trip it.
 * Twelve of them did, so a release adding a column written the way every
 * existing column was written produced a migration that refused itself -- from
 * the feature whose whole purpose is that a new column does not mean dropping
 * the table.
 *
 * This is the check that was missing. It reads the declarations rather than any
 * particular database, so it fails at the moment a column is declared badly
 * rather than the release after.
 */
class DeclaredSchemaTest extends AbstractTestCase
{
    private string $path;

    protected function setUp(): void
    {
        parent::setUp();
        $this->path = tempnam(sys_get_temp_dir(), 'fwdecl') . '.sqlite';
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
        parent::tearDown();
    }

    /**
     * Every table every shipped consumer declares.
     *
     * @return array<int, array{consumer: string, table: Table}>
     *   Each declared table, with the class that declared it.
     */
    private function declaredTables(): array
    {
        $connection = ['connection' => ['driver' => 'pdo_sqlite', 'path' => $this->path]];

        $consumers = [
            new DatabaseStorage($connection),
            new DatabaseRateLimitStorage($connection),
            new DatabaseHandler(['table' => 'firewall_log'] + $connection),
        ];

        $declared = [];

        foreach ($consumers as $consumer) {
            $method = new \ReflectionMethod($consumer, 'getStorageTables');
            $method->setAccessible(true);

            /** @var array<int, Table> $tables */
            $tables = $method->invoke($consumer);

            foreach ($tables as $table) {
                $declared[] = ['consumer' => $consumer::class, 'table' => $table];
            }
        }

        return $declared;
    }

    /**
     * No declared column is one the migrator would refuse to add.
     *
     * The failure message names the column, because the fix is to give that
     * column a default rather than to weaken this test.
     */
    public function testEveryDeclaredColumnCouldBeAddedToATableThatHasRows(): void
    {
        $refusable = [];

        foreach ($this->declaredTables() as $entry) {
            /** @var Table $table */
            $table = $entry['table'];

            foreach ($table->getColumns() as $column) {
                // An autoincrement column is exempt: the database supplies the
                // value, so there is nothing to backfill.
                if (!$column->getNotnull() || $column->getAutoincrement()) {
                    continue;
                }

                if ($column->getDefault() !== null) {
                    continue;
                }

                $refusable[] = sprintf(
                    '%s.%s (declared by %s)',
                    $table->getName(),
                    $column->getName(),
                    $entry['consumer']
                );
            }
        }

        $this->assertSame(
            [],
            $refusable,
            "These columns are NOT NULL with no default, so bin/firewall-migrate would refuse to\n"
            . "add them to an existing table. Give each one a `'default' => …`:\n  "
            . implode("\n  ", $refusable)
        );
    }

    /**
     * Declaring a table declares at least one column.
     *
     * Cheap, and it means the check above cannot pass by iterating nothing --
     * which is how a test like this rots when a declaration moves.
     */
    public function testEveryDeclaredTableHasColumns(): void
    {
        $declared = $this->declaredTables();

        $this->assertGreaterThanOrEqual(4, count($declared), 'All four shipped tables are declared');

        foreach ($declared as $entry) {
            /** @var Table $table */
            $table = $entry['table'];

            $this->assertNotSame(
                [],
                array_map(static fn(Column $c): string => $c->getName(), $table->getColumns()),
                $table->getName() . ' declares no columns'
            );
        }
    }
}
