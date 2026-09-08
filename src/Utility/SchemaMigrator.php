<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Schema\AbstractSchemaManager;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Schema\TableDiff;

/**
 * Bring an existing firewall table up to the schema this release declares.
 *
 * The tables are created on first write and, until now, never touched again.
 * That was documented rather than designed: v2.19.0's notes tell anyone with
 * an existing rate limit table to run a `CREATE INDEX` by hand, and tell
 * anyone whose log table predates a new column to drop and recreate it --
 * which loses the history the table exists to hold (#217).
 *
 * ## Only ever additive
 *
 * This adds columns and indexes the declared schema has and the live table
 * lacks. It never drops, never renames, and never alters an existing column,
 * so there is no sequence of runs that can destroy data. That is a deliberate
 * ceiling, not an unfinished one, and it is also what makes the comparison
 * trustworthy:
 *
 * A table DBAL has just created does not compare equal to its own
 * declaration. Introspecting one back reports a platform collation the
 * declaration never set -- `BINARY` on SQLite, the server default on MySQL --
 * so every string and text column shows up as "changed" on a table with no
 * drift at all. Acting on a changed column would therefore mean rewriting
 * every healthy table on every run. Whether a column or index *exists* has no
 * such ambiguity, which is why those are the only two questions asked.
 *
 * The cost is that a release which widens or retypes a column is not covered
 * here and needs an operator to run the `ALTER` themselves. No release has
 * done that; the release that does will say so.
 *
 * ## Refusing rather than failing
 *
 * A column declared `NOT NULL` with no default cannot be added to a table
 * that already has rows -- SQLite and PostgreSQL both reject it, and MySQL
 * silently invents a value, which is worse. Such a change is refused with a
 * reason rather than attempted.
 *
 * It is refused on an empty table too, where it would in fact succeed. A
 * migration whose outcome depends on whether the table happens to have rows
 * yet passes in staging and fails in production, which is the one property a
 * migration must not have.
 */
final class SchemaMigrator
{
    /**
     * Construct a migrator for one connection.
     *
     * @param Connection $connection
     *   The connection the tables live on.
     * @param AbstractSchemaManager<\Doctrine\DBAL\Platforms\AbstractPlatform> $schemaManager
     *   Its schema manager.
     */
    public function __construct(
        private readonly Connection $connection,
        private readonly AbstractSchemaManager $schemaManager
    ) {
    }

    /**
     * The additive changes a table is missing.
     *
     * Returns nothing for a table that does not exist: creating it is
     * `DatabaseTrait::createTable()`'s job, and a table that is about to be
     * created from the same declaration is not behind it.
     *
     * @param Table $table
     *   The table as this release declares it.
     *
     * @return array<int, array{table: string, kind: string, name: string, sql: array<int, string>, safe: bool, reason: string}>
     *   One entry per missing column or index, each carrying the statements
     *   that would add it. `safe` is false for a change that would be refused,
     *   and `reason` says why.
     */
    public function pending(Table $table): array
    {
        $name = $table->getName();

        if (!$this->schemaManager->tablesExist([$name])) {
            return [];
        }

        $live = $this->schemaManager->introspectTable($name);

        // Asked of the schema manager, not built here. `Comparator::__construct()`
        // is marked `@internal` -- "can be only instantiated by a schema manager"
        // -- and its signature has already moved: DBAL 4.3 added a required
        // `ComparatorConfig`, a class that does not exist in 4.2. Since DBAL 4.3
        // and up need PHP 8.2, this package's 8.1 support means both versions are
        // live at once, and only the factory reads the same in both.
        $tableDiff = $this->schemaManager->createComparator()->compareTables($live, $table);

        $changes = [];

        $platform = $this->connection->getDatabasePlatform();

        foreach ($tableDiff->getAddedColumns() as $column) {
            $refusal = '';

            if ($column->getNotnull() && $column->getDefault() === null && !$column->getAutoincrement()) {
                $refusal = 'declared NOT NULL with no default, which cannot be added to a table that has rows';
            }

            // A diff carrying this one column and nothing else. Every other
            // slot is empty, so there is no dropped column or index for the
            // platform to act on.
            $statements = $platform->getAlterTableSQL(new TableDiff($live, addedColumns: [$column]));

            if ($refusal === '') {
                $refusal = $this->refuseUnlessAdditive($statements);
            }

            $changes[] = [
                'table' => $name,
                'kind' => 'column',
                'name' => $column->getName(),
                'sql' => $statements,
                'safe' => $refusal === '',
                'reason' => $refusal,
            ];
        }

        foreach ($tableDiff->getAddedIndexes() as $index) {
            // `getCreateIndexSQL()` rather than an ALTER built from a diff.
            // Asked to add an index through `getAlterTableSQL()`, the SQLite
            // platform rebuilds the entire table -- CREATE TEMPORARY TABLE,
            // DROP TABLE, CREATE TABLE, INSERT ... SELECT, DROP TABLE -- which
            // is destructive in exactly the way this class promises not to be.
            // It also rebuilds from the table as introspected, so running it
            // after adding a column silently reverted that column.
            //
            // A plain CREATE INDEX does the same job on every platform this
            // library supports, adds nothing to the table, and cannot lose a
            // row if it fails halfway.
            $statements = [$platform->getCreateIndexSQL($index, $name)];
            $refusal = $this->refuseUnlessAdditive($statements);

            $changes[] = [
                'table' => $name,
                'kind' => 'index',
                'name' => $index->getName(),
                'sql' => $statements,
                'safe' => $refusal === '',
                'reason' => $refusal,
            ];
        }

        return $changes;
    }

    /**
     * Apply the additive changes a table is missing.
     *
     * @param Table $table
     *   The table as this release declares it.
     *
     * @return array<int, array{table: string, kind: string, name: string, sql: array<int, string>, safe: bool, reason: string, applied: bool}>
     *   Every pending change, each marked with whether it ran. A refused
     *   change is returned unapplied with its reason, and does not stop the
     *   others: one column that cannot be added is not a reason to leave an
     *   index missing as well.
     */
    public function apply(Table $table): array
    {
        $results = [];

        foreach ($this->pending($table) as $change) {
            if (!$change['safe']) {
                $results[] = $change + ['applied' => false];
                continue;
            }

            try {
                // One at a time. A driver handed several statements in one
                // string either refuses them or emulates them, depending on
                // the PDO attribute in force, and neither is something to
                // depend on.
                foreach ($change['sql'] as $statement) {
                    $this->connection->executeStatement($statement);
                }

                $results[] = $change + ['applied' => true];
            } catch (\Exception $e) {
                $results[] = [
                    'table' => $change['table'],
                    'kind' => $change['kind'],
                    'name' => $change['name'],
                    'sql' => $change['sql'],
                    'safe' => false,
                    'reason' => $e->getMessage(),
                    'applied' => false,
                ];
            }
        }

        return $results;
    }

    /**
     * Refuse anything that is not recognisably an addition.
     *
     * The last line of defence, and the reason the safety here is structural
     * rather than a matter of trusting the comparison. Every statement is
     * checked to be an `ALTER TABLE ... ADD` or a `CREATE INDEX` before it is
     * allowed to run, so a platform that answers an additive request with a
     * destructive rewrite -- SQLite answers exactly that way when asked to add
     * an index through a table diff -- is caught and reported rather than
     * executed.
     *
     * Matching on generated SQL is a blunt instrument. It is used because the
     * thing being guarded against is a *statement*, and no amount of care
     * about how the diff was built proves what the platform will emit from it.
     *
     * @param array<int, string> $statements
     *   The statements a change would run.
     *
     * @return string
     *   Empty when every statement is additive, otherwise the reason to
     *   refuse.
     */
    private function refuseUnlessAdditive(array $statements): string
    {
        foreach ($statements as $statement) {
            $normalised = strtoupper(preg_replace('/\s+/', ' ', trim($statement)) ?? '');

            if (preg_match('/^ALTER TABLE .+ ADD /', $normalised) === 1) {
                continue;
            }

            if (preg_match('/^CREATE (UNIQUE )?INDEX /', $normalised) === 1) {
                continue;
            }

            return sprintf(
                'the database platform would run a statement that is not a plain addition (%s)',
                $statement
            );
        }

        return '';
    }
}
