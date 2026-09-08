<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Traits;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Query\QueryBuilder;
use Doctrine\DBAL\Schema\AbstractSchemaManager;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Tools\DsnParser;
use Kanopi\Firewall\Exception\StorageConnectionException;
use Kanopi\Firewall\Logging\LoggingTrait;
use Kanopi\Firewall\Utility\SchemaMigrator;

/**
 * Database Trait used for referencing database.
 */
trait DatabaseTrait
{
    use LoggingTrait;

    protected Connection $connection;

    /** @phpstan-ignore-next-line */
    protected AbstractSchemaManager $schemaManager;

    /**
     * Create the Connection.
     *
     * @param array<string, mixed>|Connection $connectionParams
     *   Doctrine connection parameters, a `dsn` to parse, or a ready Connection.
     *
     * @throws StorageConnectionException
     *   When the connection cannot be built, the schema manager cannot be
     *   created, or the database cannot be reached while setting up the schema.
     *   Pre-fix this was logged and swallowed while `$connection` and
     *   `$schemaManager` — both typed and non-nullable — were left
     *   uninitialized, and the method returned as if it had succeeded. The
     *   first storage call then died with `Typed property ...$schemaManager
     *   must not be accessed before initialization`, a `\Error` that
     *   `catch (\Exception)` guards downstream do not catch, and the real
     *   reason (bad credentials, unreachable host, unresolved env token) never
     *   reached the caller.
     */
    protected function createConnection(array|Connection $connectionParams): void
    {
        try {
            if ($connectionParams instanceof Connection) {
                $this->connection = $connectionParams;

                $this->getLogger()->debug('Using existing database connection');
            } else {
                if (isset($connectionParams['dsn'])) {
                    $dsnParser = new DsnParser();
                    $parsedParams = $dsnParser->parse($connectionParams['dsn']);

                    $this->getLogger()->debug('Parsed DSN for database connection', [
                        'driver' => $parsedParams['driver'] ?? 'unknown',
                    ]);

                    $connectionParams = $parsedParams;
                }

                $this->connection = DriverManager::getConnection($connectionParams);

                $this->getLogger()->debug('Database connection created', [
                    'driver' => $connectionParams['driver'] ?? 'unknown',
                ]);
            }

            $this->schemaManager = $this->connection->createSchemaManager();
            $this->createTable();
        } catch (\Throwable $throwable) {
            // `\Throwable`, not `\Exception`: the failure has to be reported
            // whatever its shape, and callers get a typed exception either way.
            $target = self::describeConnectionTarget($connectionParams);

            $this->getLogger()->error('Failed to create database connection', [
                'error' => $throwable->getMessage(),
                'target' => $target,
            ]);

            // The code is cast: `PDOException` can carry a string SQLSTATE, and a
            // `TypeError` from the constructor here would bury the real reason
            // the same way the swallowed exception used to.
            throw new StorageConnectionException(sprintf('Firewall database storage could not connect (%s): %s', $target, $throwable->getMessage()), (int) $throwable->getCode(), previous: $throwable);
        }
    }

    /**
     * Reduce a configured `connection` to something DriverManager will accept.
     *
     * Every consumer of this trait reads its connection from YAML, so every
     * one of them needs the same two fixes applied before Doctrine sees it:
     * YAML hands back `port` as a string where `DriverManager` wants an int,
     * and a sequence-shaped key would arrive as an int where the parameter
     * names are strings. All three used to do the first of those inline and
     * they did not agree -- `DatabaseRateLimitStorage` reached for
     * `$config['connection']` without checking it was there, so a config with
     * no connection at all emitted `Undefined array key "connection"` ahead of
     * the exception that explains the real problem. That is the noise
     * `DatabaseStorage` has a comment about having removed; the removal never
     * reached its sibling. Doing it once here is why it now has.
     *
     * @param mixed $connection
     *   Whatever the config carried: parameters, a `dsn`, a ready
     *   `Connection`, or nothing usable.
     *
     * @return array<string, mixed>|Connection|null
     *   Parameters ready for `createConnection()`, the connection as given, or
     *   NULL when there is nothing usable to connect with. Callers decide what
     *   NULL means for them -- storage passes `[]` on to fail loudly, the log
     *   handler falls back to the storage connection.
     */
    protected static function normalizeConnectionParameters(mixed $connection): array|Connection|null
    {
        if ($connection instanceof Connection) {
            return $connection;
        }

        if (!is_array($connection) || $connection === []) {
            return null;
        }

        $parameters = [];

        foreach ($connection as $key => $value) {
            $parameters[(string) $key] = $value;
        }

        if (isset($parameters['port']) && is_numeric($parameters['port'])) {
            $parameters['port'] = (int) $parameters['port'];
        }

        return $parameters;
    }

    /**
     * Describe where a failed connection was pointed, for logs and messages.
     *
     * Only non-secret parameters are reported: an operator needs to see which
     * host and database the firewall tried, and must not find the credentials
     * for it in an error log or an admin screen. A `dsn` is reduced the same
     * way, since it can carry a username and password inline.
     *
     * @param array<string, mixed>|Connection $connectionParams
     *   Parameters the connection was attempted with.
     *
     * @return string
     *   Redacted description, e.g. `driver=pdo_mysql host=db port=3306 dbname=app`.
     */
    private static function describeConnectionTarget(array|Connection $connectionParams): string
    {
        if ($connectionParams instanceof Connection) {
            $connectionParams = $connectionParams->getParams();
        }

        if (isset($connectionParams['dsn']) && \is_string($connectionParams['dsn'])) {
            return self::describeDsn($connectionParams['dsn']);
        }

        $described = [];
        foreach (['driver', 'driverClass', 'host', 'port', 'dbname', 'path', 'memory'] as $key) {
            $value = $connectionParams[$key] ?? null;
            if (\is_bool($value)) {
                $value = $value ? 'true' : 'false';
            }

            if (\is_string($value) || \is_int($value)) {
                $described[] = $key . '=' . $value;
            }
        }

        return $described === [] ? 'no connection parameters' : \implode(' ', $described);
    }

    /**
     * Describe a DSN without the credentials it may carry.
     *
     * @param string $dsn
     *   The DSN the connection was attempted with.
     *
     * @return string
     *   Redacted description built from the scheme, host, port and path only.
     */
    private static function describeDsn(string $dsn): string
    {
        $parts = \parse_url($dsn);
        if ($parts === false) {
            return 'unparseable dsn';
        }

        $described = [];
        foreach (['scheme', 'host', 'port', 'path'] as $key) {
            $value = $parts[$key] ?? null;
            if (\is_string($value) || \is_int($value)) {
                $described[] = $key . '=' . $value;
            }
        }

        return $described === [] ? 'unparseable dsn' : \implode(' ', $described);
    }

    /**
     * Create the table for storage.
     *
     * @throws \Doctrine\DBAL\Exception
     *   If there is an issue with creating the table an exception is thrown.
     */
    /**
     * When each table was last confirmed, keyed by target and name.
     *
     * Holds a timestamp rather than a flag, because "this table exists" does go
     * stale. Dropping a table is a documented workflow here -- the v2.19.0
     * notes tell operators to drop and recreate `firewall_log` to pick up a new
     * column -- and a flag would mean a long-lived worker never recreated it,
     * failing every write until somebody restarted PHP.
     *
     * Re-checking at most once a MEMO_SECONDS window keeps almost all of the
     * saving. At ten requests a second that is one information_schema round
     * trip per table per minute instead of ten a second, and a dropped table
     * comes back within the window rather than never.
     *
     * @var array<string, int>
     */
    private static array $tablesKnownToExist = [];

    /**
     * Tables already compared against the schema this release declares.
     *
     * Unlike `$tablesKnownToExist` this never expires, and is deliberately a
     * flag rather than a timestamp. A table cannot fall behind mid-process:
     * the declaration is fixed in the code that is running, and the only thing
     * that changes the live table is a migration, which can only bring it
     * closer. So the answer is worth exactly one introspection per table per
     * process -- 0.48 ms against the 0.02 ms an existence check costs, which
     * is why it is not folded into the 60-second window.
     *
     * Doubling as the record of having warned: an operator who cannot run the
     * migration should not be told once a minute for the life of the worker.
     *
     * @var array<string, bool>
     */
    private static array $schemasChecked = [];

    /**
     * How long a confirmation stays good, in seconds.
     *
     * A method rather than a constant: constants in traits are PHP 8.2 and up,
     * and this package supports 8.1. The same trap caught FileTrait in 2.19.2,
     * and PHPCompatibility does not flag it -- only a lint under an 8.1 runtime
     * does.
     *
     * @return int
     *   Seconds a table confirmation remains valid.
     */
    private static function memoSeconds(): int
    {
        return 60;
    }

    /**
     * Identify a table by the connection it lives on as well as its name.
     *
     * Two consumers of this trait can be pointed at different databases -- a
     * block list on one, the log handler on another -- and a bare table name
     * would let one answer for the other.
     *
     * @param array<string, mixed> $params
     *   Connection parameters.
     * @param string $table
     *   Table name.
     *
     * @return string|null
     *   Memo key, or null when this connection must not be memoised.
     */
    private static function tableMemoKey(array $params, string $table): ?string
    {
        // An in-memory SQLite database is a new, empty database every time it
        // is opened, while its connection parameters never change. Memoising it
        // would have one connection vouch for tables that exist only in
        // another -- which reads as "no such table" on the first write.
        //
        // Nothing is lost: an in-memory database is per-connection by
        // definition, so there was never a second construction to save.
        $path = $params['path'] ?? null;

        if (($params['memory'] ?? false) === true || (is_string($path) && str_contains($path, ':memory:'))) {
            return null;
        }

        return hash('xxh128', serialize([
            $params['driver'] ?? null,
            $params['host'] ?? null,
            $params['port'] ?? null,
            $params['dbname'] ?? null,
            $params['path'] ?? null,
            $params['unix_socket'] ?? null,
            $table,
        ]));
    }

    protected function createTable(): void
    {
        $tables = $this->getStorageTables();
        /** @var Table[] $tables */
        foreach ($tables as $table) {
            // Asked once per process, not once per construction. This runs from
            // connect(), which runs on every request, and every consumer of this
            // trait pays it -- a deployment on database storage with the database
            // log handler asks four times per request, each an information_schema
            // round trip that is free on a local socket and is not over a network
            // (#227).
            //
            // Memoised per connection target and table, so two consumers pointed
            // at different databases do not answer for each other.
            $known = self::tableMemoKey($this->connection->getParams(), $table->getName());

            $confirmedAt = $known === null ? 0 : (self::$tablesKnownToExist[$known] ?? 0);

            if ($confirmedAt > time() - self::memoSeconds()) {
                continue;
            }

            if (!$this->schemaManager->tablesExist([$table->getName()])) {
                try {
                    $this->schemaManager->createTable($table);
                    $this->getLogger()->info('Database table created', [
                        'table' => $table->getName(),
                    ]);
                    if ($known !== null) {
                        self::$tablesKnownToExist[$known] = time();
                    }
                } catch (\Exception $e) {
                    // Deliberately not memoised: a creation that failed may
                    // succeed once someone fixes the permission, and a process
                    // that had recorded it would never try again.
                    $this->getLogger()->error('Failed to create database table', [
                        'table' => $table->getName(),
                        'error' => $e->getMessage(),
                    ]);
                }
            } else {
                // The table being iterated, not `config['storage_table']`.
                // A class using this trait may declare several tables --
                // `DatabaseStorage` declares two -- so the config key named
                // only the first of them, and it is not a key every consumer
                // sets at all: a class whose config has no `storage_table`
                // took an undefined-index warning here on every construction
                // where its table already existed, which is every request
                // after the first.
                if ($known !== null) {
                    self::$tablesKnownToExist[$known] = time();
                }

                $this->getLogger()->debug('Database table already exists', [
                    'table' => $table->getName(),
                ]);

                $this->reportSchemaDrift($table);
            }
        }
    }

    /**
     * The additive schema changes this consumer's tables are missing.
     *
     * The public counterpart of the startup warning, and what
     * `bin/firewall-migrate --dry-run` reports. Answers for every table the
     * class declares, so `DatabaseStorage` covers both of its.
     *
     * Introspects, and changes nothing.
     *
     * @return array<int, array{table: string, kind: string, name: string, sql: array<int, string>, safe: bool, reason: string}>
     *   One entry per missing column or index. Empty when every table matches
     *   what this release declares, or does not exist yet -- a table about to
     *   be created from this same declaration is not behind it.
     */
    public function pendingSchemaChanges(): array
    {
        $schemaMigrator = new SchemaMigrator($this->connection, $this->schemaManager);
        $pending = [];

        foreach ($this->getStorageTables() as $storageTable) {
            foreach ($schemaMigrator->pending($storageTable) as $change) {
                $pending[] = $change;
            }
        }

        return $pending;
    }

    /**
     * Add the columns and indexes this consumer's tables are missing.
     *
     * Only ever additive: it adds, and never drops, renames or rewrites, so no
     * sequence of runs can lose a row. A change it will not make safely is
     * returned unapplied with the reason, and does not stop the rest.
     *
     * Not called from anywhere in the request path. An `ALTER TABLE` takes a
     * lock, and a firewall that decides to take one under load is not
     * something to switch on by default -- `bin/firewall-migrate` is when an
     * operator says so.
     *
     * @return array<int, array{table: string, kind: string, name: string, sql: array<int, string>, safe: bool, reason: string, applied: bool}>
     *   Every pending change, each marked with whether it ran.
     */
    public function migrateSchema(): array
    {
        $schemaMigrator = new SchemaMigrator($this->connection, $this->schemaManager);
        $results = [];

        foreach ($this->getStorageTables() as $storageTable) {
            foreach ($schemaMigrator->apply($storageTable) as $result) {
                $results[] = $result;
            }
        }

        // A table that just gained a column is no longer the table this
        // process recorded as matching the declaration, and on the next
        // request it would be compared again and found clean anyway. Clearing
        // it keeps a long-lived worker from warning about a table it has since
        // migrated itself.
        self::$schemasChecked = [];

        return $results;
    }

    /**
     * Say so when an existing table is behind the schema this release declares.    /**
     * Say so when an existing table is behind the schema this release declares.
     *
     * Tables are created on first write and were then never looked at again,
     * so a release that adds a column or an index reached only installations
     * created after it. v2.19.0 shipped the symptom: its notes ask anyone with
     * an existing rate limit table to run a `CREATE INDEX` by hand, which is a
     * migration performed in prose (#217).
     *
     * Reports; does not migrate. An `ALTER TABLE` on a large `firewall_log`
     * takes a lock, and a firewall that decides to take one on a cold cache
     * under load is not something to switch on by default. `bin/firewall-migrate`
     * applies these, and this is what tells an operator to run it.
     *
     * @param Table $table
     *   The table as this release declares it.
     */
    private function reportSchemaDrift(Table $table): void
    {
        $key = self::tableMemoKey($this->connection->getParams(), $table->getName());

        // A connection that cannot be memoised -- in-memory SQLite -- is one
        // whose tables were created moments ago from this same declaration, so
        // there is nothing for them to be behind.
        if ($key === null || (self::$schemasChecked[$key] ?? false)) {
            return;
        }

        self::$schemasChecked[$key] = true;

        try {
            $pending = (new SchemaMigrator($this->connection, $this->schemaManager))->pending($table);
        } catch (\Exception $exception) {
            // Introspection is not the job. A user without the privilege to
            // read the schema can still read and write the rows, and must keep
            // running.
            $this->getLogger()->debug('Could not compare the table against the declared schema', [
                'table' => $table->getName(),
                'error' => $exception->getMessage(),
            ]);

            return;
        }

        if ($pending === []) {
            return;
        }

        // Warning, not error: everything the table is asked to do today, it
        // still does. What is missing is whatever the newer columns and
        // indexes were added for, which is a degradation rather than a
        // failure -- a missing index makes a query slow, not wrong.
        $this->getLogger()->warning('Database table is behind the schema this release declares', [
            'table' => $table->getName(),
            'missing' => array_map(
                static fn(array $change): string => $change['kind'] . ' ' . $change['name'],
                $pending
            ),
            'remedy' => 'Run bin/firewall-migrate to add them, or bin/firewall-migrate --dry-run to see the statements first.',
        ]);
    }

    /**
     * Describe the tables this storage requires.    /**
     * Describe the tables this storage requires.
     *
     * Optional hook. Classes using this trait override this to declare their
     * schema; the default returns no tables so the trait remains usable by
     * classes that manage their own schema or need none.
     *
     * @return Table[]
     *   Tables to create when they do not already exist.
     */
    protected function getStorageTables(): array
    {
        return [];
    }

    /**
     * Clamp a timestamp bound to what the column can actually hold.
     *
     * `countOffenses()` and `listOffenses()` default their upper bound to
     * `PHP_INT_MAX`, meaning "no upper bound". Every timestamp column these
     * classes declare is `Type::getType('integer')`, which PostgreSQL creates
     * as a 4-byte `INT`, and PostgreSQL refuses to compare it against a value
     * outside that range rather than deciding the comparison is trivially
     * true:
     *
     *     SQLSTATE[22003]: Numeric value out of range: 7 ERROR:
     *     value "9223372036854775807" is out of range for type integer
     *
     * MySQL and SQLite accept it, so the whole family of range queries worked
     * everywhere except PostgreSQL -- and `countOffenses()` caught the failure
     * without logging it, so on PostgreSQL it silently returned 0 for every
     * client. `find()` calls it for the offense count shown next to each
     * blocked address, so an admin listing showed every client as having
     * offended zero times.
     *
     * Clamping rather than dropping the clause: a caller that passes a real
     * bound still gets it, and one that passes the sentinel gets a bound the
     * column can hold, which for a 4-byte column is every timestamp it could
     * ever contain.
     *
     * @param int $bound
     *   A timestamp bound as the caller supplied it.
     *
     * @return int
     *   The bound, clamped to the signed 32-bit range.
     */
    protected static function clampTimestampBound(int $bound): int
    {
        return max(-2147483648, min(2147483647, $bound));
    }

    /**
     * Count the rows a query matches, in the database rather than in PHP.
     *
     * Named, rather than left as a line in each caller, because the mistake it
     * replaces was made independently in two of the three classes using this
     * trait: both `DatabaseStorage::countOffenses()` and
     * `DatabaseRateLimitStorage::countRequests()` selected every matching row,
     * pulled it all back, and called `count()` on the result.
     *
     * That is worst exactly where it hurts most. `countRequests()` is the rate
     * limiter's per-request hot path, so a client being rate-limited makes the
     * firewall fetch every row it is counting, on every request, and the
     * database backend never deletes those rows -- so the set only grows.
     * Measured over 20,000 rows on SQLite: 8.5ms and a 14MB peak to fetch and
     * count, against 2.2ms to ask the database. Over a socket to MySQL it is
     * 20,000 rows on the wire instead of one integer.
     *
     * Exceptions are left to propagate: the three callers disagree about what
     * a failed count means -- 0, 0 with a logged error, or NULL and a handler
     * that stops trying -- and that disagreement is deliberate.
     *
     * @param QueryBuilder $queryBuilder
     *   A builder with its `from()` and any constraints already applied. Its
     *   select list is replaced.
     *
     * @return int
     *   Number of matching rows.
     *
     * @throws \Doctrine\DBAL\Exception
     *   If the query cannot be run.
     */
    protected function countRows(QueryBuilder $queryBuilder): int
    {
        return (int) $queryBuilder
            ->select('COUNT(*)')
            ->executeQuery()
            ->fetchOne();
    }

    /**
     * Enforce that the data being put into the database actually has columns for it.
     *
     * @param string $table
     *   Table name to get columns for.
     * @param array $data
     *   Data going into the table.
     *
     * @return array
     *   Data modified with values allowed in the table.
     */
    protected function enforceTableData(string $table, array $data = []): array
    {
        try {
            $columns = $this->schemaManager->listTableColumns($table);
            $removedKeys = [];

            foreach (array_keys($data) as $key) {
                if (!isset($columns[$key])) {
                    unset($data[$key]);
                    $removedKeys[] = $key;
                }
            }

            if ($removedKeys !== []) {
                $this->getLogger()->debug('Removed non-existent columns from data', [
                    'table' => $table,
                    'removed_keys' => $removedKeys,
                ]);
            }
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to enforce table data', [
                'table' => $table,
                'error' => $exception->getMessage(),
            ]);
            return [];
        }

        return $data;
    }
}
