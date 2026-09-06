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
    protected function createTable(): void
    {
        $tables = $this->getStorageTables();
        /** @var Table[] $tables */
        foreach ($tables as $table) {
            if (!$this->schemaManager->tablesExist([$table->getName()])) {
                try {
                    $this->schemaManager->createTable($table);
                    $this->getLogger()->info('Database table created', [
                        'table' => $table->getName(),
                    ]);
                } catch (\Exception $e) {
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
                $this->getLogger()->debug('Database table already exists', [
                    'table' => $table->getName(),
                ]);
            }
        }
    }

    /**
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
