<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Logging\Handler;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Schema\Index;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Type;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Traits\DatabaseTrait;
use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Handler\ErrorLogHandler;
use Monolog\Level;
use Monolog\LogRecord;
use Monolog\Logger;

/**
 * Write firewall events to a relational table so they can be queried.
 *
 * Monolog ships no generic SQL handler — its own documentation tells you to
 * write one — so a table is the single destination `logger[].class` cannot
 * reach on its own. That matters here more than it would for diagnostic
 * output, because these particular lines are the record of what the firewall
 * did to real traffic, and the questions asked of them ("which rule blocked
 * the most clients this week", "did this rule ever match", "what did we do to
 * this address before it complained") are queries. A rotating file answers
 * none of them without `grep` and a reconstruction of JSON across rotations.
 *
 * Configured as a single associative array so it stays readable in YAML,
 * where the alternative is a dozen positional arguments:
 *
 * ```yaml
 * logger:
 *   - class: "Kanopi\\Firewall\\Logging\\Handler\\DatabaseHandler"
 *     args:
 *       - table: firewall_log
 *         connection:
 *           driver: pdo_mysql
 *           host: db
 *           dbname: app
 *           user: "%env(DB_USER)%"
 *           password: "%env(DB_PASSWORD)%"
 *         level: Monolog\Level::Warning
 *         retention_days: 30
 * ```
 *
 * Omit `connection` entirely and the handler reuses whatever
 * `storage.config.connection` already declares, since a deployment logging to
 * a database almost certainly has one configured for blocked clients.
 *
 * @see \Kanopi\Firewall\Traits\DatabaseTrait
 */
class DatabaseHandler extends AbstractProcessingHandler
{
    use DatabaseTrait;

    /**
     * Default table name, used when `table` is not configured.
     */
    public const DEFAULT_TABLE = 'firewall_log';

    /**
     * Columns promoted out of the record context, in table order.
     *
     * Everything here is written to its own column *and* left out of the
     * `context` JSON blob, which carries the remainder so nothing is lost.
     *
     * @var array<int, string>
     */
    private const PROMOTED_CONTEXT_KEYS = [
        'request_id',
        'client_ip',
        'plugin_name',
        'plugin_type',
        'method',
        'path',
        'host',
        'user_agent',
    ];

    /**
     * Table this handler writes to.
     */
    private string $table;

    /**
     * Connection parameters, or NULL to fall back on the storage connection.
     *
     * @var array<string, mixed>|Connection|null
     */
    private array|Connection|null $connectionParameters;

    /**
     * Whether records are held in memory and written in one go.
     */
    private bool $buffered;

    /**
     * Records to hold before flushing early. `0` holds until shutdown.
     */
    private int $bufferLimit;

    /**
     * Days of history to keep. `0` keeps everything.
     */
    private int $retentionDays;

    /**
     * Chance, per flush, of running the retention delete.
     */
    private float $pruneProbability;

    /**
     * Records held back from the database until the buffer is flushed.
     *
     * @var array<int, array<string, mixed>>
     */
    private array $buffer = [];

    /**
     * Whether `connect()` has run, successfully or not.
     */
    private bool $connectionAttempted = false;

    /**
     * Set once the database has refused us, to stop retrying every record.
     */
    private bool $disabled = false;

    /**
     * Logger for this handler's own failures — never the firewall logger.
     */
    private ?Logger $internalLogger = null;

    /**
     * Construct the handler from a single configuration array.
     *
     * @param array<string, mixed> $config
     *   Recognised keys:
     *   - `table`: table name. Defaults to `firewall_log`.
     *   - `connection`: Doctrine parameters, a `dsn`, or a `Connection`.
     *     Defaults to the connection `storage.config.connection` declares.
     *   - `level`: minimum level to record. Defaults to `Warning`, because
     *     `debug` on this handler means a row per allowed request.
     *   - `bubble`: whether handled records continue down the stack.
     *   - `buffer`: hold records in memory and write them in one statement at
     *     shutdown rather than one round trip per record. On by default.
     *   - `buffer_limit`: flush early once this many records are held. `0`
     *     (the default) holds everything until shutdown.
     *   - `retention_days`: delete rows older than this. `0` keeps forever.
     *   - `prune_probability`: chance, per flush, of running that delete.
     *     Ignored when `retention_days` is `0`.
     */
    public function __construct(array $config = [])
    {
        parent::__construct(
            $this->resolveLevel($config['level'] ?? Level::Warning),
            (bool) ($config['bubble'] ?? true)
        );

        $table = $config['table'] ?? self::DEFAULT_TABLE;
        $this->table = is_string($table) && $table !== '' ? $table : self::DEFAULT_TABLE;

        $this->buffered = (bool) ($config['buffer'] ?? true);
        $this->bufferLimit = max(0, (int) ($config['buffer_limit'] ?? 0));
        $this->retentionDays = max(0, (int) ($config['retention_days'] ?? 0));

        $probability = $config['prune_probability'] ?? 0.01;
        $this->pruneProbability = is_numeric($probability) ? min(1.0, max(0.0, (float) $probability)) : 0.01;

        $this->connectionParameters = self::normalizeConnectionParameters($config['connection'] ?? null);
    }

    /**
     * Fill in `connection` on any log handler that declared none.
     *
     * A deployment logging to a database almost certainly already has one
     * configured for blocked clients, and repeating those credentials under
     * `logger:` only creates a second place for them to drift. So a handler
     * that names no connection borrows the storage one.
     *
     * This resolves that at config time and returns the amended `logger:`
     * block, rather than leaving the handler to consult something global at
     * write time. The earlier version was a static default seeded by
     * `Firewall::create()`, and it was confusing for exactly the reason a
     * static is: it had to be assigned on every `create()` even when there was
     * nothing to assign, because not assigning it would let a firewall on file
     * storage inherit the database of one built earlier in the same process.
     * A config transform has no such state to keep straight -- what a handler
     * connects to is now visible in the config it was constructed from, and
     * `getConnectionParameters()` reports it.
     *
     * Nothing is borrowed unless the storage backend is genuinely database
     * backed. `connection` under `storage.config` means "Doctrine parameters"
     * to `DatabaseStorage` and to nothing else; a custom storage is free to
     * use the same key for a Redis config or an HTTP endpoint, and handing
     * that to `DriverManager` would produce a connection failure blamed on the
     * log handler. Most deployments run file or in-memory storage and have
     * nothing to lend, which is the case this stays cheap for: it opens no
     * connection and, finding no storage to borrow from, returns the config
     * untouched.
     *
     * @param array<int|string, mixed> $loggerConfig
     *   The `logger:` block, as normalised by `Firewall::create()`.
     * @param array<string, mixed> $storageConfig
     *   The `storage:` block, to borrow a connection from.
     *
     * @return array<int|string, mixed>
     *   The `logger:` block, with `connection` filled in on any
     *   `DatabaseHandler` entry that declared none. Entries that declare their
     *   own connection are left alone -- an explicit one always wins.
     */
    public static function shareStorageConnection(array $loggerConfig, array $storageConfig): array
    {
        $connection = self::reusableStorageConnection($storageConfig);

        if ($connection === null) {
            return $loggerConfig;
        }

        foreach ($loggerConfig as $index => $handlerConfig) {
            if (!is_array($handlerConfig)) {
                continue;
            }

            // An already-instantiated handler passed through config overrides
            // is past the point where its connection could be changed.
            $class = $handlerConfig['class'] ?? null;

            if (!is_string($class)) {
                continue;
            }

            if (!is_a(ltrim($class, '\\'), self::class, true)) {
                continue;
            }

            $args = $handlerConfig['args'] ?? [];

            if (!is_array($args)) {
                continue;
            }

            $handlerArgs = $args[0] ?? [];

            if (!is_array($handlerArgs)) {
                continue;
            }

            // An explicit connection always wins.
            if (isset($handlerArgs['connection'])) {
                continue;
            }

            $handlerArgs['connection'] = $connection;
            $args[0] = $handlerArgs;
            $loggerConfig[$index]['args'] = $args;
        }

        return $loggerConfig;
    }

    /**
     * Return the connection a storage backend can lend, if it can lend one.
     *
     * @param array<string, mixed> $storageConfig
     *   The `storage:` block.
     *
     * @return array<string, mixed>|null
     *   Doctrine connection parameters, or NULL when the storage is not
     *   database backed or declares no connection.
     */
    private static function reusableStorageConnection(array $storageConfig): ?array
    {
        $type = $storageConfig['type'] ?? null;

        if (!is_string($type) || !class_exists($type) || !self::isDatabaseBacked($type)) {
            return null;
        }

        $storageInnerConfig = $storageConfig['config'] ?? null;

        if (!is_array($storageInnerConfig)) {
            return null;
        }

        $connection = $storageInnerConfig['connection'] ?? null;

        return is_array($connection) && $connection !== [] ? $connection : null;
    }

    /**
     * Whether a storage class connects through `DatabaseTrait`.
     *
     * Tested by trait rather than by `instanceof DatabaseStorage` so a host
     * that writes its own database-backed storage -- which the custom-storage
     * guide encourages -- gets the same convenience the shipped one does.
     *
     * @param class-string $class
     *   The configured storage class.
     *
     * @return bool
     *   TRUE when the class, or one of its parents, uses `DatabaseTrait`.
     */
    private static function isDatabaseBacked(string $class): bool
    {
        $candidates = [$class, ...array_values(class_parents($class) ?: [])];

        foreach ($candidates as $candidate) {
            if (in_array(DatabaseTrait::class, class_uses($candidate) ?: [], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Describe the log table.
     *
     * The columns are the design: what can be asked of this table is decided
     * entirely by what is promoted out of the record context, so the eight
     * context keys `Firewall::getContext()` puts on every record each get one.
     *
     * `logged_at` is a Unix timestamp rather than a datetime so the column
     * sorts, ranges and prunes identically on MySQL, PostgreSQL and SQLite —
     * the same choice `DatabaseStorage` already makes for `timestamp`.
     */
    protected function getStorageTables(): array
    {
        return [
            new Table(
                $this->table,
                [
                    new Column('id', Type::getType('integer'), ['autoincrement' => true, 'unsigned' => true]),
                    new Column('logged_at', Type::getType('integer'), ['unsigned' => true, 'default' => 0]),
                    new Column('level', Type::getType('string'), ['length' => 16]),
                    new Column('level_value', Type::getType('integer'), ['unsigned' => true, 'default' => 0]),
                    new Column('channel', Type::getType('string'), ['length' => 64, 'default' => '']),
                    new Column('message', Type::getType('text')),
                    new Column('request_id', Type::getType('string'), ['length' => 64, 'default' => '']),
                    new Column('client_ip', Type::getType('string'), ['length' => 45, 'default' => '']),
                    new Column('plugin_name', Type::getType('string'), ['length' => 255, 'default' => '']),
                    new Column('plugin_type', Type::getType('string'), ['length' => 255, 'default' => '']),
                    new Column('method', Type::getType('string'), ['length' => 16, 'default' => '']),
                    new Column('path', Type::getType('text')),
                    new Column('host', Type::getType('string'), ['length' => 255, 'default' => '']),
                    new Column('user_agent', Type::getType('text')),
                    new Column('context', Type::getType('text')),
                ],
                [
                    new Index('PRIMARY', ['id'], true, true),
                    // Every question this table exists to answer is bounded by
                    // time, by address, or by rule, so all three are indexed.
                    new Index($this->indexName('logged_at'), ['logged_at']),
                    new Index($this->indexName('client_ip'), ['client_ip']),
                    new Index($this->indexName('plugin_type'), ['plugin_type']),
                ]
            ),
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function write(LogRecord $record): void
    {
        if ($this->disabled) {
            return;
        }

        $this->buffer[] = $this->toRow($record);

        if (!$this->buffered) {
            $this->flush();
            return;
        }

        if ($this->bufferLimit > 0 && count($this->buffer) >= $this->bufferLimit) {
            $this->flush();
        }
    }

    /**
     * {@inheritdoc}
     *
     * Monolog calls this from `AbstractHandler::__destruct()`, which runs on a
     * normal shutdown and on `exit()` — including the `exit()` a blocking
     * response ends on. A fatal error skips destructors, and a buffered record
     * is lost with it; that is the cost of not paying for a round trip on the
     * request path, and `buffer: false` is the way to decline it.
     */
    public function close(): void
    {
        $this->flush();
    }

    /**
     * {@inheritdoc}
     */
    public function reset(): void
    {
        $this->flush();

        parent::reset();
    }

    /**
     * Write everything held in the buffer, then prune if it is time to.
     */
    public function flush(): void
    {
        if ($this->buffer === []) {
            return;
        }

        $rows = $this->buffer;

        // Cleared before the write, not after: a failing insert that left the
        // rows in place would be retried by the next flush and by close(),
        // turning one unreachable database into a growing pile of retries.
        $this->buffer = [];

        if (!$this->connect()) {
            return;
        }

        foreach ($rows as $row) {
            try {
                $this->connection->insert($this->table, $row);
            } catch (\Throwable $throwable) {
                $this->reportFailure('Failed to write a firewall log record', $throwable);
                return;
            }
        }

        $this->pruneIfDue();
    }

    /**
     * Delete rows older than `retention_days`.
     *
     * A log table that only grows is a support ticket six months out, and
     * nothing in a library can promise an operator has a cron. So the delete
     * runs from here on a probability, and `bin/firewall-log-prune` runs it
     * deterministically for deployments that would rather schedule it —
     * set `prune_probability: 0` to leave pruning entirely to the script.
     *
     * @return int|null
     *   Number of rows deleted, 0 when retention is off, or NULL when the
     *   delete could not run — a distinction `bin/firewall-log-prune` reports
     *   as a failure rather than as a quiet success.
     */
    public function prune(): ?int
    {
        if ($this->retentionDays <= 0) {
            return 0;
        }

        if (!$this->connect()) {
            return null;
        }

        try {
            $deleted = (int) $this->connection->createQueryBuilder()
                ->delete($this->table)
                ->where('logged_at < :cutoff')
                ->setParameter('cutoff', $this->retentionCutoff())
                ->executeStatement();
        } catch (\Throwable $throwable) {
            $this->reportFailure('Failed to prune the firewall log table', $throwable);
            return null;
        }

        if ($deleted > 0) {
            $this->getLogger()->info('Pruned firewall log records', [
                'table' => $this->table,
                'retention_days' => $this->retentionDays,
                'deleted' => $deleted,
            ]);
        }

        return $deleted;
    }

    /**
     * Count the rows `prune()` would delete, without deleting them.
     *
     * @return int|null
     *   Number of rows outside the retention window, 0 when retention is off,
     *   or NULL when the table could not be read.
     */
    public function countPrunable(): ?int
    {
        if ($this->retentionDays <= 0) {
            return 0;
        }

        if (!$this->connect()) {
            return null;
        }

        try {
            return $this->countRows(
                $this->connection->createQueryBuilder()
                    ->from($this->table)
                    ->where('logged_at < :cutoff')
                    ->setParameter('cutoff', $this->retentionCutoff())
            );
        } catch (\Throwable $throwable) {
            $this->reportFailure('Failed to count prunable firewall log records', $throwable);

            return null;
        }
    }

    /**
     * Return the timestamp before which rows are outside the retention window.
     */
    private function retentionCutoff(): int
    {
        return time() - ($this->retentionDays * 86400);
    }

    /**
     * Return the table this handler writes to.
     */
    public function getTable(): string
    {
        return $this->table;
    }

    /**
     * Return the retention window, in days. `0` means keep everything.
     */
    public function getRetentionDays(): int
    {
        return $this->retentionDays;
    }

    /**
     * Return the connection this handler was configured with, if any.
     *
     * @return array<string, mixed>|Connection|null
     *   Parameters as normalised by the constructor, or NULL when the handler
     *   declares none and will fall back on the storage connection.
     */
    public function getConnectionParameters(): array|Connection|null
    {
        return $this->connectionParameters;
    }

    /**
     * Log this handler's own failures somewhere that is not this handler.
     *
     * `DatabaseTrait` logs through `getLogger()`, and the firewall logger is
     * the one holding *this* handler. Left alone, a failed insert would be
     * reported through the handler that just failed, which would fail again
     * and report that — unbounded recursion triggered by exactly the outage
     * the message is trying to describe. Overriding the trait's accessor
     * (a class method wins over a trait method) redirects every such line,
     * including the trait's own connection diagnostics, to the PHP error log.
     */
    protected function getLogger(): Logger
    {
        if (!$this->internalLogger instanceof Logger) {
            $this->internalLogger = new Logger('firewall.log-handler');
            $this->internalLogger->pushHandler(new ErrorLogHandler(ErrorLogHandler::OPERATING_SYSTEM, Level::Error));
        }

        return $this->internalLogger;
    }

    /**
     * Open the connection, once, on first use.
     *
     * Lazily, rather than in the constructor, for two reasons. The handler is
     * built during `Firewall::create()`, so a constructor that threw would
     * take the whole firewall down because its *log* destination was
     * unreachable — failing closed on a diagnostic. And a request that logs
     * nothing (every allowed request, at the default level) should not pay
     * for a connection it never uses.
     *
     * @return bool
     *   TRUE when the connection is usable.
     */
    private function connect(): bool
    {
        if ($this->disabled) {
            return false;
        }

        if ($this->connectionAttempted) {
            return true;
        }

        $this->connectionAttempted = true;

        $connection = $this->connectionParameters;

        if ($connection === null) {
            $this->disabled = true;
            // Says which of the two ways of configuring this was missed.
            // Reaching here on file or in-memory storage is the likely case:
            // there was no storage connection for `shareStorageConnection()`
            // to fill in, so the handler has to declare its own, and a config
            // that looks complete otherwise would just never produce a table.
            $this->getLogger()->error('Firewall log handler has no database connection: none declared under its `args`, and the configured storage is not database backed so there was none to inherit', [
                'table' => $this->table,
            ]);

            return false;
        }

        try {
            $this->createConnection($connection);
        } catch (\Throwable) {
            // Already described by `DatabaseTrait`, which redacts the target.
            $this->disabled = true;

            return false;
        }

        return true;
    }

    /**
     * Turn a Monolog record into a row for the log table.
     *
     * @param LogRecord $logRecord
     *   The record being written.
     *
     * @return array<string, mixed>
     *   Column values, keyed by column name.
     */
    private function toRow(LogRecord $logRecord): array
    {
        $context = self::redact($logRecord->context);

        $row = [
            'logged_at' => $logRecord->datetime->getTimestamp(),
            'level' => $logRecord->level->getName(),
            'level_value' => $logRecord->level->value,
            'channel' => $logRecord->channel,
            'message' => $logRecord->message,
        ];

        foreach (self::PROMOTED_CONTEXT_KEYS as $key) {
            $value = $context[$key] ?? '';
            unset($context[$key]);

            $row[$key] = is_scalar($value) ? (string) $value : '';
        }

        // The remainder, so a column that was never promoted — `mode`,
        // `provider`, whatever a custom plugin adds — is still queryable by
        // whatever JSON support the database has, and readable regardless.
        $row['context'] = json_encode(
            array_merge($context, $logRecord->extra),
            JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR
        ) ?: '{}';

        return $row;
    }

    /**
     * Replace values whose names are on the redaction list.
     *
     * A table is a more durable place to leak a session cookie than a file
     * that rotates away, so the list `LoggingFactory` already applies to
     * rule-match logging is applied again here, over the whole context —
     * covering context a plugin assembled itself rather than through
     * `EvaluateTrait`. Names are dotted paths, matching how the list is
     * written: a nested `['header' => ['cookie' => …]]` is tested as
     * `header.cookie`.
     *
     * @param array<mixed, mixed> $context
     *   Record context.
     * @param string $prefix
     *   Dotted path of the parent, when recursing.
     *
     * @return array<mixed, mixed>
     *   The context with redacted values replaced.
     */
    private static function redact(array $context, string $prefix = ''): array
    {
        $redacted = [];

        foreach ($context as $key => $value) {
            $path = $prefix === '' ? (string) $key : $prefix . '.' . $key;

            if (LoggingFactory::shouldRedactVariable($path)) {
                $redacted[$key] = '[REDACTED]';
                continue;
            }

            $redacted[$key] = is_array($value) ? self::redact($value, $path) : $value;
        }

        return $redacted;
    }

    /**
     * Run the retention delete on a fraction of flushes.
     */
    private function pruneIfDue(): void
    {
        if ($this->retentionDays <= 0 || $this->pruneProbability <= 0.0) {
            return;
        }

        // `mt_rand()` rather than `random_int()`: this decides whether to run
        // housekeeping, not anything an attacker gains from predicting, and it
        // is on the request path.
        if (mt_rand(1, PHP_INT_MAX) / PHP_INT_MAX > $this->pruneProbability) {
            return;
        }

        $this->prune();
    }

    /**
     * Report a failure and stop writing, so one outage is one message.
     *
     * @param string $message
     *   What was being attempted.
     * @param \Throwable $throwable
     *   The failure.
     */
    private function reportFailure(string $message, \Throwable $throwable): void
    {
        $this->disabled = true;

        $this->getLogger()->error($message, [
            'table' => $this->table,
            'error' => $throwable->getMessage(),
        ]);
    }

    /**
     * Build an index name scoped to the configured table.
     *
     * Index names are schema-wide on PostgreSQL, so two handlers writing to
     * two tables in one database would collide on a bare `logged_at`.
     *
     * @param string $column
     *   Column the index covers.
     *
     * @return string
     *   Index name.
     */
    private function indexName(string $column): string
    {
        return $this->table . '_' . $column . '_idx';
    }

    /**
     * Resolve a configured level to a Monolog `Level`.
     *
     * `LoggingFactory` rewrites `Monolog\Level::Warning` strings found in the
     * top level of `args`, but this handler takes one associative array, so
     * its `level` is nested a layer deeper than that pass reaches. Accepting
     * the same spelling here keeps the YAML consistent with every other
     * handler rather than making this one the exception.
     *
     * @param mixed $level
     *   A `Level`, a level name, a Monolog integer, or a
     *   `Monolog\Level::Warning` string.
     *
     * @return Level
     *   The resolved level, defaulting to `Warning`.
     */
    private function resolveLevel(mixed $level): Level
    {
        if ($level instanceof Level) {
            return $level;
        }

        if (is_int($level)) {
            return Level::tryFrom($level) ?? Level::Warning;
        }

        if (!is_string($level) || $level === '') {
            return Level::Warning;
        }

        $prefix = Level::class . '::';

        if (str_starts_with($level, $prefix)) {
            $level = substr($level, strlen($prefix));
        }

        try {
            return Level::fromName($level);
        } catch (\Throwable) {
            return Level::Warning;
        }
    }
}
