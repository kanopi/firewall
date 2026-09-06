<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Logging;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Kanopi\Firewall\Logging\Handler\DatabaseHandler;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Level;
use Monolog\LogRecord;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Unit tests for the database log handler.
 *
 * These run against a real SQLite file rather than a mocked Connection. The
 * handler's whole value is the shape of what lands in the table, and a mock
 * that returns whatever it was told to cannot show that a row is queryable.
 */
class DatabaseHandlerTest extends AbstractTestCase
{
    /**
     * Path of the SQLite file backing the current test.
     */
    private string $databasePath;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->databasePath = sys_get_temp_dir() . '/' . uniqid('firewall-log-', true) . '.sqlite';
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        if (is_file($this->databasePath)) {
            unlink($this->databasePath);
        }

        parent::tearDown();
    }

    /**
     * A record is written with every promoted context key in its own column.
     */
    public function testRecordIsWrittenWithPromotedColumns(): void
    {
        $handler = $this->createHandler();
        $handler->handle($this->record(Level::Warning, 'Request would be blocked (log mode)', [
            'request_id' => 'REQ-1',
            'client_ip' => '203.0.113.5',
            'plugin_name' => 'IP Address',
            'plugin_type' => 'Kanopi\Firewall\Plugins\IpAddress',
            'method' => 'POST',
            'path' => '/wp-login.php',
            'host' => 'example.com',
            'user_agent' => 'curl/8.4.0',
            'mode' => 'log',
        ]));
        $handler->flush();

        $row = $this->rows()[0];

        self::assertSame('WARNING', $row['level']);
        self::assertSame(Level::Warning->value, (int) $row['level_value']);
        self::assertSame('firewall', $row['channel']);
        self::assertSame('Request would be blocked (log mode)', $row['message']);
        self::assertSame('REQ-1', $row['request_id']);
        self::assertSame('203.0.113.5', $row['client_ip']);
        self::assertSame('IP Address', $row['plugin_name']);
        self::assertSame('Kanopi\Firewall\Plugins\IpAddress', $row['plugin_type']);
        self::assertSame('POST', $row['method']);
        self::assertSame('/wp-login.php', $row['path']);
        self::assertSame('example.com', $row['host']);
        self::assertSame('curl/8.4.0', $row['user_agent']);
        self::assertGreaterThan(0, (int) $row['logged_at']);

        // Promoted keys leave the blob; everything else stays in it.
        self::assertSame(['mode' => 'log'], json_decode($row['context'], true));
    }

    /**
     * The questions the table exists to answer are answerable in SQL.
     */
    public function testTableAnswersTheQuestionsItExistsFor(): void
    {
        $handler = $this->createHandler();

        foreach (['203.0.113.5', '203.0.113.5', '198.51.100.9'] as $address) {
            $handler->handle($this->record(Level::Warning, 'Request blocked', [
                'client_ip' => $address,
                'plugin_name' => 'IP Address',
                'plugin_type' => 'Kanopi\Firewall\Plugins\IpAddress',
            ]));
        }

        $handler->handle($this->record(Level::Warning, 'Request blocked', [
            'client_ip' => '198.51.100.9',
            'plugin_name' => 'User Agent',
            'plugin_type' => 'Kanopi\Firewall\Plugins\UserAgent',
        ]));
        $handler->flush();

        $connection = $this->connection();

        self::assertSame(
            3,
            (int) $connection->fetchOne(
                'SELECT COUNT(*) FROM firewall_log WHERE plugin_type = ?',
                ['Kanopi\Firewall\Plugins\IpAddress']
            ),
            'Which rule has blocked the most clients'
        );

        self::assertSame(
            2,
            (int) $connection->fetchOne('SELECT COUNT(*) FROM firewall_log WHERE client_ip = ?', ['203.0.113.5']),
            'What did we do to this address'
        );

        self::assertSame(
            0,
            (int) $connection->fetchOne(
                'SELECT COUNT(*) FROM firewall_log WHERE plugin_type = ?',
                ['Kanopi\Firewall\Plugins\GeoLocation']
            ),
            'Did anything match this rule at all'
        );
    }

    /**
     * Records below the handler level never reach the table.
     */
    public function testLevelIsHonoured(): void
    {
        $handler = $this->createHandler(['level' => 'Monolog\Level::Warning']);
        $handler->handle($this->record(Level::Debug, 'Request allowed'));
        $handler->handle($this->record(Level::Info, 'Request bypassed'));
        $handler->handle($this->record(Level::Error, 'Something broke'));
        $handler->flush();

        $rows = $this->rows();

        self::assertCount(1, $rows);
        self::assertSame('Something broke', $rows[0]['message']);
    }

    /**
     * Warning is the default, so `debug` does not become a row per request.
     */
    public function testDefaultLevelIsWarning(): void
    {
        $handler = $this->createHandler(['level' => null]);

        self::assertSame(Level::Warning, $handler->getLevel());
    }

    /**
     * Every spelling `level` accepts resolves to the same place.
     *
     */
    #[DataProvider('levelProvider')]
    public function testLevelIsResolvedFromEverySupportedSpelling(mixed $level, Level $expected): void
    {
        self::assertSame($expected, $this->createHandler(['level' => $level])->getLevel());
    }

    /**
     * Level spellings, and what each should resolve to.
     *
     * @return array<string, array{mixed, Level}>
     */
    public static function levelProvider(): array
    {
        return [
            'Level instance' => [Level::Critical, Level::Critical],
            'Monolog constant string' => ['Monolog\Level::Notice', Level::Notice],
            'bare name' => ['error', Level::Error],
            'Monolog integer' => [Level::Alert->value, Level::Alert],
            'unknown integer' => [999, Level::Warning],
            'unknown name' => ['chatty', Level::Warning],
            'empty string' => ['', Level::Warning],
            'wrong type' => [[Level::Debug], Level::Warning],
        ];
    }

    /**
     * Nothing is written until the buffer is flushed, and then all of it is.
     */
    public function testBufferedRecordsAreHeldUntilFlush(): void
    {
        $handler = $this->createHandler();
        $handler->handle($this->record(Level::Warning, 'First'));
        $handler->handle($this->record(Level::Warning, 'Second'));

        self::assertSame([], $this->rows(), 'Buffered records should not have been written yet');

        $handler->flush();

        self::assertCount(2, $this->rows());
    }

    /**
     * `buffer: false` pays the round trip per record, for those who want it.
     */
    public function testUnbufferedRecordsAreWrittenImmediately(): void
    {
        $handler = $this->createHandler(['buffer' => false]);
        $handler->handle($this->record(Level::Warning, 'Immediate'));

        self::assertCount(1, $this->rows());
    }

    /**
     * A buffer limit flushes early rather than growing without bound.
     */
    public function testBufferLimitFlushesEarly(): void
    {
        $handler = $this->createHandler(['buffer_limit' => 2]);
        $handler->handle($this->record(Level::Warning, 'First'));

        self::assertSame([], $this->rows());

        $handler->handle($this->record(Level::Warning, 'Second'));

        self::assertCount(2, $this->rows());

        $handler->handle($this->record(Level::Warning, 'Third'));

        self::assertCount(2, $this->rows(), 'The third record starts a new buffer');
    }

    /**
     * `close()` flushes, which is what makes shutdown-time writing work.
     */
    public function testCloseFlushesTheBuffer(): void
    {
        $handler = $this->createHandler();
        $handler->handle($this->record(Level::Warning, 'Held'));
        $handler->close();

        self::assertCount(1, $this->rows());
    }

    /**
     * `reset()` flushes too — a long-running worker must not lose a batch.
     */
    public function testResetFlushesTheBuffer(): void
    {
        $handler = $this->createHandler();
        $handler->handle($this->record(Level::Warning, 'Held'));
        $handler->reset();

        self::assertCount(1, $this->rows());
    }

    /**
     * Flushing an empty buffer opens no connection and writes nothing.
     */
    public function testFlushingAnEmptyBufferDoesNothing(): void
    {
        $handler = $this->createHandler();
        $handler->flush();

        self::assertFileDoesNotExist($this->databasePath, 'No connection should have been opened');
    }

    /**
     * A record that logs nothing still costs no connection.
     */
    public function testNoConnectionIsOpenedUntilSomethingIsWritten(): void
    {
        $this->createHandler();

        self::assertFileDoesNotExist($this->databasePath);
    }

    /**
     * Values on the redaction list never reach the table.
     */
    public function testRedactedContextNeverReachesTheTable(): void
    {
        $handler = $this->createHandler();
        $handler->handle($this->record(Level::Warning, 'Comparison matched', [
            'header' => [
                'cookie' => 'SESS9f2=super-secret',
                'user-agent' => 'curl/8.4.0',
            ],
            'cookie' => ['SESS9f2' => 'super-secret'],
            'note' => 'kept',
        ]));
        $handler->flush();

        $context = $this->rows()[0]['context'];

        self::assertStringNotContainsString('super-secret', $context);
        self::assertSame([
            'header' => [
                'cookie' => '[REDACTED]',
                'user-agent' => 'curl/8.4.0',
            ],
            // `cookie.*` is a prefix wildcard, so it redacts each cookie
            // rather than the bag holding them -- the same reading
            // `EvaluateTrait` gives it for a `cookie.SESS` rule.
            'cookie' => ['SESS9f2' => '[REDACTED]'],
            'note' => 'kept',
        ], json_decode($context, true));
    }

    /**
     * Redaction follows the configured list, not a hardcoded one.
     */
    public function testRedactionFollowsTheConfiguredList(): void
    {
        $original = LoggingFactory::getRedactedVariables();

        try {
            LoggingFactory::setRedactedVariables(['note']);

            $handler = $this->createHandler();
            $handler->handle($this->record(Level::Warning, 'Comparison matched', [
                'note' => 'now secret',
                'header' => ['cookie' => 'no longer redacted'],
            ]));
            $handler->flush();

            self::assertSame([
                'note' => '[REDACTED]',
                'header' => ['cookie' => 'no longer redacted'],
            ], json_decode($this->rows()[0]['context'], true));
        } finally {
            LoggingFactory::setRedactedVariables($original);
        }
    }

    /**
     * A promoted key holding something that is not a scalar stores empty.
     */
    public function testNonScalarPromotedValuesDoNotBreakTheRow(): void
    {
        $handler = $this->createHandler();
        $handler->handle($this->record(Level::Warning, 'Odd context', [
            'client_ip' => ['192.0.2.1'],
            'plugin_name' => null,
        ]));
        $handler->flush();

        $row = $this->rows()[0];

        self::assertSame('', $row['client_ip']);
        self::assertSame('', $row['plugin_name']);
    }

    /**
     * Processor output reaches the blob alongside the remaining context.
     */
    public function testExtraIsStoredAlongsideContext(): void
    {
        $handler = $this->createHandler();
        $handler->handle(new LogRecord(
            new \DateTimeImmutable(),
            'firewall',
            Level::Warning,
            'With extra',
            ['mode' => 'log'],
            ['memory_peak_usage' => '2 MB']
        ));
        $handler->flush();

        self::assertSame(
            ['mode' => 'log', 'memory_peak_usage' => '2 MB'],
            json_decode($this->rows()[0]['context'], true)
        );
    }

    /**
     * Context that will not encode still produces a row.
     */
    public function testUnencodableContextStillWritesARow(): void
    {
        $handler = $this->createHandler();
        $handler->handle($this->record(Level::Warning, 'Broken encoding', [
            'raw' => "\xB1\x31",
        ]));
        $handler->flush();

        $rows = $this->rows();

        self::assertCount(1, $rows);
        self::assertNotSame('', $rows[0]['context']);
    }

    /**
     * The configured table name is the one created and written to.
     */
    public function testTableNameIsConfigurable(): void
    {
        $handler = $this->createHandler(['table' => 'custom_firewall_log']);
        $handler->handle($this->record(Level::Warning, 'Elsewhere'));
        $handler->flush();

        self::assertSame('custom_firewall_log', $handler->getTable());
        self::assertSame(1, (int) $this->connection()->fetchOne('SELECT COUNT(*) FROM custom_firewall_log'));
    }

    /**
     * An unusable table name falls back rather than producing broken SQL.
     *
     */
    #[DataProvider('unusableTableProvider')]
    public function testUnusableTableNameFallsBackToTheDefault(mixed $table): void
    {
        self::assertSame(DatabaseHandler::DEFAULT_TABLE, $this->createHandler(['table' => $table])->getTable());
    }

    /**
     * Table names that cannot be used.
     *
     * @return array<string, array{mixed}>
     */
    public static function unusableTableProvider(): array
    {
        return [
            'empty string' => [''],
            'not a string' => [42],
            'null' => [null],
        ];
    }

    /**
     * A port arriving from YAML as a string is cast for Doctrine.
     */
    public function testNumericPortIsCastToInteger(): void
    {
        $handler = new DatabaseHandler([
            'connection' => ['driver' => 'pdo_mysql', 'host' => 'db', 'port' => '3306'],
        ]);

        self::assertSame(3306, $handler->getConnectionParameters()['port']);
    }

    /**
     * A ready Connection object is accepted, for programmatic wiring.
     */
    public function testAReadyConnectionIsAccepted(): void
    {
        $handler = new DatabaseHandler(['connection' => $this->connection()]);
        $handler->handle($this->record(Level::Warning, 'Injected connection'));
        $handler->flush();

        self::assertCount(1, $this->rows());
    }

    /**
     * With no `connection`, the handler disables itself rather than throwing.
     *
     * A log destination that cannot be reached must not take the firewall down
     * with it, so this is reported and survived rather than raised.
     */
    public function testMissingConnectionDisablesTheHandler(): void
    {
        $handler = new DatabaseHandler(['table' => 'firewall_log', 'retention_days' => 30]);
        $handler->handle($this->record(Level::Warning, 'Nowhere to go'));
        $handler->flush();
        $handler->handle($this->record(Level::Warning, 'Still nowhere'));
        $handler->flush();

        self::assertFileDoesNotExist($this->databasePath);
        self::assertNull($handler->prune());
        self::assertNull($handler->countPrunable());
    }

    /**
     * An unreachable database is a dead handler, not a dead firewall.
     */
    public function testUnreachableDatabaseDisablesTheHandler(): void
    {
        $handler = new DatabaseHandler([
            'connection' => ['driver' => 'pdo_sqlite', 'path' => '/nonexistent/dir/firewall.sqlite'],
        ]);

        $handler->handle($this->record(Level::Warning, 'Unreachable'));
        $handler->flush();

        // The point of the test: no exception escaped, and nothing else in the
        // process had to know the log destination was gone.
        self::assertTrue(true);
    }

    /**
     * The handler's own failures never route back through the firewall logger.
     *
     * `DatabaseTrait` logs through `getLogger()`, and the firewall logger is
     * the one holding this handler — so a failed write reported that way would
     * be handled by the handler that just failed, forever.
     */
    public function testHandlerFailuresDoNotRecurseThroughTheFirewallLogger(): void
    {
        $handler = new DatabaseHandler([
            'connection' => ['driver' => 'pdo_sqlite', 'path' => '/nonexistent/dir/firewall.sqlite'],
        ]);

        $firewallLogger = new Logger('firewall');
        $firewallLogger->pushHandler($handler);
        LoggingFactory::setLogger($firewallLogger);

        $firewallLogger->warning('Request would be blocked (log mode)');
        $handler->flush();

        $internal = self::readProperty($handler, 'internalLogger');

        self::assertInstanceOf(Logger::class, $internal);
        self::assertNotSame($firewallLogger, $internal);
        self::assertSame('firewall.log-handler', $internal->getName());
        self::assertSame($internal, self::readProperty($handler, 'internalLogger'), 'The internal logger is built once');
    }

    /**
     * A write that fails mid-flight stops the handler instead of retrying.
     */
    public function testAFailedInsertDisablesTheHandler(): void
    {
        $handler = $this->createHandler();
        $handler->handle($this->record(Level::Warning, 'Creates the table'));
        $handler->flush();

        $this->connection()->executeStatement('DROP TABLE firewall_log');

        $handler->handle($this->record(Level::Warning, 'Nowhere to land'));
        $handler->flush();

        $handler->handle($this->record(Level::Warning, 'Not retried'));
        $handler->flush();

        self::assertSame(
            [],
            $this->connection()->fetchAllAssociative(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'firewall_log'"
            ),
            'The handler should not have recreated the table by reconnecting'
        );
    }

    /**
     * Rows older than the retention window are deleted, newer ones are not.
     */
    public function testPruneDeletesOnlyRowsOutsideTheRetentionWindow(): void
    {
        $handler = $this->createHandler(['retention_days' => 30, 'prune_probability' => 0]);
        $handler->handle($this->record(Level::Warning, 'Recent'));
        $handler->flush();

        $this->insertAncientRow(31);

        self::assertSame(1, $handler->countPrunable());
        self::assertSame(1, $handler->prune());

        $remaining = $this->rows();

        self::assertCount(1, $remaining);
        self::assertSame('Recent', $remaining[0]['message']);
    }

    /**
     * Without `retention_days`, nothing is ever deleted.
     */
    public function testPruneIsANoOpWithoutRetentionDays(): void
    {
        $handler = $this->createHandler();
        $handler->handle($this->record(Level::Warning, 'Kept forever'));
        $handler->flush();

        self::assertSame(0, $handler->prune());
        self::assertSame(0, $handler->countPrunable());
        self::assertCount(1, $this->rows());
    }

    /**
     * A prune that cannot run is reported as a failure, not as "nothing to do".
     */
    public function testPruneReportsFailureRatherThanZero(): void
    {
        $handler = $this->createHandler(['retention_days' => 1, 'prune_probability' => 0]);
        $handler->handle($this->record(Level::Warning, 'Creates the table'));
        $handler->flush();

        $this->connection()->executeStatement('DROP TABLE firewall_log');

        self::assertNull($handler->countPrunable());

        $handler = $this->createHandler(['retention_days' => 1, 'prune_probability' => 0]);
        $handler->handle($this->record(Level::Warning, 'Creates the table again'));
        $handler->flush();
        $this->connection()->executeStatement('DROP TABLE firewall_log');

        self::assertNull($handler->prune());
    }

    /**
     * `prune_probability: 1` prunes on every flush, with no cron anywhere.
     */
    public function testPruningHappensOnFlushWhenProbabilityIsCertain(): void
    {
        $handler = $this->createHandler(['retention_days' => 30, 'prune_probability' => 1]);
        $handler->handle($this->record(Level::Warning, 'Creates the table'));
        $handler->flush();

        $this->insertAncientRow();

        $handler->handle($this->record(Level::Warning, 'Triggers the prune'));
        $handler->flush();

        self::assertSame(
            ['Creates the table', 'Triggers the prune'],
            array_column($this->rows(), 'message')
        );
    }

    /**
     * `prune_probability: 0` leaves pruning entirely to the CLI script.
     */
    public function testProbabilityZeroNeverPrunesOnFlush(): void
    {
        $handler = $this->createHandler(['retention_days' => 30, 'prune_probability' => 0]);
        $handler->handle($this->record(Level::Warning, 'Creates the table'));
        $handler->flush();

        $this->insertAncientRow();

        $handler->handle($this->record(Level::Warning, 'No prune'));
        $handler->flush();

        self::assertCount(3, $this->rows());
    }

    /**
     * A flush whose roll comes up short leaves the old rows alone.
     *
     * The probability is small enough that the roll cannot succeed: the
     * smallest value `mt_rand(1, PHP_INT_MAX) / PHP_INT_MAX` can produce is
     * about 1.1e-19, so this exercises the "not this time" branch without
     * making the test depend on luck.
     */
    public function testAFlushThatDoesNotWinTheRollPrunesNothing(): void
    {
        $handler = $this->createHandler(['retention_days' => 30, 'prune_probability' => 1.0e-30]);
        $handler->handle($this->record(Level::Warning, 'Creates the table'));
        $handler->flush();

        $this->insertAncientRow();

        $handler->handle($this->record(Level::Warning, 'Rolls, and loses'));
        $handler->flush();

        self::assertCount(3, $this->rows());
    }

    /**
     * Out-of-range knobs are clamped rather than trusted.
     */
    public function testConfigurationIsClamped(): void
    {
        $handler = $this->createHandler([
            'retention_days' => -5,
            'prune_probability' => 7.5,
            'buffer_limit' => -1,
        ]);

        self::assertSame(0, $handler->getRetentionDays());
        self::assertSame(1.0, self::readProperty($handler, 'pruneProbability'));
        self::assertSame(0, self::readProperty($handler, 'bufferLimit'));
    }

    /**
     * A `prune_probability` that is not a number falls back to the default.
     */
    public function testNonNumericPruneProbabilityFallsBackToTheDefault(): void
    {
        self::assertSame(0.01, self::readProperty($this->createHandler(['prune_probability' => 'often']), 'pruneProbability'));
    }

    /**
     * An empty `connection:` reads as "declared none", not as "declared empty".
     */
    public function testEmptyConnectionIsTreatedAsAbsent(): void
    {
        self::assertNull((new DatabaseHandler(['table' => 'firewall_log', 'connection' => []]))->getConnectionParameters());
    }

    /**
     * A connection of an unusable shape is treated as none at all.
     */
    public function testUnusableConnectionIsTreatedAsAbsent(): void
    {
        self::assertNull($this->createHandler(['connection' => 'not-a-connection'])->getConnectionParameters());
    }

    /**
     * Index names carry the table name, because they are schema-wide.
     */
    public function testIndexNamesAreScopedToTheTable(): void
    {
        $handler = $this->createHandler(['table' => 'scoped_log']);
        $handler->handle($this->record(Level::Warning, 'Creates the table'));
        $handler->flush();

        $indexes = $this->connection()->fetchFirstColumn(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'scoped_log'"
        );

        self::assertContains('scoped_log_logged_at_idx', $indexes);
        self::assertContains('scoped_log_client_ip_idx', $indexes);
        self::assertContains('scoped_log_plugin_type_idx', $indexes);
    }

    /**
     * An existing table is written to rather than recreated.
     */
    public function testAnExistingTableIsReused(): void
    {
        $first = $this->createHandler();
        $first->handle($this->record(Level::Warning, 'First run'));
        $first->flush();

        $second = $this->createHandler();
        $second->handle($this->record(Level::Warning, 'Second run'));
        $second->flush();

        self::assertSame(['First run', 'Second run'], array_column($this->rows(), 'message'));
    }

    /**
     * Records handled after the handler is disabled are dropped, not buffered.
     */
    public function testRecordsAreDroppedOnceTheHandlerIsDisabled(): void
    {
        $handler = new DatabaseHandler(['connection' => 'not-a-connection']);
        $handler->handle($this->record(Level::Warning, 'Disables the handler'));
        $handler->flush();
        $handler->handle($this->record(Level::Warning, 'Dropped'));

        $buffer = self::readProperty($handler, 'buffer');

        self::assertSame([], $buffer);
    }

    /**
     * `bubble: false` stops the record reaching handlers below.
     */
    public function testBubbleIsConfigurable(): void
    {
        self::assertTrue($this->createHandler(['bubble' => false])->handle($this->record(Level::Warning, 'Stops here')));
        self::assertFalse($this->createHandler()->handle($this->record(Level::Warning, 'Carries on')));
    }

    /**
     * Insert a row old enough for the retention window to exclude it.
     *
     * @param int $daysAgo
     *   How far back to date the row.
     */
    private function insertAncientRow(int $daysAgo = 60): void
    {
        $this->connection()->insert('firewall_log', [
            'logged_at' => time() - ($daysAgo * 86400),
            'level' => 'WARNING',
            'level_value' => Level::Warning->value,
            'channel' => 'firewall',
            'message' => 'Ancient',
            'request_id' => '',
            'client_ip' => '',
            'plugin_name' => '',
            'plugin_type' => '',
            'method' => '',
            'path' => '',
            'host' => '',
            'user_agent' => '',
            'context' => '{}',
        ]);
    }

    /**
     * Read a private property, for the few pieces with no public accessor.
     */
    private static function readProperty(DatabaseHandler $handler, string $property): mixed
    {
        return (new \ReflectionProperty(DatabaseHandler::class, $property))->getValue($handler);
    }

    /**
     * Build a handler pointed at this test's SQLite file.
     *
     * @param array<string, mixed> $config
     *   Configuration overrides.
     */
    private function createHandler(array $config = []): DatabaseHandler
    {
        return new DatabaseHandler($config + [
            'table' => 'firewall_log',
            'connection' => ['driver' => 'pdo_sqlite', 'path' => $this->databasePath],
        ]);
    }

    /**
     * Build a log record.
     *
     * @param array<string, mixed> $context
     *   Record context.
     */
    private function record(Level $level, string $message, array $context = []): LogRecord
    {
        return new LogRecord(new \DateTimeImmutable(), 'firewall', $level, $message, $context);
    }

    /**
     * Open a second connection to this test's SQLite file.
     */
    private function connection(): Connection
    {
        return DriverManager::getConnection([
            'driver' => 'pdo_sqlite',
            'path' => $this->databasePath,
        ]);
    }

    /**
     * Return every row in the log table, oldest first.
     *
     * @return array<int, array<string, mixed>>
     *   Rows, or an empty list when the table does not exist yet.
     */
    private function rows(string $table = 'firewall_log'): array
    {
        if (!is_file($this->databasePath)) {
            return [];
        }

        try {
            return $this->connection()->fetchAllAssociative(sprintf('SELECT * FROM %s ORDER BY id', $table));
        } catch (\Throwable) {
            return [];
        }
    }
}
