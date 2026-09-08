<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Traits;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Storage\DatabaseStorage;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * The table-existence memo (#227).
 *
 * `createTable()` runs from `connect()`, which runs on every construction — so on every
 * request — and asked `information_schema` once per declared table. `DatabaseStorage`
 * declares two, and a deployment using database storage together with the database log
 * handler asked four times per request.
 *
 * Free on a local socket, and not over a network: measured at 0.7314 ms per construction
 * against MariaDB and 0.3985 ms once memoised.
 */
class DatabaseTableMemoTest extends AbstractTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        LoggingFactory::setLogger(LoggingFactory::create([
            ['class' => TestLogHandler::class],
        ]));

        $this->forgetKnownTables();
    }

    protected function tearDown(): void
    {
        $this->forgetKnownTables();
        parent::tearDown();
    }

    /**
     * The memo is static and outlives an instance, so tests must clear it or
     * they answer for each other.
     */
    private function forgetKnownTables(): void
    {
        // Reflected on the class, not the trait. A static trait property
        // belongs to each class that uses the trait, and PHP 8.3 deprecates
        // reaching for it through the trait itself.
        $property = new \ReflectionProperty(DatabaseStorage::class, 'tablesKnownToExist');
        $property->setAccessible(true);
        $property->setValue(null, []);
    }

    /**
     * A file-backed SQLite database, so the schema survives between connections.
     */
    private function config(string $path): array
    {
        return ['connection' => ['driver' => 'pdo_sqlite', 'path' => $path]];
    }

    /**
     * How many times the database was asked about a table.
     *
     * Either message means the check ran: a fresh database creates, an existing
     * one confirms. Counting only one of them measures whichever branch the
     * fixture happened to take.
     */
    private function existenceChecks(): int
    {
        $handler = LoggingFactory::logger()->getHandlers()[0];

        return count(array_filter(
            $handler->records,
            static fn ($record): bool => str_contains((string) $record->message, 'Database table already exists')
                || str_contains((string) $record->message, 'Database table created')
        ));
    }

    /**
     * Forget what has been logged, so a count measures one construction.
     */
    private function forgetLogs(): void
    {
        LoggingFactory::logger()->getHandlers()[0]->records = [];
    }

    /**
     * The second construction does not ask the database again.
     */
    public function testTablesAreConfirmedOncePerProcess(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'fwmemo') . '.sqlite';

        try {
            new DatabaseStorage($this->config($path));
            $this->assertGreaterThan(0, $this->existenceChecks(), 'The first construction asks');

            $this->forgetLogs();
            new DatabaseStorage($this->config($path));

            $this->assertSame(
                0,
                $this->existenceChecks(),
                'A second construction must not ask information_schema again'
            );
        } finally {
            @unlink($path);
        }
    }

    /**
     * Two databases do not answer for each other.
     *
     * A block list on one connection and a log handler on another is an
     * ordinary deployment, and a bare table name would let the first confirm
     * tables that only exist on it.
     */
    public function testTheMemoIsScopedToTheConnection(): void
    {
        $first = tempnam(sys_get_temp_dir(), 'fwmemo_a') . '.sqlite';
        $second = tempnam(sys_get_temp_dir(), 'fwmemo_b') . '.sqlite';

        try {
            new DatabaseStorage($this->config($first));

            $this->forgetLogs();
            new DatabaseStorage($this->config($second));

            $this->assertGreaterThan(
                0,
                $this->existenceChecks(),
                'A different database must be checked on its own'
            );
        } finally {
            @unlink($first);
            @unlink($second);
        }
    }

    /**
     * Clearing the memo makes it ask again, which is what proves the skip is
     * the memo rather than something else quietly caching.
     */
    public function testClearingTheMemoRestoresTheCheck(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'fwmemo_c') . '.sqlite';

        try {
            new DatabaseStorage($this->config($path));

            $this->forgetKnownTables();
            $this->forgetLogs();
            new DatabaseStorage($this->config($path));

            $this->assertGreaterThan(
                0,
                $this->existenceChecks(),
                'Clearing the memo should make it ask again'
            );
        } finally {
            @unlink($path);
        }
    }
}
