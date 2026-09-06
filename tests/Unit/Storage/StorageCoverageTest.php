<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Covers the storage branches the feature suites do not reach.
 *
 * Mostly the defensive reads: an offense record written by an older build, a
 * timestamp that is not a timestamp, a connection whose parameters cannot be
 * described. Storage is the one component that outlives a deploy, so the code
 * that copes with what a previous version wrote is exactly the code worth
 * having tests on.
 */
class StorageCoverageTest extends AbstractTestCase
{
    /**
     * A fixed moment, used wherever an exact timestamp is asserted.
     */
    private const MOMENT = 1_760_000_000;

    /**
     * Seed an offense list directly, bypassing recordOffense().
     *
     * The point of these tests is what happens when the store holds something
     * the current build would not have written.
     *
     * @param array<int, mixed> $offenses
     *   Raw offense entries.
     */
    private function storageHolding(array $offenses): InMemoryStorage
    {
        $storage = new InMemoryStorage();

        $property = new \ReflectionProperty(InMemoryStorage::class, 'offenses');
        $property->setAccessible(true);
        $property->setValue($storage, ['1.2.3.4' => $offenses]);

        return $storage;
    }

    /**
     * Entries that are not usable offense records are skipped.
     *
     * @param array<int, mixed> $offenses
     *   Raw offense entries that should all be ignored.
     */
    #[DataProvider('unusableOffenseProvider')]
    public function testUnusableOffenceRecordsAreSkipped(array $offenses): void
    {
        $this->assertSame([], $this->storageHolding($offenses)->listOffenses('1.2.3.4'));
    }

    /**
     * Shapes a store might hold that carry no usable moment.
     */
    public static function unusableOffenseProvider(): array
    {
        return [
            'not an array' => [['a string', 42, null]],
            'no timestamp key' => [[['request' => '/x']]],
            'unparseable timestamp' => [[['timestamp' => 'the day before yesterday']]],
        ];
    }

    /**
     * A timestamp stored as an integer by an older build still reads.
     */
    public function testIntegerTimestampsFromAnOlderBuildAreRead(): void
    {
        $moment = 1_760_000_000;

        $this->assertSame(
            [$moment],
            $this->storageHolding([['timestamp' => $moment]])->listOffenses('1.2.3.4')
        );
    }

    /**
     * Offences outside the window are excluded from either end.
     */
    public function testOffencesOutsideTheWindowAreExcluded(): void
    {
        $storage = $this->storageHolding([
            ['timestamp' => 1_000],
            ['timestamp' => 5_000],
            ['timestamp' => 9_000],
        ]);

        $this->assertSame([5000], $storage->listOffenses('1.2.3.4', 2_000, 8_000));
        $this->assertSame([9000, 5000], $storage->listOffenses('1.2.3.4', 2_000));
        $this->assertSame([5000, 1000], $storage->listOffenses('1.2.3.4', 0, 8_000));
    }

    /**
     * A key with no offences at all lists nothing.
     */
    public function testUnknownKeyListsNothing(): void
    {
        $this->assertSame([], (new InMemoryStorage())->listOffenses('9.9.9.9'));
    }

    /**
     * A connection target is described without its credentials.
     *
     * @param array<string, mixed> $params
     *   Connection parameters.
     * @param string $expected
     *   The description they should produce.
     */
    #[DataProvider('connectionTargetProvider')]
    public function testConnectionTargetsAreDescribedWithoutCredentials(array $params, string $expected): void
    {
        $method = new \ReflectionMethod(
            \Kanopi\Firewall\Storage\DatabaseStorage::class,
            'describeConnectionTarget'
        );
        $method->setAccessible(true);

        $description = (string) $method->invoke(null, $params);

        $this->assertSame($expected, $description);
        $this->assertStringNotContainsString('hunter2', $description);
    }

    /**
     * Parameter sets and how each should read back.
     */
    public static function connectionTargetProvider(): array
    {
        return [
            'host and port' => [
                ['driver' => 'pdo_mysql', 'host' => 'db', 'port' => 3306, 'dbname' => 'app',
                    'user' => 'root', 'password' => 'hunter2'],
                'driver=pdo_mysql host=db port=3306 dbname=app',
            ],
            'sqlite in memory, boolean rendered' => [
                ['driver' => 'pdo_sqlite', 'memory' => true],
                'driver=pdo_sqlite memory=true',
            ],
            'boolean false still renders' => [
                ['driver' => 'pdo_sqlite', 'memory' => false],
                'driver=pdo_sqlite memory=false',
            ],
            'nothing describable' => [
                ['user' => 'root', 'password' => 'hunter2'],
                'no connection parameters',
            ],
            'dsn is described by its parts' => [
                ['dsn' => 'mysql://root:hunter2@db:3306/app'],
                'scheme=mysql host=db port=3306 path=/app',
            ],
            // parse_url() yields a bare path for anything scheme-less, so a
            // stray word is described rather than rejected.
            'dsn without a scheme' => [
                ['dsn' => 'nonsense'],
                'path=nonsense',
            ],
            // It fails outright on a handful of malformed forms, and those are
            // the ones that report as unparseable.
            'dsn parse_url rejects' => [
                ['dsn' => 'http://:80'],
                'unparseable dsn',
            ],
        ];
    }

    /**
     * A live Connection is described from the parameters it was built with.
     */
    public function testALiveConnectionDescribesItself(): void
    {
        $connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);

        $method = new \ReflectionMethod(
            \Kanopi\Firewall\Storage\DatabaseStorage::class,
            'describeConnectionTarget'
        );
        $method->setAccessible(true);

        $this->assertInstanceOf(Connection::class, $connection);
        $this->assertStringContainsString('pdo_sqlite', (string) $method->invoke(null, $connection));
    }

    /**
     * A timestamp is normalised on the way into the database.
     *
     * The column is an integer, and callers hand over an ISO-8601 string, a
     * Unix timestamp, or nothing at all. A failed parse used to store 0, which
     * reads back as 1970 — so it falls back to "now" instead.
     *
     * @param mixed $given
     *   What the caller supplied.
     * @param bool $exact
     *   Whether the stored value should equal self::MOMENT exactly, or merely
     *   be recent.
     */
    #[DataProvider('timestampProvider')]
    public function testTimestampsAreNormalisedOnWrite(mixed $given, bool $exact): void
    {
        $storage = new \Kanopi\Firewall\Storage\DatabaseStorage([
            'connection' => ['dsn' => 'sqlite3:///:memory:'],
            'storage_table' => 'firewall_storage',
        ]);

        $storage->set('1.2.3.4', ['request' => ['path' => '/x'], 'timestamp' => $given]);

        $stored = (int) ($storage->get('1.2.3.4')['timestamp'] ?? 0);

        if ($exact) {
            $this->assertSame(self::MOMENT, $stored);

            return;
        }

        $this->assertGreaterThan(time() - 60, $stored, 'An unusable timestamp must not read back as 1970.');
    }

    /**
     * Timestamp inputs, and whether each should land on MOMENT exactly.
     */
    public static function timestampProvider(): array
    {
        return [
            'unix timestamp passes through' => [self::MOMENT, true],
            'numeric string passes through' => [(string) self::MOMENT, true],
            'iso-8601 is parsed' => [gmdate('c', self::MOMENT), true],
            'unparseable falls back to now, never 1970' => ['the day before yesterday', false],
            'missing falls back to now' => [null, false],
        ];
    }
}
