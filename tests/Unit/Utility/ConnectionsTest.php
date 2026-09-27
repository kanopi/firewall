<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Doctrine\DBAL\Connection;
use Kanopi\Firewall\Diagnostics\ConfigLinter;
use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Diagnostics\Doctor;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Logging\Handler\DatabaseHandler;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Storage\DatabaseStorage;
use Kanopi\Firewall\Utility\BlockList;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\Connections;
use Kanopi\Firewall\Utility\DatabaseConsumers;
use Kanopi\Firewall\Utility\DegradedBackends;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Connections declared once, and handed over by name (#395).
 *
 * Runs without a cache server. SQLite stands in for "a connection" wherever the kind does
 * not matter, since DBAL ships it. Memcached and Redis against real servers are
 * `NamedConnectionsIntegrationTest`.
 */
final class ConnectionsTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();

        DegradedBackends::reset();
        $this->dir = sys_get_temp_dir() . '/fw-connections-' . uniqid();
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        DegradedBackends::reset();

        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->dir);

        parent::tearDown();
    }

    /**
     * @return array<string, mixed>
     */
    private function sqlite(): array
    {
        return ['driver' => 'pdo_sqlite', 'path' => $this->dir . '/firewall.sqlite'];
    }

    // -----------------------------------------------------------------------
    // Resolution
    // -----------------------------------------------------------------------

    /**
     * The common configuration names no connection, and is returned untouched.
     */
    public function testAConfigurationWithNoReferenceIsReturnedAsItIs(): void
    {
        $config = ['storage' => ['type' => 'X', 'config' => ['path' => '/tmp/x']], 'connections' => ['db' => $this->sqlite()]];

        $this->assertSame($config, Connections::resolveIn($config));
    }

    public function testAReferenceBecomesTheConnection(): void
    {
        $resolved = Connections::resolveIn([
            'connections' => ['db' => $this->sqlite()],
            'storage' => ['config' => ['connection' => '%connection(db)%']],
        ]);

        $this->assertInstanceOf(Connection::class, $resolved['storage']['config']['connection']);
    }

    /**
     * Two references to one name are one connection -- the point of naming it.
     */
    public function testTwoReferencesShareOneConnection(): void
    {
        $resolved = Connections::resolveIn([
            'connections' => ['db' => $this->sqlite()],
            'storage' => ['config' => ['connection' => '%connection(db)%']],
            'logger' => [['class' => 'X', 'args' => [['connection' => '%connection(db)%']]]],
        ]);

        $this->assertSame($resolved['storage']['config']['connection'], $resolved['logger'][0]['args'][0]['connection']);
    }

    /**
     * Two resolutions -- two firewalls in one process -- never share by accident.
     */
    public function testTwoResolutionsDoNotShare(): void
    {
        $config = ['connections' => ['db' => $this->sqlite()], 'storage' => ['connection' => '%connection(db)%']];

        $this->assertNotSame(
            Connections::resolveIn($config)['storage']['connection'],
            Connections::resolveIn($config)['storage']['connection']
        );
    }

    /**
     * The block that declares the names is where they are declared, not where they are used.
     */
    public function testTheConnectionsBlockIsNotResolved(): void
    {
        $resolved = Connections::resolveIn([
            'connections' => ['db' => $this->sqlite(), 'alias' => '%connection(db)%'],
            'storage' => ['connection' => '%connection(db)%'],
        ]);

        $this->assertSame('%connection(db)%', $resolved['connections']['alias']);
    }

    public function testAnUndeclaredNameIsRefusedAndTheDeclaredOnesListed(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('Connection "dbb" is referenced but not declared under connections: (declared: db)');

        Connections::resolveIn(['connections' => ['db' => $this->sqlite()], 'storage' => ['connection' => '%connection(dbb)%']]);
    }

    public function testAnUndeclaredNameWithNothingDeclared(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('Connection "db" is referenced but not declared under connections:');

        Connections::resolveIn(['storage' => ['connection' => '%connection(db)%']]);
    }

    /**
     * A connection is an object; spliced into a string it would be the word "Object".
     */
    public function testAReferenceInsideAStringIsRefused(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('logger.0.args.0: %connection(...)% must be the whole value');

        Connections::resolveIn([
            'connections' => ['db' => $this->sqlite()],
            'logger' => [['args' => ['prefix-%connection(db)%']]],
        ]);
    }

    /**
     * Nothing referenced, nothing built -- even a declaration that could not be built.
     */
    public function testAnUnreferencedConnectionIsNeverBuilt(): void
    {
        $resolved = Connections::resolveIn([
            'connections' => ['db' => $this->sqlite(), 'broken' => ['driver' => 'no_such_driver']],
            'storage' => ['connection' => '%connection(db)%'],
        ]);

        $this->assertInstanceOf(Connection::class, $resolved['storage']['connection']);
    }

    // -----------------------------------------------------------------------
    // Declarations
    // -----------------------------------------------------------------------

    /**
     * @return array<string, array{0: mixed}>
     */
    public static function provideDatabaseDeclarations(): array
    {
        return [
            'driver and parameters' => [['driver' => 'pdo_sqlite', 'memory' => true]],
            'a DSN in a map' => [['dsn' => 'pdo-sqlite:///:memory:']],
            'a DSN on its own' => ['pdo-sqlite:///:memory:'],
        ];
    }

    #[DataProvider('provideDatabaseDeclarations')]
    public function testADatabaseIsDeclaredInEveryDocumentedForm(mixed $declaration): void
    {
        $connection = (new Connections(['db' => $declaration]))->get('db');

        $this->assertInstanceOf(Connection::class, $connection);
        $this->assertSame(1, (int) $connection->fetchOne('SELECT 1'));
    }

    /**
     * @return array<string, array{0: mixed, 1: string}>
     */
    public static function provideUnbuildableDeclarations(): array
    {
        return [
            'not a DSN or a map' => [42, 'must be a DSN or a map, not int'],
            'no driver' => [['host' => 'db.internal'], 'names no driver'],
            'an unknown driver' => [['driver' => 'no_such_driver'], 'could not be built'],
        ];
    }

    /**
     * A database connection connects on first use, so the only thing that can fail when
     * building one is a declaration that describes no database -- a configuration error.
     */
    #[DataProvider('provideUnbuildableDeclarations')]
    public function testADeclarationThatDescribesNoConnectionIsRefused(mixed $declaration, string $message): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($message);

        (new Connections(['db' => $declaration]))->get('db');
    }

    /**
     * Where the extension is missing, a Memcached or Redis connection degrades -- it does
     * not stop the firewall starting (#356) -- and says which fix it needs.
     *
     * @return array<string, array{0: string, 1: string}>
     */
    public static function provideCacheServers(): array
    {
        return [
            'memcached' => ['memcached://127.0.0.1:11211', 'memcached'],
            'redis' => ['redis://127.0.0.1:6379', 'redis'],
        ];
    }

    #[DataProvider('provideCacheServers')]
    public function testAMissingExtensionDegradesAndIsNamed(string $dsn, string $extension): void
    {
        if (extension_loaded($extension)) {
            $this->markTestSkipped(sprintf('Asserts what happens without ext-%s, and it is loaded here.', $extension));
        }

        $connections = new Connections(['cache' => $dsn]);

        $this->assertNull($connections->get('cache'));

        $degraded = DegradedBackends::all();
        $this->assertCount(1, $degraded);
        $this->assertSame('named connection', $degraded[0]['component']);
        $this->assertStringContainsString(sprintf('the %s extension is not installed', $extension), $degraded[0]['error']);
        $this->assertStringContainsString('could not be built', (string) $connections->probe('cache'));
    }

    // -----------------------------------------------------------------------
    // Reports
    // -----------------------------------------------------------------------

    /**
     * @return array<string, array{0: mixed, 1: string}>
     */
    public static function provideDescriptions(): array
    {
        return [
            'a DSN with a password' => ['redis://:s3cret@cache:6379/0', 'redis://***@cache:6379/0'],
            'a map with a DSN' => [['dsn' => 'memcached://u:s3cret@cache:11211'], 'memcached://***@cache:11211'],
            'database parameters' => [['driver' => 'pdo_mysql', 'host' => 'db.internal', 'dbname' => 'fw', 'user' => 'u', 'password' => 's3cret'], 'pdo_mysql://db.internal/fw'],
            'a file database' => [['driver' => 'pdo_sqlite', 'path' => '/var/fw.sqlite'], 'pdo_sqlite:///var/fw.sqlite'],
            'nothing but a driver' => [['memory' => true], 'database://localhost'],
            'not a declaration' => [42, 'int'],
        ];
    }

    #[DataProvider('provideDescriptions')]
    public function testADescriptionNeverCarriesCredentials(mixed $declaration, string $expected): void
    {
        $described = (new Connections(['c' => $declaration]))->describe('c');

        $this->assertSame($expected, $described);
        $this->assertStringNotContainsString('s3cret', $described);
    }

    public function testAProbeReportsWhetherTheServerAnswers(): void
    {
        $connections = new Connections([
            'db' => $this->sqlite(),
            'unreachable' => ['driver' => 'pdo_sqlite', 'path' => '/nonexistent/dir/fw.sqlite'],
            'broken' => ['host' => 'nowhere'],
        ]);

        $this->assertNull($connections->probe('db'));
        $this->assertNotNull($connections->probe('unreachable'));
        $this->assertStringContainsString('names no driver', (string) $connections->probe('broken'));
    }

    public function testUndeclaredReferencesAreFoundWithoutBuildingAnything(): void
    {
        $this->assertSame(['dbb', 'cache'], Connections::undeclaredReferences([
            'connections' => ['db' => ['driver' => 'no_such_driver']],
            'storage' => ['connection' => '%connection(dbb)%'],
            'logger' => [['args' => ['%connection(cache)%', '%connection(dbb)%', '%connection(db)%']]],
        ]));
    }

    // -----------------------------------------------------------------------
    // Where they are resolved
    // -----------------------------------------------------------------------

    /**
     * The token survives loading and the compiled config cache as a string, and is only
     * made an object where components are built (#259).
     */
    public function testLoadingLeavesTheReferenceAString(): void
    {
        $this->assertSame(
            '%connection(db)%',
            Config::load([['connections' => ['db' => $this->sqlite()], 'storage' => ['config' => ['connection' => '%connection(db)%']]]])['storage']['config']['connection']
        );
    }

    /**
     * The storage and the database log handler on one named connection, through the whole
     * firewall -- the case #184 opened with, now sharing the connection itself.
     */
    public function testTheFirewallSharesOneConnectionBetweenStorageAndLogger(): void
    {
        $firewall = Firewall::create([[
            'connections' => ['db' => $this->sqlite()],
            'storage' => ['type' => DatabaseStorage::class, 'config' => ['connection' => '%connection(db)%']],
            'logger' => [['class' => DatabaseHandler::class, 'args' => [['table' => 'firewall_log', 'connection' => '%connection(db)%']]]],
            'global' => ['mode' => 'exception'],
        ]]);

        $handler = LoggingFactory::logger()->getHandlers()[0] ?? null;
        $this->assertInstanceOf(DatabaseHandler::class, $handler);

        $storage = (new \ReflectionProperty(Firewall::class, 'storage'))->getValue($firewall);
        $this->assertInstanceOf(DatabaseStorage::class, $storage);

        // The handler connects on its first write, so what it holds until then is
        // the connection it was given -- which must be the one the storage uses.
        $handed = (new \ReflectionProperty(DatabaseHandler::class, 'connectionParameters'))->getValue($handler);
        $this->assertInstanceOf(Connection::class, $handed);
        $this->assertSame($this->connectionOf($storage), $handed);
    }

    public function testTheFirewallRefusesToStartWithAnUndeclaredName(): void
    {
        $this->expectException(ConfigurationException::class);

        Firewall::create([[
            'storage' => ['type' => DatabaseStorage::class, 'config' => ['connection' => '%connection(db)%']],
            'global' => ['mode' => 'exception'],
        ]]);
    }

    public function testTheBlockListResolvesItsStorageConnection(): void
    {
        $storage = (new BlockList([[
            'connections' => ['db' => $this->sqlite()],
            'storage' => ['type' => DatabaseStorage::class, 'config' => ['connection' => '%connection(db)%']],
        ]]))->storage();

        $this->assertInstanceOf(DatabaseStorage::class, $storage);
    }

    public function testTheMaintenanceCommandsResolveTheirConnections(): void
    {
        $built = DatabaseConsumers::fromConfig([
            'connections' => ['db' => $this->sqlite()],
            'storage' => ['type' => DatabaseStorage::class, 'config' => ['connection' => '%connection(db)%']],
        ]);

        $this->assertInstanceOf(DatabaseStorage::class, $built['consumers']['storage'] ?? null);
    }

    public function testTheLinterReportsAnUndeclaredName(): void
    {
        $findings = (new ConfigLinter([[
            'storage' => ['config' => ['connection' => '%connection(db)%']],
            'plugins' => [],
        ]]))->run();

        $this->assertContains(
            'Connection "db" is referenced but not declared',
            array_map(static fn (Diagnosis $d): string => $d->title, $findings)
        );
    }

    public function testTheDoctorReportsEachDeclaredConnection(): void
    {
        $findings = (new Doctor([[
            'connections' => ['db' => $this->sqlite(), 'gone' => ['driver' => 'pdo_sqlite', 'path' => '/nonexistent/dir/fw.sqlite']],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'global' => ['mode' => 'block'],
            'plugins' => [],
        ]]))->run();

        $byTitle = [];
        foreach ($findings as $finding) {
            $byTitle[$finding->title] = $finding;
        }

        $this->assertSame(Diagnosis::OK, $byTitle['Connection db answers']->status ?? null);
        $this->assertSame(Diagnosis::ERROR, $byTitle['Connection gone could not be reached']->status ?? null);
    }

    /**
     * The connection a DatabaseTrait consumer holds.
     */
    private function connectionOf(object $consumer): Connection
    {
        $property = new \ReflectionProperty($consumer, 'connection');

        return $property->getValue($consumer);
    }
}
