<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\ConfigReference;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * `%config(...)%` references (#184).
 */
class ConfigReferenceTest extends AbstractTestCase
{
    /**
     * Temporary config files to remove after each test.
     *
     * @var array<int, string>
     */
    private array $tempFiles = [];

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();

        Config::clearLoadErrors();
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $file) {
            @unlink($file);
        }

        $this->tempFiles = [];

        Config::clearLoadErrors();

        parent::tearDown();
    }

    /**
     * A whole-value reference keeps the referenced value's type.
     *
     * This is the case the feature exists for: a connection is an array, and
     * substituting a string representation of one would be useless.
     */
    public function testAWholeValueReferenceReturnsAnArrayIntact(): void
    {
        $connection = ['driver' => 'pdo_mysql', 'host' => 'db', 'port' => 3306];

        $resolved = ConfigReference::resolve([
            'storage' => ['config' => ['connection' => $connection]],
            'logger' => [['args' => [['connection' => '%config(storage.config.connection)%']]]],
        ]);

        self::assertSame($connection, $resolved['logger'][0]['args'][0]['connection']);
    }

    /**
     * Scalars keep their type too, rather than becoming strings.
     */
    public function testAWholeValueReferenceKeepsScalarTypes(): void
    {
        $resolved = ConfigReference::resolve([
            'a' => ['port' => 3306, 'on' => true, 'ratio' => 0.5, 'none' => null],
            'b' => [
                'port' => '%config(a.port)%',
                'on' => '%config(a.on)%',
                'ratio' => '%config(a.ratio)%',
                'none' => '%config(a.none)%',
            ],
        ]);

        self::assertSame(3306, $resolved['b']['port']);
        self::assertTrue($resolved['b']['on']);
        self::assertSame(0.5, $resolved['b']['ratio']);
        self::assertNull($resolved['b']['none']);
    }

    /**
     * A reference inside a larger string is interpolated.
     */
    public function testAReferenceInsideAStringIsInterpolated(): void
    {
        $resolved = ConfigReference::resolve([
            'a' => ['host' => 'db.internal'],
            'b' => 'mysql://%config(a.host)%:3306',
        ]);

        self::assertSame('mysql://db.internal:3306', $resolved['b']);
    }

    /**
     * List indexes are addressable, so a reference can point into `logger:`.
     */
    public function testAListIndexIsAValidSegment(): void
    {
        $resolved = ConfigReference::resolve([
            'logger' => [['args' => [['table' => 'firewall_log']]]],
            'copy' => '%config(logger.0.args.0.table)%',
        ]);

        self::assertSame('firewall_log', $resolved['copy']);
    }

    /**
     * A reference to a reference resolves through.
     */
    public function testReferencesChain(): void
    {
        $resolved = ConfigReference::resolve([
            'a' => 'value',
            'b' => '%config(a)%',
            'c' => '%config(b)%',
        ]);

        self::assertSame('value', $resolved['c']);
    }

    /**
     * A config with no references comes back exactly as it went in.
     */
    public function testAConfigWithoutReferencesIsUnchanged(): void
    {
        $config = [
            'storage' => ['config' => ['connection' => ['driver' => 'pdo_mysql']]],
            'global' => ['mode' => 'block', 'behind_proxy' => false],
            'plugins' => [['plugin' => 'X', 'config' => ['203.0.113.0/24']]],
        ];

        $problems = [];

        self::assertSame($config, ConfigReference::resolve($config, $problems));
        self::assertSame([], $problems);
    }

    /**
     * A `%` that is not a reference is left alone.
     *
     * `%env()%` and `%file()%` have already been resolved per file by the time
     * this runs, but a literal percent in a message or a rule must survive.
     */
    public function testUnrelatedPercentSignsAreUntouched(): void
    {
        $config = [
            'global' => [
                'banning_message' => 'Blocked: 100% of your requests',
                'pattern' => '%env(NOT_RESOLVED)%',
            ],
        ];

        self::assertSame($config, ConfigReference::resolve($config));
    }

    /**
     * A reference that resolves to nothing is reported and left in place.
     *
     * Left as its literal token rather than replaced with NULL: whatever reads
     * it then fails in its own terms with its own message, instead of the
     * value looking like something that was never configured.
     *
     * @param array<array-key, mixed> $config
     *   Config containing the bad reference.
     * @param string $expectedMessage
     *   Fragment the reported problem must contain.
     */
    #[DataProvider('unresolvableProvider')]
    public function testAnUnresolvableReferenceIsReportedAndLeftInPlace(array $config, string $expectedMessage): void
    {
        $problems = [];
        $resolved = ConfigReference::resolve($config, $problems);

        self::assertSame($config['b'], $resolved['b'], 'The literal token should survive');
        self::assertNotSame([], $problems);
        self::assertStringContainsString($expectedMessage, implode("\n", $problems));
    }

    /**
     * References that cannot be resolved, and what should be said about each.
     *
     * @return array<string, array{array<array-key, mixed>, string}>
     *   Provider sets, keyed by what is wrong.
     */
    public static function unresolvableProvider(): array
    {
        return [
            'a path that does not exist' => [
                ['a' => ['x' => 1], 'b' => '%config(a.nope)%'],
                'points at nothing',
            ],
            'a path through a scalar' => [
                ['a' => 'scalar', 'b' => '%config(a.deeper)%'],
                'points at nothing',
            ],
            'no path at all' => [
                ['a' => 1, 'b' => '%config()%'],
                'names no path',
            ],
            'a direct cycle' => [
                ['a' => 1, 'b' => '%config(b)%'],
                'is circular',
            ],
            'an array interpolated into a string' => [
                ['a' => ['x' => 1], 'b' => 'value is %config(a)%'],
                'cannot be interpolated into a string',
            ],
        ];
    }

    /**
     * A cycle between two keys terminates rather than exhausting the stack.
     */
    public function testAnIndirectCycleIsReportedRatherThanRecursing(): void
    {
        $problems = [];

        $resolved = ConfigReference::resolve([
            'a' => '%config(b)%',
            'b' => '%config(a)%',
        ], $problems);

        self::assertSame('%config(b)%', $resolved['a']);
        self::assertStringContainsString('a -> b -> a', implode("\n", $problems));
    }

    /**
     * One bad reference does not stop the others resolving.
     */
    public function testOneBadReferenceDoesNotSpoilTheRest(): void
    {
        $problems = [];

        $resolved = ConfigReference::resolve([
            'a' => ['driver' => 'pdo_mysql'],
            'good' => '%config(a.driver)%',
            'bad' => '%config(a.missing)%',
        ], $problems);

        self::assertSame('pdo_mysql', $resolved['good']);
        self::assertSame('%config(a.missing)%', $resolved['bad']);
        self::assertCount(1, $problems);
    }

    /**
     * References cross a `configs:` include, which is the whole point.
     *
     * A YAML anchor already deduplicates within one file and stays the right
     * answer there. It cannot span two, because each file is parsed on its
     * own -- and splitting `storage:` and `logger:` across included files is a
     * normal way to organise this project's configuration.
     */
    public function testAReferenceCrossesAnIncludeBoundary(): void
    {
        $directory = sys_get_temp_dir() . '/fw-ref-' . uniqid('', true);
        mkdir($directory);

        $this->write("$directory/storage.yml", <<<'YAML'
        storage:
          type: "Kanopi\\Firewall\\Storage\\DatabaseStorage"
          config:
            connection:
              driver: pdo_sqlite
              path: /tmp/firewall-reference-test.sqlite
        YAML);

        $this->write("$directory/logging.yml", <<<'YAML'
        logger:
          - class: "Kanopi\\Firewall\\Logging\\Handler\\DatabaseHandler"
            args:
              - table: firewall_log
                connection: "%config(storage.config.connection)%"
        YAML);

        $main = "$directory/main.yml";
        $this->write($main, <<<'YAML'
        configs:
          - "storage.yml"
          - "logging.yml"
        YAML);

        $config = Config::load([$main]);

        self::assertSame(
            ['driver' => 'pdo_sqlite', 'path' => '/tmp/firewall-reference-test.sqlite'],
            $config['logger'][0]['args'][0]['connection']
        );
        self::assertSame([], Config::getLoadWarnings());

        @rmdir($directory);
    }

    /**
     * `%env()%` resolves through a reference.
     *
     * The two tokens run at different times -- `%env()%` per file during the
     * parse, references once after the merge -- so the referenced value is
     * already resolved by the time it is copied. Worth pinning: the reverse
     * order would copy an unresolved token and leave credentials looking like
     * literal strings.
     */
    public function testEnvironmentTokensAreResolvedBeforeBeingReferenced(): void
    {
        putenv('FW_REFERENCE_TEST_HOST=db.internal');

        try {
            $file = $this->tempFile();
            $this->write($file, <<<'YAML'
            storage:
              config:
                connection:
                  host: "%env(FW_REFERENCE_TEST_HOST)%"
            logger:
              - args:
                  - connection: "%config(storage.config.connection)%"
            YAML);

            $config = Config::load([$file]);

            self::assertSame(['host' => 'db.internal'], $config['logger'][0]['args'][0]['connection']);
        } finally {
            putenv('FW_REFERENCE_TEST_HOST');
        }
    }

    /**
     * References are resolved after overrides, so an override can write one.
     */
    public function testAnOverrideCanWriteAReference(): void
    {
        $file = $this->tempFile();
        $this->write($file, <<<'YAML'
        storage:
          config:
            connection:
              driver: pdo_sqlite
        YAML);

        $config = Config::load([$file], [
            '[logger][0][args][0][connection]' => '%config(storage.config.connection)%',
        ]);

        self::assertSame(['driver' => 'pdo_sqlite'], $config['logger'][0]['args'][0]['connection']);
    }

    /**
     * A reference sees the value an override replaced, not the original.
     */
    public function testAReferenceSeesOverriddenValues(): void
    {
        $file = $this->tempFile();
        $this->write($file, <<<'YAML'
        storage:
          config:
            connection:
              driver: pdo_sqlite
        logger:
          - args:
              - connection: "%config(storage.config.connection)%"
        YAML);

        $config = Config::load([$file], ['[storage][config][connection][driver]' => 'pdo_mysql']);

        self::assertSame(['driver' => 'pdo_mysql'], $config['logger'][0]['args'][0]['connection']);
    }

    /**
     * An unresolvable reference surfaces as a config load warning.
     *
     * `Firewall::create()` logs those, so an operator sees the cause rather
     * than only the effect.
     */
    public function testAnUnresolvableReferenceBecomesALoadWarning(): void
    {
        $file = $this->tempFile();
        $this->write($file, <<<'YAML'
        logger:
          - args:
              - connection: "%config(storage.config.connection)%"
        YAML);

        Config::load([$file]);

        $warnings = Config::getLoadWarnings();

        self::assertCount(1, $warnings);
        self::assertStringContainsString('points at nothing', $warnings[0]['message']);
    }

    /**
     * Return a temporary YAML path this test will clean up.
     */
    private function tempFile(): string
    {
        $file = sys_get_temp_dir() . '/fw-ref-' . uniqid('', true) . '.yml';
        $this->tempFiles[] = $file;

        return $file;
    }

    /**
     * Write a config file, remembering it for cleanup.
     */
    private function write(string $path, string $contents): void
    {
        $this->tempFiles[] = $path;
        file_put_contents($path, $contents);
    }
}
