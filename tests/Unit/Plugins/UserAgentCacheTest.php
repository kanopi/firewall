<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use DeviceDetector\Cache\CacheInterface;
use Kanopi\Firewall\Plugins\UserAgent;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Logging\LoggingFactory;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\HttpFoundation\Request;

/**
 * Caching of the device-detector regex corpus (#107).
 *
 * device-detector recompiles 20 YAML files totalling 1.7MB on the first parse
 * of every PHP process — 110-637ms depending on the user agent, against ~4ms
 * once warm. Under PHP-FPM each worker pays that on its first request.
 *
 * These tests assert the wiring and, more importantly, that caching does not
 * change what the plugin detects. A cache that quietly altered a verdict would
 * be far worse than a slow one.
 */
final class UserAgentCacheTest extends AbstractTestCase
{
    private const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) '
        . 'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
    private const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    private const SQLMAP = 'sqlmap/1.8.3#stable (https://sqlmap.org)';

    /**
     * @var array<int, string>
     */
    private array $tempDirs = [];

    protected function tearDown(): void
    {
        foreach ($this->tempDirs as $dir) {
            $this->removeDirectory($dir);
        }

        $this->tempDirs = [];

        parent::tearDown();
    }

    private function tempDir(): string
    {
        $dir = sys_get_temp_dir() . '/fw-ua-cache-' . uniqid('', true);
        $this->tempDirs[] = $dir;

        return $dir;
    }

    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $items = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($items as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }

        @rmdir($dir);
    }

    private function request(string $userAgent): Request
    {
        return Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '1.1.1.1',
            'HTTP_USER_AGENT' => $userAgent,
        ]);
    }

    /**
     * Expose the resolved cache without reaching through reflection at every
     * call site.
     *
     * @param array<string, mixed> $metadata
     * @param array<int, mixed> $config
     */
    private function plugin(array $metadata = [], array $config = ['bot:true']): UserAgent
    {
        return new class ($metadata, $config) extends UserAgent {
            public function resolvedCache(): ?CacheInterface
            {
                return $this->cache();
            }

            public function resolvedCacheDir(): string
            {
                return $this->cacheDir();
            }
        };
    }

    // -----------------------------------------------------------------------
    // Correctness: caching must not change detection
    // -----------------------------------------------------------------------

    /**
     * The property that matters most. A cache that altered a verdict would be
     * a security regression dressed as an optimisation.
     *
     * @param string $userAgent
     * @param string $variable
     */
    #[DataProvider('provideDetectionCases')]
    public function testCachingDoesNotChangeDetection(string $userAgent, string $variable, string $expected): void
    {
        $dir = $this->tempDir();

        $uncached = $this->plugin(['cache' => false], [$variable . ':' . $expected]);
        $cached = $this->plugin(['cache' => ['dir' => $dir]], [$variable . ':' . $expected]);

        $request = $this->request($userAgent);

        // Run the cached one twice: once cold (populating), once warm (reading
        // back). A cache that round-trips incorrectly would differ on the
        // second call, not the first.
        $uncachedResult = $uncached->evaluate($request);
        $cachedCold = $cached->evaluate($request);

        $warm = $this->plugin(['cache' => ['dir' => $dir]], [$variable . ':' . $expected]);
        $cachedWarm = $warm->evaluate($request);

        $this->assertSame($uncachedResult, $cachedCold, 'Cold cache changed the verdict.');
        $this->assertSame($uncachedResult, $cachedWarm, 'Warm cache changed the verdict.');
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideDetectionCases(): array
    {
        return [
            'bot is detected' => [self::GOOGLEBOT, 'bot', 'true'],
            'browser is not a bot' => [self::IPHONE, 'bot', 'false'],
            'device type' => [self::IPHONE, 'device.type', 'smartphone'],
            'os name' => [self::IPHONE, 'os.name', 'iOS'],
            'client name' => [self::SQLMAP, 'client.name', 'sqlmap'],
        ];
    }

    /**
     * Reading a populated cache must reproduce the same rich bot metadata, not
     * merely the same boolean.
     */
    public function testWarmCacheReproducesBotMetadata(): void
    {
        $dir = $this->tempDir();
        $request = $this->request(self::GOOGLEBOT);

        $cold = $this->plugin(['cache' => ['dir' => $dir]], ['bot.name:Googlebot']);
        $this->assertTrue($cold->evaluate($request), 'Cold cache failed to match bot.name.');

        $warm = $this->plugin(['cache' => ['dir' => $dir]], ['bot.name:Googlebot']);
        $this->assertTrue($warm->evaluate($request), 'Warm cache failed to match bot.name.');
    }

    // -----------------------------------------------------------------------
    // Wiring
    // -----------------------------------------------------------------------

    public function testCachingIsOnByDefault(): void
    {
        $this->assertInstanceOf(CacheInterface::class, $this->plugin()->resolvedCache());
    }

    /**
     * Off by default would mean almost nobody benefits, since the cost is
     * invisible without profiling — but it must remain switchable.
     */
    public function testCachingCanBeDisabled(): void
    {
        $this->assertNull($this->plugin(['cache' => false])->resolvedCache());
    }

    public function testDisabledCacheStillEvaluatesCorrectly(): void
    {
        $plugin = $this->plugin(['cache' => false], ['bot:true']);

        $this->assertTrue($plugin->evaluate($this->request(self::GOOGLEBOT)));
        $this->assertFalse($plugin->evaluate($this->request(self::IPHONE)));
    }

    public function testDefaultCacheDirectoryIsCreatedAndUsed(): void
    {
        $dir = $this->tempDir();
        $plugin = $this->plugin(['cache' => ['dir' => $dir]], ['bot:true']);

        $plugin->evaluate($this->request(self::GOOGLEBOT));

        $this->assertDirectoryExists($dir, 'The cache directory should have been created.');
        $this->assertNotEmpty(glob($dir . '/*'), 'The cache directory should have been populated.');
    }

    public function testNothingIsWrittenWhenCachingIsDisabled(): void
    {
        $dir = $this->tempDir();
        $plugin = $this->plugin(['cache' => false], ['bot:true']);

        $plugin->evaluate($this->request(self::GOOGLEBOT));

        $this->assertDirectoryDoesNotExist($dir);
    }

    /**
     * The `['adaptor' => ..., 'args' => [...]]` shape matches what
     * CacheRateLimitStorage already accepts, so there is one convention in the
     * codebase rather than two.
     */
    public function testAdaptorClassAndArgsAreHonoured(): void
    {
        $dir = $this->tempDir();

        $plugin = $this->plugin([
            'cache' => [
                'adaptor' => FilesystemAdapter::class,
                'args' => ['device-detector', 0, $dir],
            ],
        ], ['bot:true']);

        $this->assertTrue($plugin->evaluate($this->request(self::GOOGLEBOT)));
        $this->assertDirectoryExists($dir);
    }

    /**
     * An already-constructed pool is how a framework container would inject
     * one, since YAML cannot carry an object.
     */
    public function testAnAlreadyConstructedPoolIsAccepted(): void
    {
        $pool = new ArrayAdapter();
        $plugin = $this->plugin(['cache' => ['adaptor' => $pool]], ['bot:true']);

        $this->assertInstanceOf(CacheInterface::class, $plugin->resolvedCache());
        $this->assertTrue($plugin->evaluate($this->request(self::GOOGLEBOT)));
        $this->assertNotSame([], $pool->getValues(), 'The injected pool should have been written to.');
    }

    public function testPoolPassedDirectlyWithoutTheAdaptorKeyIsAccepted(): void
    {
        $pool = new ArrayAdapter();
        $plugin = $this->plugin(['cache' => $pool], ['bot:true']);

        $this->assertInstanceOf(CacheInterface::class, $plugin->resolvedCache());
    }

    // -----------------------------------------------------------------------
    // Degrading safely
    // -----------------------------------------------------------------------

    /**
     * A typo in a YAML file must not take a site down. It degrades to the
     * default cache and says so, following the precedent set by Crs and
     * AbuseIpdb for bad config.
     */
    public function testUnusableAdaptorFallsBackAndWarns(): void
    {
        $handler = new TestLogHandler(\Monolog\Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $plugin = $this->plugin(['cache' => ['adaptor' => 'Totally\\Not\\A\\Class']], ['bot:true']);

        $this->assertInstanceOf(CacheInterface::class, $plugin->resolvedCache());
        $this->assertTrue(
            $handler->hasWarningContaining('not a PSR-6 pool'),
            'A bad adaptor should warn rather than fail silently.',
        );
        // And the plugin still works.
        $this->assertTrue($plugin->evaluate($this->request(self::GOOGLEBOT)));
    }

    /**
     * A class that exists but is not a cache pool must be rejected on the same
     * path — `class_exists()` alone would let it through to a fatal.
     */
    public function testNonPoolClassIsRejected(): void
    {
        $plugin = $this->plugin(['cache' => ['adaptor' => \stdClass::class]], ['bot:true']);

        $this->assertInstanceOf(CacheInterface::class, $plugin->resolvedCache());
        $this->assertTrue($plugin->evaluate($this->request(self::GOOGLEBOT)));
    }

    /**
     * An unwritable cache location must leave a working, if slower, plugin.
     * Refusing to evaluate would turn an optimisation into an outage.
     */
    public function testUnwritableCacheDirectoryDoesNotBreakEvaluation(): void
    {
        $plugin = $this->plugin([
            'cache' => ['adaptor' => FilesystemAdapter::class, 'args' => ['dd', 0, '/proc/nope/definitely-not-writable']],
        ], ['bot:true']);

        $this->assertTrue($plugin->evaluate($this->request(self::GOOGLEBOT)));
        $this->assertFalse($plugin->evaluate($this->request(self::IPHONE)));
    }

    // -----------------------------------------------------------------------
    // Cache directory resolution
    // -----------------------------------------------------------------------

    public function testExplicitDirWins(): void
    {
        $dir = $this->tempDir();

        $this->assertSame($dir, $this->plugin(['cache' => ['dir' => $dir]])->resolvedCacheDir());
    }

    public function testDefaultDirectoryLivesUnderTheSystemTempDir(): void
    {
        $this->assertStringStartsWith(sys_get_temp_dir(), $this->plugin()->resolvedCacheDir());
    }

    /**
     * Regression for the defect shipped in v2.11.0.
     *
     * `FilesystemAdapter` constructs happily against an unwritable directory
     * and only fails later, per write. The plugin therefore logged
     * "cache initialized" at debug and every request paid the full uncached
     * parse — roughly 645ms instead of ~20ms — silently, forever.
     */
    public function testUnwritableCacheIsDetectedAndWarnedAboutLoudly(): void
    {
        $handler = new TestLogHandler(\Monolog\Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $plugin = $this->plugin(['cache' => ['dir' => '/proc/definitely-not-writable/nope']], ['bot:true']);

        $this->assertNull(
            $plugin->resolvedCache(),
            'A cache that cannot persist must not be reported as usable.',
        );
        $this->assertTrue(
            $handler->hasWarningContaining('not writable'),
            'An unusable cache must warn, not pass silently at debug level.',
        );
    }

    /**
     * The probe must not reject a cache that works.
     */
    public function testUsableCacheIsNotRejectedByTheProbe(): void
    {
        $handler = new TestLogHandler(\Monolog\Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $plugin = $this->plugin(['cache' => ['dir' => $this->tempDir()]], ['bot:true']);

        $this->assertInstanceOf(CacheInterface::class, $plugin->resolvedCache());
        $this->assertFalse($handler->hasWarningContaining('not writable'));
    }

    /**
     * The probe leaves nothing behind that could be mistaken for corpus data.
     */
    public function testProbeDoesNotDisturbTheCachedCorpus(): void
    {
        $dir = $this->tempDir();

        $first = $this->plugin(['cache' => ['dir' => $dir]], ['bot:true']);
        $this->assertTrue($first->evaluate($this->request(self::GOOGLEBOT)));

        $second = $this->plugin(['cache' => ['dir' => $dir]], ['bot:true']);
        $this->assertTrue($second->evaluate($this->request(self::GOOGLEBOT)));
    }
}
