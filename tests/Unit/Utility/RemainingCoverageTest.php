<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use DeviceDetector\DeviceDetector;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\Url;
use Kanopi\Firewall\Plugins\UserAgent;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\ConfigLoader;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Utility\GeoHeaderMap;
use Kanopi\Firewall\Utility\SelectiveDeviceDetector;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use Symfony\Component\HttpFoundation\Request;

/**
 * Closes the last branches the feature suites do not reach.
 *
 * Each of these is a guard that only fires in an unusual arrangement — a
 * remote include with nothing cached, a header holding something that is not a
 * string, a detector that is not the selective one. They are short tests, but
 * an unexercised guard is a guard nobody has checked the logic of.
 */
class RemainingCoverageTest extends AbstractTestCase
{
    /**
     * Scratch directory.
     */
    private string $workspace;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->workspace = sys_get_temp_dir() . '/firewall-last-' . bin2hex(random_bytes(6));
        mkdir($this->workspace, 0775, true);
        Config::clearLoadErrors();
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        foreach (glob($this->workspace . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->workspace);
        Config::clearLoadErrors();
        parent::tearDown();
    }

    /**
     * A remote include that cannot be fetched, with nothing cached, gets the
     * generic reason rather than silence.
     */
    public function testUnfetchableRemoteConfigWithNoCacheIsReportedGenerically(): void
    {
        $config = Config::loadFile('https://nonexistent-test-domain-12345.invalid/firewall.yml');

        $this->assertSame([], $config);

        $errors = Config::getLoadErrors();
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('could not be fetched', $errors[0]['message']);
    }

    /**
     * Degraded config loads are reported at warning level, not as failures.
     */
    public function testConfigLoadWarningsAreReportedAtWarningLevel(): void
    {
        $handler = new TestHandler(Level::Debug);
        $logger = new Logger('warnings');
        $logger->pushHandler($handler);
        LoggingFactory::setLogger($logger);

        $method = new \ReflectionMethod(Firewall::class, 'reportConfigLoadWarnings');
        $method->setAccessible(true);
        $method->invoke(null, [
            ['file' => 'https://cdn.example.com/rules.yml', 'message' => 'served a cached copy 7412s old.'],
        ]);

        $this->assertTrue($handler->hasRecordThatContains('degraded state', Level::Warning));
        $this->assertFalse($handler->hasWarningThatContains('NOT active'), 'A warning is not a failure.');
    }

    /**
     * An empty warning list logs nothing at all.
     */
    public function testNoWarningsLogsNothing(): void
    {
        $handler = new TestHandler(Level::Debug);
        $logger = new Logger('warnings');
        $logger->pushHandler($handler);
        LoggingFactory::setLogger($logger);

        $method = new \ReflectionMethod(Firewall::class, 'reportConfigLoadWarnings');
        $method->setAccessible(true);
        $method->invoke(null, []);

        $this->assertSame([], $handler->getRecords());
    }

    /**
     * A header value that is not a list of scalars resolves to nothing.
     *
     * Symfony gives lists of strings, so this is a guard rather than a shape
     * the framework produces — but folding a nested structure into a string
     * would let a `contains` rule match something nobody sent.
     */
    public function testHeaderHoldingANonScalarResolvesToNothing(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']);
        $request->headers->set('X-Odd', [['nested']]);

        $plugin = new class ([], ['header.x-odd@exists']) extends Url {
            public function resolve(Request $request, string $variable): mixed
            {
                return $this->getValue($request, $variable);
            }
        };

        $this->assertNull($plugin->resolve($request, 'header.x-odd'));
    }

    /**
     * Bot metadata is empty when the detector cannot offer a crawler match.
     *
     * The plain device-detector has no crawler list, so a wider `bot_detector`
     * has nothing extra to fall back on.
     */
    public function testBotFieldsAreEmptyWithoutTheSelectiveDetector(): void
    {
        $plugin = new class (['bot_detector' => 'both'], ['bot.name@contains:sqlmap']) extends UserAgent {
            protected function detectDevice(string $userAgent): DeviceDetector
            {
                $detector = new DeviceDetector($userAgent);
                $detector->parse();

                return $detector;
            }

            /**
             * @return array<string, mixed>
             */
            public function fields(): array
            {
                $this->deviceDetector = $this->detectDevice('sqlmap/1.7.2');

                return $this->botFields();
            }
        };

        $this->assertSame([], $plugin->fields());
    }

    /**
     * The crawler match is nothing when the agent is not a crawler.
     */
    public function testCrawlerMatchIsNullForARealBrowser(): void
    {
        $detector = new SelectiveDeviceDetector(
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36'
        );

        $this->assertNull($detector->crawlerMatch());
    }

    /**
     * ...and is the matched substring when it is one.
     */
    public function testCrawlerMatchReturnsTheMatchedSubstring(): void
    {
        $detector = new SelectiveDeviceDetector('sqlmap/1.7.2 (https://sqlmap.org)');

        $this->assertNotNull($detector->crawlerMatch());
    }

    /**
     * A logger path that is already a stream wrapper is left alone.
     *
     * `php://stdout` is the common case, and rewriting it against the config
     * directory would produce a file nobody wanted.
     */
    public function testStreamLoggerPathsAreNotRewritten(): void
    {
        $file = $this->workspace . '/config-log.yml';
        file_put_contents(
            $file,
            "logger:\n  - class: 'Monolog\\Handler\\StreamHandler'\n    args: ['php://stdout']\n"
        );

        $config = ConfigLoader::load($file);

        $this->assertSame('php://stdout', $config['logger'][0]['args'][0]);
    }

    /**
     * An absolute logger path is left alone too.
     */
    public function testAbsoluteLoggerPathsAreNotRewritten(): void
    {
        $file = $this->workspace . '/config-log-abs.yml';
        file_put_contents(
            $file,
            "logger:\n  - class: 'Monolog\\Handler\\StreamHandler'\n    args: ['/var/log/firewall.log']\n"
        );

        $config = ConfigLoader::load($file);

        $this->assertSame('/var/log/firewall.log', $config['logger'][0]['args'][0]);
    }

    /**
     * A malformed geo header map is refused with the shape it wanted.
     */
    public function testGeoHeaderMapRejectsMalformedEntries(): void
    {
        $malformed = [
            ['country' => ''],
            ['country' => '   '],
            [0 => 'X-Geo-Country'],
        ];

        foreach ($malformed as $headers) {
            try {
                GeoHeaderMap::fromMetadata(['provider' => 'custom', 'headers' => $headers]);
                $this->fail('Expected a ConfigurationException for ' . json_encode($headers));
            } catch (ConfigurationException $configurationException) {
                $this->assertStringContainsString('Header-Name', $configurationException->getMessage());
            }
        }
    }

    /**
     * A compound geo header that is absent or blank yields nothing.
     */
    public function testAbsentCompoundGeoHeadersYieldNothing(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']);

        $this->assertSame([], GeoHeaderMap::fromMetadata(['provider' => 'akamai'])->read($request));
        $this->assertSame([], GeoHeaderMap::fromMetadata(['provider' => 'gcp'])->read($request));

        $blank = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.9',
            'HTTP_X_AKAMAI_EDGESCAPE' => '   ',
            'HTTP_X_CLIENT_GEO_LOCATION' => '   ',
        ]);

        $this->assertSame([], GeoHeaderMap::fromMetadata(['provider' => 'akamai'])->read($blank));
        $this->assertSame([], GeoHeaderMap::fromMetadata(['provider' => 'gcp'])->read($blank));
    }

    /**
     * An Edgescape segment with no `=` is skipped rather than mangled.
     */
    public function testEdgescapeSegmentsWithoutAnEqualsAreSkipped(): void
    {
        $request = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.9',
            'HTTP_X_AKAMAI_EDGESCAPE' => 'junk,country_code=US',
        ]);

        $this->assertSame(
            ['country' => 'US'],
            GeoHeaderMap::fromMetadata(['provider' => 'akamai'])->read($request)
        );
    }

    /**
     * A creatable path that is already a URL is left alone.
     *
     * Storage can be pointed at a stream wrapper, and rewriting that against
     * the config directory would produce nonsense.
     */
    public function testUrlValuedCreatablePathsAreNotRewritten(): void
    {
        $file = $this->workspace . '/config.yml';
        file_put_contents($file, "storage:\n  config:\n    storage_file: 'https://example.org/state.data'\n");

        $config = ConfigLoader::load($file, [], ['storage.config.(storage_file|offense_file)']);

        $this->assertSame('https://example.org/state.data', $config['storage']['config']['storage_file']);
    }

    /**
     * An absolute creatable path is left alone too.
     */
    public function testAbsoluteCreatablePathsAreNotRewritten(): void
    {
        $file = $this->workspace . '/config-abs.yml';
        file_put_contents($file, "storage:\n  config:\n    storage_file: '/var/lib/firewall/state.data'\n");

        $config = ConfigLoader::load($file, [], ['storage.config.(storage_file|offense_file)']);

        $this->assertSame('/var/lib/firewall/state.data', $config['storage']['config']['storage_file']);
    }
}
