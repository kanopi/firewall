<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Plugins\IpAddress;
use Kanopi\Firewall\Plugins\VulnerabilityScore;
use Kanopi\Firewall\Source\SourceCache;
use Kanopi\Firewall\Source\SourceLoader;
use Kanopi\Firewall\Source\SourceManager;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;

/**
 * Tests `metadata.sources` as plugins actually consume it.
 */
class PluginSourcesTest extends AbstractTestCase
{
    /**
     * Scratch directory for fixtures and cache files.
     */
    private string $workspace;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->workspace = sys_get_temp_dir() . '/firewall-plugin-sources-' . bin2hex(random_bytes(6));
        mkdir($this->workspace . '/cache', 0775, true);
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        foreach (glob($this->workspace . '/{,cache/}*', GLOB_BRACE) ?: [] as $file) {
            if (is_file($file)) {
                @unlink($file);
            }
        }

        @rmdir($this->workspace . '/cache');
        @rmdir($this->workspace);
        parent::tearDown();
    }

    /**
     * Write a fixture and return its path.
     */
    private function fixture(string $name, string $contents): string
    {
        $path = $this->workspace . '/' . $name;
        file_put_contents($path, $contents);

        return $path;
    }

    /**
     * An IpAddress plugin whose sources resolve against the scratch cache.
     */
    private function plugin(array $metadata, array $config = []): IpAddress
    {
        $cacheDir = $this->workspace . '/cache';

        return new class ($metadata, $config, $cacheDir) extends IpAddress {
            public function __construct(array $metadata, array $config, private readonly string $cacheDir)
            {
                parent::__construct($metadata, $config);
            }

            protected function sourceManager(): SourceManager
            {
                $cache = new SourceCache($this->cacheDir);

                return new SourceManager(new SourceLoader($cache), $cache);
            }

            public function rules(): array
            {
                return $this->config;
            }
        };
    }

    /**
     * Read a plugin's assembled rule list.
     */
    private function rules(IpAddress $plugin): array
    {
        $property = new \ReflectionProperty(IpAddress::class, 'config');
        $property->setAccessible(true);

        return $property->getValue($plugin);
    }

    /**
     * A single source becomes the plugin's rule list.
     */
    public function testSingleSourceBecomesTheRuleList(): void
    {
        $plugin = $this->plugin([
            'sources' => [
                ['name' => 'tor', 'upstream' => $this->fixture('tor.txt', "1.1.1.1\n2.2.2.2")],
            ],
        ]);

        $this->assertSame(['1.1.1.1', '2.2.2.2'], $this->rules($plugin));
    }

    /**
     * Several sources concatenate and inline `config:` lands last, so a site
     * can always add an entry without editing a shared list.
     */
    public function testSourcesConcatenateAndInlineConfigLandsLast(): void
    {
        $plugin = $this->plugin(
            [
                'sources' => [
                    ['name' => 'circleci', 'upstream' => $this->fixture('ci.txt', '3.228.39.90/32')],
                    ['name' => 'uptimerobot', 'upstream' => $this->fixture('ur.txt', '216.144.250.150/32')],
                ],
            ],
            ['127.0.0.1', '10.0.0.0/8']
        );

        $this->assertSame([
            '3.228.39.90/32',
            '216.144.250.150/32',
            '127.0.0.1',
            '10.0.0.0/8',
        ], $this->rules($plugin));
    }

    /**
     * The loaded rules are the ones the plugin evaluates against.
     */
    public function testLoadedRulesAreEvaluated(): void
    {
        $plugin = $this->plugin([
            'sources' => [['upstream' => $this->fixture('block.txt', '203.0.113.0/24')]],
        ]);

        $this->assertTrue($plugin->evaluate($this->getRequest('203.0.113.9')));
        $this->assertFalse($plugin->evaluate($this->getRequest('198.51.100.9')));
    }

    /**
     * A JSON source is selected, filtered, and templated on the way in.
     */
    public function testJsonSourceIsShapedForThePlugin(): void
    {
        $body = '{"prefixes":[' .
            '{"ip_prefix":"3.5.140.0/22","region":"ap-northeast-2","service":"S3"},' .
            '{"ip_prefix":"18.34.32.0/20","region":"us-east-1","service":"EC2"}]}';

        $plugin = $this->plugin([
            'sources' => [
                [
                    'name' => 'aws-ec2-us',
                    'upstream' => $this->fixture('ranges.json', $body),
                    'select' => 'prefixes.*',
                    'where' => ['service:EC2', 'region@starts_with:us-'],
                    'template' => '{value[ip_prefix]}',
                    'validate' => 'cidr',
                ],
            ],
        ]);

        $this->assertSame(['18.34.32.0/20'], $this->rules($plugin));
    }

    /**
     * Each entry can be attributed back to the source that supplied it, so a
     * match can report which list caused it.
     */
    public function testEntriesReportTheirSource(): void
    {
        $plugin = $this->plugin(
            [
                'sources' => [
                    ['name' => 'circleci', 'upstream' => $this->fixture('p1.txt', "1.1.1.1\n2.2.2.2")],
                    ['name' => 'tor', 'upstream' => $this->fixture('p2.txt', '3.3.3.3')],
                ],
            ],
            ['127.0.0.1']
        );

        $this->assertSame('circleci', $plugin->entrySource(0));
        $this->assertSame('circleci', $plugin->entrySource(1));
        $this->assertSame('tor', $plugin->entrySource(2));
        $this->assertNull($plugin->entrySource(3), 'Inline entries are local, not from a source.');
    }

    /**
     * A required source that cannot load stops construction rather than
     * leaving the plugin quietly narrower than configured.
     */
    public function testRequiredSourceFailureAborts(): void
    {
        $this->expectException(SourceException::class);

        $this->plugin([
            'sources' => [
                ['name' => 'ci', 'upstream' => $this->workspace . '/absent.txt', 'required' => true],
            ],
        ]);
    }

    /**
     * A non-required source that fails leaves the rest of the list intact.
     */
    public function testOptionalSourceFailureLeavesTheRest(): void
    {
        $plugin = $this->plugin(
            [
                'sources' => [
                    ['name' => 'good', 'upstream' => $this->fixture('ok.txt', '1.1.1.1')],
                    ['name' => 'gone', 'upstream' => $this->workspace . '/absent.txt'],
                ],
            ],
            ['127.0.0.1']
        );

        $this->assertSame(['1.1.1.1', '127.0.0.1'], $this->rules($plugin));
    }

    /**
     * Declaring no sources leaves the plugin exactly as it was.
     */
    public function testNoSourcesLeavesConfigUntouched(): void
    {
        $plugin = $this->plugin([], ['127.0.0.1']);

        $this->assertSame(['127.0.0.1'], $this->rules($plugin));
    }

    /**
     * `metadata.sources` and the legacy `metadata.config` can coexist, with
     * sources first and file-loaded rules after.
     */
    public function testSourcesCoexistWithLegacyConfigFiles(): void
    {
        $legacy = $this->fixture('legacy.yml', "- 8.8.8.8\n");

        $plugin = $this->plugin(
            [
                'sources' => [['upstream' => $this->fixture('new.txt', '1.1.1.1')]],
                'config' => [$legacy],
            ],
            ['127.0.0.1']
        );

        $this->assertSame(['1.1.1.1', '8.8.8.8', '127.0.0.1'], $this->rules($plugin));
    }

    /**
     * Sources produce *lists of entries*, which is the whole shape of the
     * pipeline. A map-shaped document therefore arrives as one record rather
     * than being merged key-by-key, so nested configuration trees stay with
     * `metadata.config` — the one job it is not deprecated for.
     */
    public function testSourcesProduceListsNotMergedDocuments(): void
    {
        $document = $this->fixture('scoring.yml', "scoring:\n  methods:\n    PUT: 9\n");

        $plugin = $this->plugin(['sources' => [['upstream' => $document]]]);

        $this->assertSame([['scoring' => ['methods' => ['PUT' => 9]]]], $this->rules($plugin));
    }

    /**
     * The counterpart: `metadata.config` does merge a document by key, which
     * is what VulnerabilityScore's nested trees depend on.
     */
    public function testLegacyConfigStillMergesDocumentsByKey(): void
    {
        $document = $this->fixture('scoring2.yml', "scoring:\n  methods:\n    PUT: 9\n");

        $plugin = new class (
            ['config' => [$document]],
            ['scoring' => ['methods' => ['GET' => 0]]]
        ) extends VulnerabilityScore {
            public function scoringMethods(): array
            {
                return $this->config['scoring']['methods'] ?? [];
            }
        };

        $this->assertSame(['PUT' => 9, 'GET' => 0], $plugin->scoringMethods());
    }

    /**
     * Capture log records for the duration of a test.
     */
    private function captureLog(): TestHandler
    {
        $handler = new TestHandler();
        $logger = new Logger('sources-test');
        $logger->pushHandler($handler);
        LoggingFactory::setLogger($logger);

        return $handler;
    }

    /**
     * Using `metadata.config` for a rule list points at its replacement.
     */
    public function testLegacyListConfigLogsADeprecation(): void
    {
        $handler = $this->captureLog();

        $this->plugin(['config' => [$this->fixture('legacy-list.yml', "- 1.1.1.1\n")]]);

        $this->assertTrue(
            $handler->hasRecordThatContains('metadata.config is deprecated for rule lists', Level::Notice)
        );
    }

    /**
     * The notice is limited to the case sources actually replaces, so nested
     * configuration documents do not get told to migrate to something that
     * cannot express them.
     */
    public function testDocumentConfigDoesNotWarn(): void
    {
        $handler = $this->captureLog();

        new class (['config' => [$this->fixture('doc.yml', "scoring:\n  methods:\n    PUT: 9\n")]], []) extends VulnerabilityScore {
        };

        $this->assertFalse(
            $handler->hasRecordThatContains('metadata.config is deprecated for rule lists', Level::Notice)
        );
    }

    /**
     * Declaring sources alongside the legacy key silences the notice: the
     * migration has already happened for the part that matters.
     */
    public function testDeclaringSourcesSilencesTheNotice(): void
    {
        $handler = $this->captureLog();

        $this->plugin([
            'sources' => [['upstream' => $this->fixture('new-list.txt', '2.2.2.2')]],
            'config' => [$this->fixture('legacy-list2.yml', "- 1.1.1.1\n")],
        ]);

        $this->assertFalse(
            $handler->hasRecordThatContains('metadata.config is deprecated for rule lists', Level::Notice)
        );
    }
}
