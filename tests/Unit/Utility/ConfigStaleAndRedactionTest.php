<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Plugins\IpAddress;
use Kanopi\Firewall\Source\SourceManager;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Utility\Config;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;

/**
 * Covers the config paths the main suites do not reach.
 *
 * Mostly the ones that only run when something has gone wrong: an unreadable
 * cached copy, a plugin config file that fails mid-load, credentials on their
 * way into a log line.
 */
class ConfigStaleAndRedactionTest extends AbstractTestCase
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
        $this->workspace = sys_get_temp_dir() . '/firewall-cfg-edge-' . bin2hex(random_bytes(6));
        mkdir($this->workspace, 0775, true);
        Config::clearLoadErrors();
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        foreach (glob($this->workspace . '/*') ?: [] as $file) {
            @chmod($file, 0664);
            @unlink($file);
        }

        @rmdir($this->workspace);
        Config::clearLoadErrors();
        parent::tearDown();
    }

    /**
     * Reach `fileGetContents()` directly.
     */
    private function fileGetContents(): \ReflectionMethod
    {
        $method = new \ReflectionMethod(Config::class, 'fileGetContents');
        $method->setAccessible(true);

        return $method;
    }

    /**
     * A cached copy that exists but cannot be read is an error, not a silent
     * fallback to nothing.
     */
    public function testUnreadableStaleCacheIsReported(): void
    {
        $url = 'https://nonexistent-test-domain-12345.com/unreadable.yml';
        $cacheFile = $this->workspace . '/' . md5($url) . '.cache';
        file_put_contents($cacheFile, 'stale: yes');
        touch($cacheFile, time() - 7200);

        if (!chmod($cacheFile, 0000) || is_readable($cacheFile)) {
            $this->markTestSkipped('Cannot make a file unreadable as this user.');
        }

        $result = $this->fileGetContents()->invoke(null, $url, $this->workspace, 3600, 1.0);

        $this->assertFalse($result);

        $errors = Config::getLoadErrors();
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('cached copy could not be read', $errors[0]['message']);
    }

    /**
     * The staleness bound can also come from a constant.
     */
    #[RunInSeparateProcess]
    public function testMaxStaleConstantIsUsed(): void
    {
        define('KANOPI_FIREWALL_CACHE_MAX_STALE', 60);

        $url = 'https://nonexistent-test-domain-12345.com/too-old.yml';
        $cacheFile = $this->workspace . '/' . md5($url) . '.cache';
        file_put_contents($cacheFile, 'stale: yes');
        touch($cacheFile, time() - 7200);

        Config::clearLoadErrors();
        $method = new \ReflectionMethod(Config::class, 'fileGetContents');
        $method->setAccessible(true);

        $this->assertFalse($method->invoke(null, $url, $this->workspace, 3600, 1.0));
        $this->assertStringContainsString('beyond the 60s', Config::getLoadErrors()[0]['message']);
    }

    /**
     * A plugin config file that cannot be parsed is reported against the
     * plugin, not swallowed.
     */
    public function testPluginConfigFileFailureIsReported(): void
    {
        $broken = $this->workspace . '/broken.yml';
        file_put_contents($broken, "plugins:\n  - one\n bad indent\n");

        $plugin = new IpAddress(['config' => [$broken]], []);

        $this->assertSame([], $plugin->evaluate($this->getRequest()) ? ['matched'] : []);
        $this->assertNotSame([], Config::getLoadErrors());
    }

    /**
     * Credentials never reach the metadata a plugin logs.
     *
     * Covers every declaration shape: a bare string upstream, a map upstream
     * with auth, and a source entry that is not a map at all.
     */
    public function testMetadataRedactionCoversEveryDeclarationShape(): void
    {
        $plugin = new class ([
            'sources' => [
                'https://example.org/list.txt?api_key=s3cr3t',
                ['upstream' => 'https://reader:hunter2@example.org/b.txt'],
                [
                    'upstream' => [
                        'url' => 'https://example.org/c.json?token=s3cr3t',
                        'auth' => ['type' => 'bearer', 'token' => 's3cr3t'],
                        'headers' => ['X-API-Key' => 's3cr3t'],
                    ],
                ],
                ['name' => 'no upstream key'],
                42,
            ],
        ], []) extends IpAddress {
            protected function loadDeclaredSources(): array
            {
                // The declarations above are deliberately unfetchable; this
                // test is about what gets logged, not what gets loaded.
                return [];
            }

            /**
             * @return array<int|string, mixed>
             */
            public function loggedMetadata(): array
            {
                return $this->redactedMetadata();
            }
        };

        $encoded = json_encode($plugin->loggedMetadata());

        $this->assertIsString($encoded);
        $this->assertStringNotContainsString('s3cr3t', $encoded);
        $this->assertStringNotContainsString('hunter2', $encoded);
        $this->assertStringContainsString('***', $encoded);
    }

    /**
     * Metadata with no sources is returned untouched.
     */
    public function testMetadataWithoutSourcesIsUnchanged(): void
    {
        $plugin = new class (['status_code' => 403], []) extends IpAddress {
            /**
             * @return array<int|string, mixed>
             */
            public function loggedMetadata(): array
            {
                return $this->redactedMetadata();
            }
        };

        $this->assertSame(['status_code' => 403], $plugin->loggedMetadata());
    }

    /**
     * A source that fails to load is reported against the plugin.
     */
    public function testFailingSourceIsReportedAgainstThePlugin(): void
    {
        $plugin = new class ([
            'sources' => [['name' => 'gone', 'upstream' => $this->workspace . '/never-written.txt']],
        ], ['127.0.0.1']) extends IpAddress {
            protected function sourceManager(): SourceManager
            {
                return new SourceManager();
            }

            /**
             * @return array<array-key, mixed>
             */
            public function rules(): array
            {
                return $this->config;
            }
        };

        $this->assertSame(['127.0.0.1'], $plugin->rules(), 'The local entry survives a failed source.');
    }

    /**
     * A plugin config file served from a stale cache is reported as degraded.
     *
     * The rules are active — they are just older than the TTL wanted — so this
     * is a warning against the plugin rather than a load failure.
     */
    public function testPluginConfigServedFromStaleCacheIsReportedAsDegraded(): void
    {
        $handler = new TestHandler(Level::Debug);
        $logger = new Logger('plugin-warnings');
        $logger->pushHandler($handler);
        LoggingFactory::setLogger($logger);

        $url = 'https://nonexistent-test-domain-12345.invalid/plugin-rules.yml';

        // loadFile() uses the default cache location, so the stale copy has to
        // be seeded where it will actually look.
        $cacheDir = '/tmp/cache';

        if (!is_dir($cacheDir) && !@mkdir($cacheDir, 0775, true) && !is_dir($cacheDir)) {
            $this->markTestSkipped('Cannot create the default cache directory.');
        }

        $cacheFile = $cacheDir . '/' . md5($url) . '.cache';

        if (@file_put_contents($cacheFile, "- 203.0.113.7\n") === false) {
            $this->markTestSkipped('Cannot seed the default cache directory.');
        }

        touch($cacheFile, time() - 86400);

        try {
            // Constructing the plugin loads the file, fails to refetch, falls
            // back to the stale copy, and reports that against the plugin.
            $plugin = new IpAddress(['config' => [$url]], []);

            $this->assertTrue(
                $handler->hasRecordThatContains('degraded state', Level::Warning),
                'A stale plugin config must be reported against the plugin.'
            );
            $this->assertTrue(
                $plugin->evaluate($this->getRequest('203.0.113.7')),
                'The stale rules are active, which is the point of the fallback.'
            );
        } finally {
            @unlink($cacheFile);
        }
    }
}
