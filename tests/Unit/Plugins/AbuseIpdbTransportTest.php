<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

require_once __DIR__ . '/../../Traits/PluginsNamespaceOverrides.php';

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\AbuseIpdb;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Level;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use Symfony\Component\HttpFoundation\Request;

/**
 * The AbuseIPDB network and cache layers, with the wrapper shimmed.
 *
 * `AbuseIpdbTest` scripts `fetch()` wholesale so the plugin's decision logic
 * can be tested without a network. That leaves everything inside `fetch()`
 * unexercised — the status handling, the empty and malformed body cases, the
 * unreachable host — and those are precisely the paths that decide whether a
 * failing third party turns into a blocked visitor. Reaching them against the
 * real API would cost quota, need a key in CI, and require AbuseIPDB to return
 * specific errors on demand, so the stream wrapper is shimmed instead. See
 * tests/Traits/PluginsNamespaceOverrides.php.
 */
final class AbuseIpdbTransportTest extends AbstractTestCase
{
    private string $cacheDir;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->cacheDir = sys_get_temp_dir() . '/abuseipdb-transport-' . bin2hex(random_bytes(6));
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        // These are process-global. A leaked flag would feed a canned HTTP
        // response, or a forced failure, to every later test in the run.
        $GLOBALS['fake_plugin_http_response'] = null;
        $GLOBALS['fake_plugin_http_handles'] = [];
        $GLOBALS['simulate_plugins_file_get_contents_failure'] = false;
        $GLOBALS['simulate_plugins_file_put_contents_failure'] = false;
        $GLOBALS['simulate_plugins_is_dir_failure'] = false;
        $GLOBALS['simulate_plugins_mkdir_failure'] = false;

        foreach ((array) glob($this->cacheDir . '/*') as $file) {
            @unlink((string) $file);
        }
        @rmdir($this->cacheDir);

        parent::tearDown();
    }

    public function testASuccessfulResponseProducesAMatchAboveThreshold(): void
    {
        $this->fakeResponse(200, (string) json_encode([
            'data' => [
                'abuseConfidenceScore' => 95,
                'isWhitelisted' => false,
                'totalReports' => 42,
                'countryCode' => 'RU',
            ],
        ]));

        $this->assertTrue($this->plugin(['threshold' => 50])->evaluate($this->request()));
    }

    public function testASuccessfulResponseBelowThresholdDoesNotMatch(): void
    {
        $this->fakeResponse(200, (string) json_encode([
            'data' => ['abuseConfidenceScore' => 10, 'isWhitelisted' => false],
        ]));

        $this->assertFalse($this->plugin(['threshold' => 50])->evaluate($this->request()));
    }

    /**
     * A whitelisted address never matches, whatever its score.
     *
     * AbuseIPDB whitelists infrastructure that attracts reports without being
     * malicious — search engine crawlers, large NATs. Blocking those on score
     * alone is how a firewall de-indexes a site.
     */
    public function testWhitelistedAddressNeverMatches(): void
    {
        $this->fakeResponse(200, (string) json_encode([
            'data' => ['abuseConfidenceScore' => 100, 'isWhitelisted' => true],
        ]));

        $this->assertFalse($this->plugin(['threshold' => 50])->evaluate($this->request()));
    }

    /**
     * An unreachable API must not become a blocked visitor.
     *
     * Fail-open is the right default for a reputation lookup, unlike challenge
     * verification: the plugin has no opinion when it cannot ask, and turning
     * every DNS blip into a site-wide block would be far worse than missing
     * some bad traffic.
     */
    public function testUnreachableApiDoesNotMatch(): void
    {
        $GLOBALS['fake_plugin_http_response'] = false;

        $handler = $this->captureLogs();

        $this->assertFalse($this->plugin(['threshold' => 50])->evaluate($this->request()));
        $this->assertTrue(
            $handler->hasWarningContaining('lookup failed - allowing the request through'),
            'Failing open has to be stated in the log, not inferred from a missing block.',
        );
    }

    /**
     * Responses that carry no usable verdict.
     *
     * @return array<string, array{0: int, 1: string}>
     */
    public static function unusableResponseProvider(): array
    {
        return [
            'unauthorized' => [401, '{"errors":[{"detail":"authentication failed"}]}'],
            'forbidden' => [403, ''],
            'rate limited' => [429, '{"errors":[{"detail":"too many requests"}]}'],
            'server error' => [500, ''],
            'empty body on 200' => [200, ''],
            'not json' => [200, 'not json at all'],
            'json without data' => [200, '{"meta":{}}'],
            'data not an object' => [200, '{"data":"nope"}'],
        ];
    }

    #[DataProvider('unusableResponseProvider')]
    public function testUnusableResponseDoesNotMatch(int $status, string $body): void
    {
        $this->fakeResponse($status, $body);

        $this->assertFalse($this->plugin(['threshold' => 50])->evaluate($this->request()));
    }

    /**
     * A response with no parseable status line is a failure, not a pass.
     */
    public function testResponseWithNoStatusLineDoesNotMatch(): void
    {
        $GLOBALS['fake_plugin_http_response'] = [
            'headers' => ['Content-Type: application/json'],
            'body' => '{"data":{"abuseConfidenceScore":100}}',
        ];

        $this->assertFalse($this->plugin(['threshold' => 50])->evaluate($this->request()));
    }

    /**
     * A request with no client IP is skipped before any quota is spent.
     */
    public function testRequestWithoutAClientIpIsSkipped(): void
    {
        $GLOBALS['fake_plugin_http_response'] = false;

        $request = Request::create('/', 'GET');
        $request->server->remove('REMOTE_ADDR');

        $this->assertFalse($this->plugin(['threshold' => 50])->evaluate($request));
    }

    /**
     * An unwritable cache warns rather than failing, and still answers.
     *
     * Losing the cache means every request spends API quota — the free tier
     * allows 1,000 checks a day, so this is the difference between working and
     * exhausted by mid-morning. Worth a warning; not worth failing the request.
     */
    public function testUnwritableCacheWarnsButStillEvaluates(): void
    {
        $this->fakeResponse(200, (string) json_encode([
            'data' => ['abuseConfidenceScore' => 95, 'isWhitelisted' => false],
        ]));
        $GLOBALS['simulate_plugins_file_put_contents_failure'] = true;

        $handler = $this->captureLogs();

        $this->assertTrue($this->plugin(['threshold' => 50])->evaluate($this->request()));
        $this->assertTrue($handler->hasWarningContaining('could not write its cache'));
    }

    /**
     * A cache directory that cannot be created warns and disables caching.
     */
    public function testUncreatableCacheDirectoryWarns(): void
    {
        $this->fakeResponse(200, (string) json_encode([
            'data' => ['abuseConfidenceScore' => 95, 'isWhitelisted' => false],
        ]));
        $GLOBALS['simulate_plugins_is_dir_failure'] = true;
        $GLOBALS['simulate_plugins_mkdir_failure'] = true;

        $handler = $this->captureLogs();

        $this->assertTrue($this->plugin(['threshold' => 50])->evaluate($this->request()));
        $this->assertTrue($handler->hasWarningContaining('cache directory could not be created'));
    }

    /**
     * An unreadable cache entry is refetched rather than trusted.
     */
    public function testUnreadableCacheEntryIsRefetched(): void
    {
        $this->fakeResponse(200, (string) json_encode([
            'data' => ['abuseConfidenceScore' => 95, 'isWhitelisted' => false],
        ]));

        // Prime the cache, then make reading it fail.
        $this->assertTrue($this->plugin(['threshold' => 50])->evaluate($this->request()));
        $GLOBALS['simulate_plugins_file_get_contents_failure'] = true;

        $this->assertTrue($this->plugin(['threshold' => 50])->evaluate($this->request()));
    }

    /**
     * A non-numeric timeout falls back to the default and says so.
     */
    public function testNonNumericTimeoutWarnsAndUsesTheDefault(): void
    {
        $this->fakeResponse(200, (string) json_encode([
            'data' => ['abuseConfidenceScore' => 95, 'isWhitelisted' => false],
        ]));

        $handler = $this->captureLogs();

        $this->assertTrue(
            $this->plugin(['threshold' => 50, 'timeout' => 'soon'])->evaluate($this->request())
        );
        $this->assertTrue($handler->hasWarningContaining('timeout is not a number'));
    }

    /**
     * KANOPI_FIREWALL_CACHE_DIR is honoured when no cache_dir is configured.
     *
     * Separate process because `define()` cannot be undone — leaking it would
     * redirect the cache for every test that ran afterwards.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testCacheDirFallsBackToTheGlobalConstant(): void
    {
        $dir = sys_get_temp_dir() . '/fw-abuse-const-' . bin2hex(random_bytes(4));
        define('KANOPI_FIREWALL_CACHE_DIR', $dir);

        $plugin = new class ([], ['api_key' => 'k', 'threshold' => 50]) extends AbuseIpdb {
            public function exposedCacheDir(): string
            {
                return $this->cacheDir();
            }
        };

        $this->assertSame($dir, $plugin->exposedCacheDir());
    }

    /**
     * A numeric timeout is used as configured.
     *
     * The default and the non-numeric fallback are covered above; this is the
     * ordinary case, and without it a bug that ignored a configured timeout
     * entirely would go unnoticed.
     */
    public function testNumericTimeoutIsUsedAsConfigured(): void
    {
        $plugin = new class ([], ['api_key' => 'k', 'timeout' => '2.5']) extends AbuseIpdb {
            public function exposedTimeout(): float
            {
                return $this->timeout();
            }
        };

        $this->assertSame(2.5, $plugin->exposedTimeout());
    }

    /**
     * With no cache_dir and no constant, the cache lands under the temp dir.
     */
    public function testCacheDirDefaultsUnderTheTempDirectory(): void
    {
        $plugin = new class ([], ['api_key' => 'k']) extends AbuseIpdb {
            public function exposedCacheDir(): string
            {
                return $this->cacheDir();
            }
        };

        $this->assertSame(
            sys_get_temp_dir() . '/kanopi-firewall-abuseipdb',
            $plugin->exposedCacheDir()
        );
    }

    /**
     * An entry that cannot be encoded is not written at all.
     *
     * Writing whatever `json_encode()` produced on failure would put `null`
     * or a truncated fragment in the cache, and a corrupt entry is worse than
     * a missing one: the next request would read it back, fail to parse it,
     * and spend quota anyway — while looking like a cache hit.
     */
    public function testUnencodableCacheEntryIsNotWritten(): void
    {
        $plugin = new class ([], ['api_key' => 'k', 'cache_dir' => $this->cacheDir]) extends AbuseIpdb {
            /**
             * @param array<string, mixed> $entry
             *   Entry to write.
             */
            public function exposedWriteCache(string $ip, array $entry): void
            {
                $this->writeCache($ip, $entry);
            }

            public function exposedCachePath(string $ip): ?string
            {
                return $this->cachePath($ip);
            }
        };

        // NAN has no JSON representation, so json_encode() fails outright.
        $plugin->exposedWriteCache('203.0.113.45', ['report' => ['score' => NAN]]);

        $path = $plugin->exposedCachePath('203.0.113.45');
        $this->assertIsString($path);
        $this->assertFileDoesNotExist($path, 'A cache entry that cannot be encoded must not be written.');
    }

    /**
     * Install a canned HTTP response with a conventional status line.
     */
    private function fakeResponse(int $status, string $body): void
    {
        $GLOBALS['fake_plugin_http_response'] = [
            'headers' => ['HTTP/1.1 ' . $status . ' ' . ($status === 200 ? 'OK' : 'Error')],
            'body' => $body,
        ];
    }

    private function captureLogs(): TestLogHandler
    {
        $handler = new TestLogHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        return $handler;
    }

    /**
     * @param array<string, mixed> $config
     *   Plugin config; `api_key` and `cache_dir` are filled in.
     */
    private function plugin(array $config): AbuseIpdb
    {
        $config['api_key'] ??= 'test-key';
        $config['cache_dir'] ??= $this->cacheDir;

        return new AbuseIpdb([], $config);
    }

    private function request(string $ip = '203.0.113.45'): Request
    {
        return Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $ip]);
    }
}
