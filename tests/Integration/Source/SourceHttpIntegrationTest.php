<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration\Source;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\Fetcher\HttpFetcher;
use Kanopi\Firewall\Source\SourceCache;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Source\SourceLoader;
use Kanopi\Firewall\Tests\Integration\IntegrationTestCase;

/**
 * Exercises the HTTP fetcher against real servers.
 *
 * Two PHP built-in servers run on different ports — different origins, as far
 * as credential handling is concerned. That is what makes it possible to prove
 * the thing most worth proving here: an upstream that redirects elsewhere does
 * not get to collect the credential meant for it.
 */
class SourceHttpIntegrationTest extends IntegrationTestCase
{
    /**
     * Running server processes, by port.
     *
     * @var array<int, resource>
     */
    private array $servers = [];

    /**
     * Ports the servers are listening on.
     *
     * @var array<int, int>
     */
    private array $ports = [];

    /**
     * File the router appends each received request to.
     */
    private string $recordFile;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->recordFile = $this->tempDir . '/requests.jsonl';
        touch($this->recordFile);

        foreach ([0, 1] as $index) {
            $this->ports[$index] = $this->startServer();
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        foreach ($this->servers as $process) {
            @proc_terminate($process);
            @proc_close($process);
        }

        $this->servers = [];
        parent::tearDown();
    }

    /**
     * Boot a built-in server on a free port and wait for it to answer.
     */
    private function startServer(): int
    {
        $router = __DIR__ . '/server/router.php';

        for ($attempt = 0; $attempt < 5; $attempt++) {
            $port = random_int(20000, 60000);

            // Two things worth spelling out. PHP_BINARY rather than a bare
            // `php`, because the explicit environment below replaces the
            // inherited one and `$_ENV` is empty under the default
            // variables_order — so PATH would be missing and the exec would
            // fail silently. And file descriptors rather than pipes, because
            // the built-in server logs every request to stderr and blocks once
            // an undrained pipe fills.
            $process = @proc_open(
                sprintf('exec %s -S 127.0.0.1:%d %s', escapeshellarg(PHP_BINARY), $port, escapeshellarg($router)),
                [
                    ['file', '/dev/null', 'r'],
                    ['file', $this->tempDir . '/server-out.log', 'a'],
                    ['file', $this->tempDir . '/server-err.log', 'a'],
                ],
                $pipes,
                null,
                ['FIREWALL_TEST_RECORD' => $this->recordFile] + getenv()
            );

            if (!is_resource($process)) {
                continue;
            }

            if ($this->waitForServer($process, $port)) {
                $this->servers[] = $process;

                return $port;
            }

            @proc_terminate($process);
            @proc_close($process);
        }

        $this->markTestSkipped('Could not start a PHP built-in server for the HTTP source tests.');
    }

    /**
     * Poll until the server accepts connections, or has plainly died.
     *
     * @param resource $process
     *   The server process.
     * @param int $port
     *   Port it should be listening on.
     *
     * @return bool
     *   True once the port answers.
     */
    private function waitForServer($process, int $port): bool
    {
        for ($attempt = 0; $attempt < 60; $attempt++) {
            $status = proc_get_status($process);

            if ($status !== false && !$status['running']) {
                // Exited already — a bound port, or a failed exec. Retrying
                // the same wait would only burn time.
                return false;
            }

            $socket = @fsockopen('127.0.0.1', $port, $errno, $error, 0.1);

            if (is_resource($socket)) {
                fclose($socket);

                return true;
            }

            usleep(25000);
        }

        return false;
    }

    /**
     * Requests the routers recorded, oldest first.
     *
     * @return array<int, array<string, mixed>>
     */
    private function recorded(): array
    {
        $requests = [];

        foreach (explode("\n", (string) file_get_contents($this->recordFile)) as $line) {
            if (trim($line) === '') {
                continue;
            }

            $decoded = json_decode($line, true);

            if (is_array($decoded)) {
                $requests[] = $decoded;
            }
        }

        return $requests;
    }

    /**
     * Requests recorded against one port.
     *
     * @return array<int, array<string, mixed>>
     */
    private function recordedFor(int $port): array
    {
        return array_values(array_filter(
            $this->recorded(),
            static fn (array $request): bool => (int) ($request['port'] ?? 0) === $port
        ));
    }

    /**
     * A URL on one of the running servers.
     */
    private function url(int $index, string $path): string
    {
        return sprintf('http://127.0.0.1:%d%s', $this->ports[$index], $path);
    }

    /**
     * A loader writing into this test's temp directory.
     */
    private function loader(): SourceLoader
    {
        return new SourceLoader(sourceCache: new SourceCache($this->tempDir . '/cache'));
    }

    /**
     * A plain fetch works and returns the body.
     */
    public function testPlainFetch(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'plain',
            'upstream' => $this->url(0, '/list'),
        ]);

        $this->assertSame(['1.1.1.1', '2.2.2.2'], $this->loader()->load($definition));
    }

    /**
     * A bearer token reaches the upstream that asked for it.
     */
    public function testBearerTokenIsSent(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'protected',
            'upstream' => [
                'url' => $this->url(0, '/protected'),
                'auth' => ['type' => 'bearer', 'token' => 's3cr3t'],
                'allow_insecure' => true,
            ],
        ]);

        $this->assertSame(['3.3.3.3'], $this->loader()->load($definition));

        $received = $this->recordedFor($this->ports[0]);
        $this->assertSame('Bearer s3cr3t', $received[0]['headers']['authorization'] ?? null);
    }

    /**
     * Without the credential the same endpoint refuses, and the error points
     * at the setting to check.
     */
    public function testMissingCredentialReportsUsefully(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'protected',
            'upstream' => $this->url(0, '/protected'),
        ]);

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('HTTP 401');

        $this->loader()->load($definition);
    }

    /**
     * Extra headers are sent alongside the credential.
     */
    public function testExtraHeadersAreSent(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'with-headers',
            'upstream' => [
                'url' => $this->url(0, '/list'),
                'headers' => ['X-Account' => '12345'],
            ],
        ]);

        $this->loader()->load($definition);

        $received = $this->recordedFor($this->ports[0]);
        $this->assertSame('12345', $received[0]['headers']['x-account'] ?? null);
    }

    /**
     * Query auth arrives as a query parameter.
     */
    public function testQueryAuthIsSent(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'query-auth',
            'upstream' => [
                'url' => $this->url(0, '/list'),
                'auth' => ['type' => 'query', 'name' => 'api_key', 'value' => 's3cr3t'],
                'allow_insecure' => true,
            ],
        ]);

        $this->loader()->load($definition);

        $received = $this->recordedFor($this->ports[0]);
        $this->assertStringContainsString('api_key=s3cr3t', (string) ($received[0]['query'] ?? ''));
    }

    /**
     * A redirect within the same origin keeps the credential — the upstream is
     * still the party we meant to authenticate to.
     */
    public function testSameOriginRedirectKeepsCredentials(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'same-origin',
            'upstream' => [
                'url' => $this->url(0, '/redirect-same'),
                'auth' => ['type' => 'bearer', 'token' => 's3cr3t'],
                'allow_insecure' => true,
            ],
        ]);

        $this->assertSame(['1.1.1.1', '2.2.2.2'], $this->loader()->load($definition));

        $received = $this->recordedFor($this->ports[0]);
        $listRequest = array_values(array_filter(
            $received,
            static fn (array $request): bool => $request['path'] === '/list'
        ));

        $this->assertNotSame([], $listRequest, 'The redirect should have been followed.');
        $this->assertSame('Bearer s3cr3t', $listRequest[0]['headers']['authorization'] ?? null);
    }

    /**
     * The one that matters: a redirect to a different origin must not carry
     * the credential with it. PHP's own follow_location would have resent it.
     */
    public function testCrossOriginRedirectDropsCredentials(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'cross-origin',
            'upstream' => [
                'url' => $this->url(0, '/redirect-cross?to=' . $this->ports[1]),
                'auth' => ['type' => 'bearer', 'token' => 's3cr3t'],
                'headers' => ['X-API-Key' => 'also-secret'],
                'allow_insecure' => true,
            ],
        ]);

        $this->assertSame(['1.1.1.1', '2.2.2.2'], $this->loader()->load($definition));

        $first = $this->recordedFor($this->ports[0]);
        $second = $this->recordedFor($this->ports[1]);

        $this->assertSame(
            'Bearer s3cr3t',
            $first[0]['headers']['authorization'] ?? null,
            'The origin we authenticated to should still receive the credential.'
        );

        $this->assertNotSame([], $second, 'The cross-origin redirect should have been followed.');
        $this->assertArrayNotHasKey(
            'authorization',
            $second[0]['headers'],
            'A credential must not follow a redirect to another origin.'
        );
        $this->assertArrayNotHasKey(
            'x-api-key',
            $second[0]['headers'],
            'Operator-set headers are credentials too and must not cross origins.'
        );
    }

    /**
     * Redirect following is bounded.
     */
    public function testRedirectsAreBounded(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'no-redirects',
            'upstream' => [
                'url' => $this->url(0, '/redirect-same'),
                'max_redirects' => 0,
            ],
        ]);

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('HTTP 302');

        $this->loader()->load($definition);
    }

    /**
     * A conditional request avoids re-downloading an unchanged list.
     */
    public function testConditionalRequestYields304(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'conditional',
            'upstream' => $this->url(0, '/conditional'),
            'ttl' => 0,
        ]);

        $loader = $this->loader();

        $this->assertSame(['4.4.4.4'], $loader->load($definition));
        $this->assertSame(['4.4.4.4'], $loader->load($definition), 'A 304 reuses the cached entries.');

        $received = $this->recordedFor($this->ports[0]);
        $this->assertCount(2, $received);
        $this->assertArrayNotHasKey('if-none-match', $received[0]['headers']);
        $this->assertSame('W/"list-v1"', $received[1]['headers']['if-none-match'] ?? null);
    }

    /**
     * A POST upstream sends its body.
     */
    public function testPostBodyIsSent(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'posted',
            'upstream' => [
                'url' => $this->url(0, '/list'),
                'method' => 'POST',
                'body' => '{"query":"all"}',
                'headers' => ['Content-Type' => 'application/json'],
            ],
        ]);

        $this->loader()->load($definition);

        $received = $this->recordedFor($this->ports[0]);
        $this->assertSame('POST', $received[0]['method']);
        $this->assertSame('{"query":"all"}', $received[0]['body']);
    }

    /**
     * A 404 is an error naming the status, not a silently empty rule list.
     */
    public function testNotFoundIsAnError(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'missing',
            'upstream' => $this->url(0, '/nope'),
        ]);

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('HTTP 404');

        $this->loader()->load($definition);
    }

    /**
     * The fetcher handles remote upstreams and leaves local ones alone.
     */
    public function testSupportsOnlyRemoteUpstreams(): void
    {
        $this->assertTrue((new HttpFetcher())->supports(
            SourceDefinition::fromArray(['upstream' => $this->url(0, '/list')])
        ));
        $this->assertFalse((new HttpFetcher())->supports(
            SourceDefinition::fromArray(['upstream' => '/lists/a.txt'])
        ));
    }

    /**
     * A Last-Modified response is revalidated with If-Modified-Since.
     */
    public function testLastModifiedDrivesConditionalRequests(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'last-modified',
            'upstream' => $this->url(0, '/last-modified'),
            'ttl' => 0,
        ]);

        $loader = $this->loader();

        $this->assertSame(['5.5.5.5'], $loader->load($definition));
        $this->assertSame(['5.5.5.5'], $loader->load($definition), 'A 304 reuses the cached entries.');

        $received = $this->recordedFor($this->ports[0]);
        $this->assertArrayNotHasKey('if-modified-since', $received[0]['headers']);
        $this->assertSame(
            'Wed, 03 Sep 2026 18:02:00 GMT',
            $received[1]['headers']['if-modified-since'] ?? null
        );
    }

    /**
     * A redirect with no Location is not followed, and reports the status.
     */
    public function testRedirectWithoutLocationIsNotFollowed(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'nowhere',
            'upstream' => $this->url(0, '/redirect-no-location'),
        ]);

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('HTTP 302');

        $this->loader()->load($definition);
    }

    /**
     * A relative Location is resolved against the URL that produced it.
     */
    public function testRelativeRedirectIsResolved(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'relative',
            'upstream' => $this->url(0, '/redirect-relative'),
        ]);

        $this->assertSame(['1.1.1.1', '2.2.2.2'], $this->loader()->load($definition));
    }

    /**
     * A redirect loop is bounded by max_redirects rather than running forever.
     */
    public function testRedirectLoopIsBounded(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'loop',
            'upstream' => ['url' => $this->url(0, '/redirect-loop'), 'max_redirects' => 3],
        ]);

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('HTTP 302');

        $this->loader()->load($definition);
    }

    /**
     * A 303 turns the request into a GET, as the status requires.
     */
    public function testSeeOtherDowngradesThePostToAGet(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'see-other',
            'upstream' => [
                'url' => $this->url(0, '/redirect-see-other'),
                'method' => 'POST',
                'body' => 'q=1',
            ],
        ]);

        $this->assertSame(['GET'], $this->loader()->load($definition));
    }

    /**
     * A per-source timeout is honoured over the fetcher's own.
     */
    public function testUpstreamTimeoutIsUsed(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'timed',
            'upstream' => ['url' => $this->url(0, '/list'), 'timeout' => 30],
        ]);

        $this->assertSame(['1.1.1.1', '2.2.2.2'], $this->loader()->load($definition));
    }

    /**
     * A fetcher-level timeout is used when the source declares none.
     */
    public function testFetcherTimeoutIsUsedWhenTheSourceDeclaresNone(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'fetcher-timeout',
            'upstream' => $this->url(0, '/list'),
        ]);

        $loader = new SourceLoader(
            sourceCache: new SourceCache($this->tempDir . '/cache'),
            fetchers: [new HttpFetcher(timeout: 20.0)]
        );

        $this->assertSame(['1.1.1.1', '2.2.2.2'], $loader->load($definition));
    }

    /**
     * A connection that cannot be opened at all is reported.
     */
    public function testUnreachableUpstreamIsReported(): void
    {
        // Port 1 is privileged and never listening. Deliberately not an
        // ephemeral port grabbed and released: that range overlaps the one
        // startServer() binds, so the "closed" port could be one of this
        // test's own servers.
        $definition = SourceDefinition::fromArray([
            'name' => 'closed',
            'upstream' => 'http://127.0.0.1:1/list',
        ]);

        $this->expectException(SourceException::class);

        $this->loader()->load($definition);
    }
}
