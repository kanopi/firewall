<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source\Fetcher;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\Fetcher\HttpFetcher;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;

/**
 * Covers the fetcher paths a working server cannot produce.
 *
 * A stream that opens but yields no headers, and one whose body cannot be read
 * despite a success status, are both real failure modes and neither can be
 * provoked against a server that is behaving. They go through the `readStream`
 * seam instead.
 */
class HttpFetcherEdgeTest extends AbstractTestCase
{
    /**
     * A remote source definition.
     */
    private function definition(): SourceDefinition
    {
        return SourceDefinition::fromArray(['name' => 'feed', 'upstream' => 'https://example.org/list.txt']);
    }

    /**
     * A fetcher whose stream returns whatever the test wants.
     *
     * @param string|false $body
     *   The body to hand back.
     * @param array<int, string> $headers
     *   The raw response headers to hand back.
     */
    private function fetcherReturning(string|false $body, array $headers): HttpFetcher
    {
        return new class ($body, $headers) extends HttpFetcher {
            /**
             * @param string|false $body
             *   Body to return.
             * @param array<int, string> $headers
             *   Headers to return.
             */
            public function __construct(private readonly string|false $body, private readonly array $headers)
            {
                parent::__construct();
            }

            protected function readStream(SourceDefinition $sourceDefinition, string $url, array $options): array
            {
                return [$this->body, $this->headers];
            }
        };
    }

    /**
     * A response with no headers at all is reported rather than parsed.
     */
    public function testResponseWithoutHeadersIsReported(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('no response headers');

        $this->fetcherReturning('body', [])->fetch($this->definition());
    }

    /**
     * A success status whose body could not be read is reported.
     *
     * Returning an empty rule list here would look exactly like an upstream
     * that legitimately went empty.
     */
    public function testUnreadableBodyOnSuccessIsReported(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('the body could not be read');

        $this->fetcherReturning(false, ['HTTP/1.1 200 OK'])->fetch($this->definition());
    }

    /**
     * A body that reads fine comes back with its validators.
     */
    public function testSuccessfulResponseCarriesItsValidators(): void
    {
        $result = $this->fetcherReturning(
            "1.1.1.1\n",
            ['HTTP/1.1 200 OK', 'ETag: W/"v9"', 'Last-Modified: Wed, 03 Sep 2026 18:02:00 GMT']
        )->fetch($this->definition());

        $this->assertSame("1.1.1.1\n", $result->body);
        $this->assertSame('W/"v9"', $result->etag);
        $this->assertSame('Wed, 03 Sep 2026 18:02:00 GMT', $result->lastModified);
    }

    /**
     * An origin cannot be derived from a URL that does not parse.
     *
     * It resolves to an empty string, which compares unequal to any real
     * origin — so a credential is dropped rather than carried into the unknown.
     */
    public function testUnparseableUrlHasNoOrigin(): void
    {
        $method = new \ReflectionMethod(HttpFetcher::class, 'origin');
        $method->setAccessible(true);

        $this->assertSame('', $method->invoke(new HttpFetcher(), 'http://:'));
    }

    /**
     * Location resolution handles every form a server might send.
     *
     * @param string $base
     *   The URL that was requested.
     * @param string $location
     *   The Location header value.
     * @param string $expected
     *   The URL that should be requested next.
     */
    #[DataProvider('locationProvider')]
    public function testLocationResolution(string $base, string $location, string $expected): void
    {
        $method = new \ReflectionMethod(HttpFetcher::class, 'resolve');
        $method->setAccessible(true);

        $this->assertSame($expected, $method->invoke(new HttpFetcher(), $base, $location));
    }

    /**
     * Redirect targets, absolute and relative.
     */
    public static function locationProvider(): array
    {
        return [
            'absolute' => [
                'https://a.example/list',
                'https://b.example/other',
                'https://b.example/other',
            ],
            'root relative' => [
                'https://a.example/v1/list',
                '/v2/list',
                'https://a.example/v2/list',
            ],
            'path relative' => [
                'https://a.example/v1/list',
                'other',
                'https://a.example/v1/other',
            ],
            'port preserved' => [
                'https://a.example:8443/v1/list',
                '/v2/list',
                'https://a.example:8443/v2/list',
            ],
            'unparseable base returns the location as given' => [
                'not a url',
                '/v2/list',
                '/v2/list',
            ],
        ];
    }

    /**
     * The global timeout constant is the last fallback.
     */
    #[RunInSeparateProcess]
    public function testGlobalTimeoutConstantIsUsed(): void
    {
        define('KANOPI_FIREWALL_CACHE_TIMEOUT', 12.5);

        $method = new \ReflectionMethod(HttpFetcher::class, 'timeout');
        $method->setAccessible(true);

        $this->assertSame(12.5, $method->invoke(new HttpFetcher(), $this->definition()));
    }

    /**
     * A non-numeric constant is ignored rather than cast to nonsense.
     */
    #[RunInSeparateProcess]
    public function testNonNumericTimeoutConstantFallsBackToTheDefault(): void
    {
        define('KANOPI_FIREWALL_CACHE_TIMEOUT', 'soon');

        $method = new \ReflectionMethod(HttpFetcher::class, 'timeout');
        $method->setAccessible(true);

        $this->assertSame(5.0, $method->invoke(new HttpFetcher(), $this->definition()));
    }
}
