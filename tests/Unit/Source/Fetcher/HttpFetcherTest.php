<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source\Fetcher;

use Kanopi\Firewall\Source\Fetcher\HttpFetcher;
use Kanopi\Firewall\Source\Fetcher\LocalFetcher;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Tests response parsing for the conditional-request fetcher.
 */
class HttpFetcherTest extends AbstractTestCase
{
    /**
     * Call a private method on the fetcher.
     */
    private function invoke(string $method, mixed ...$arguments): mixed
    {
        $reflection = new \ReflectionMethod(HttpFetcher::class, $method);
        $reflection->setAccessible(true);

        return $reflection->invoke(new HttpFetcher(), ...$arguments);
    }

    /**
     * The status code is read from the response line.
     */
    #[DataProvider('statusProvider')]
    public function testStatusParsing(array $headers, int $expected): void
    {
        $this->assertSame($expected, $this->invoke('status', $headers));
    }

    /**
     * Response header sets and the status each yields.
     */
    public static function statusProvider(): array
    {
        return [
            'ok' => [['HTTP/1.1 200 OK'], 200],
            'not modified' => [['HTTP/1.1 304 Not Modified'], 304],
            'http/2' => [['HTTP/2 200'], 200],
            'not found' => [['HTTP/1.1 404 Not Found'], 404],
            'nothing parseable' => [['Content-Type: text/plain'], 0],
            'redirect keeps the final status' => [
                ['HTTP/1.1 301 Moved Permanently', 'Location: /new', 'HTTP/1.1 200 OK'],
                200,
            ],
        ];
    }

    /**
     * Header lookup is case-insensitive.
     */
    public function testHeaderLookupIsCaseInsensitive(): void
    {
        $headers = ['HTTP/1.1 200 OK', 'ETag: W/"v1"', 'Last-Modified: Wed, 03 Sep 2026 18:02:00 GMT'];

        $this->assertSame('W/"v1"', $this->invoke('header', $headers, 'etag'));
        $this->assertSame('Wed, 03 Sep 2026 18:02:00 GMT', $this->invoke('header', $headers, 'LAST-MODIFIED'));
    }

    /**
     * An absent header reads as null, as does an empty one.
     */
    public function testAbsentHeaderIsNull(): void
    {
        $this->assertNull($this->invoke('header', ['HTTP/1.1 200 OK'], 'etag'));
        $this->assertNull($this->invoke('header', ['HTTP/1.1 200 OK', 'ETag:  '], 'etag'));
    }

    /**
     * Headers set by a redirect hop are discarded — only the final response's
     * validators are worth storing, since they describe the body we kept.
     */
    public function testRedirectHeadersAreSuperseded(): void
    {
        $headers = [
            'HTTP/1.1 301 Moved Permanently',
            'ETag: W/"old"',
            'HTTP/1.1 200 OK',
            'Content-Type: text/plain',
        ];

        $this->assertNull($this->invoke('header', $headers, 'etag'));
    }

    /**
     * A header value containing a colon survives intact.
     */
    public function testHeaderValueMayContainColons(): void
    {
        $headers = ['HTTP/1.1 200 OK', 'Last-Modified: Wed, 03 Sep 2026 18:02:00 GMT'];

        $this->assertStringContainsString('18:02:00', (string) $this->invoke('header', $headers, 'last-modified'));
    }

    /**
     * The fetchers divide work by upstream shape and do not overlap.
     */
    public function testFetcherSelection(): void
    {
        $remote = SourceDefinition::fromArray(['upstream' => 'https://example.org/list.txt']);
        $local = SourceDefinition::fromArray(['upstream' => '/lists/list.txt']);

        $this->assertTrue((new HttpFetcher())->supports($remote));
        $this->assertFalse((new HttpFetcher())->supports($local));
        $this->assertTrue((new LocalFetcher())->supports($local));
        $this->assertFalse((new LocalFetcher())->supports($remote));
    }
}
