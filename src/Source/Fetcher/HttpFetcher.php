<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Source\Fetcher;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Logging\LoggingTrait;
use Kanopi\Firewall\Source\FetchResult;
use Kanopi\Firewall\Source\SourceDefinition;

/**
 * Retrieves a source over HTTP, revalidating before re-downloading.
 *
 * The first fetch records whatever `ETag` and `Last-Modified` the upstream
 * offered. Later fetches send them back as `If-None-Match` / `If-Modified-Since`,
 * so an unchanged list answers `304` and no body crosses the wire at all. That
 * is cheaper than hashing a body we would have had to download first.
 *
 * Built on streams rather than an HTTP client so the library gains no new
 * dependency for this. Headers come from the stream's own metadata rather than
 * the magic `$http_response_header` local, which is only defined when the HTTP
 * wrapper got far enough to set it.
 *
 * **Redirects are followed by hand.** PHP's `follow_location` reuses the whole
 * request context on every hop, so a redirect to another host would resend the
 * `Authorization` header to whoever answered it. Following the chain here means
 * credentials can be dropped the moment the origin changes.
 */
final class HttpFetcher implements FetcherInterface
{
    use LoggingTrait;

    /**
     * Default seconds to wait on a remote list.
     */
    private const DEFAULT_TIMEOUT = 5.0;

    /**
     * Statuses that send us somewhere else.
     */
    private const REDIRECTS = [301, 302, 303, 307, 308];

    /**
     * @param float|null $timeout
     *   Seconds to wait, or NULL to take the source's own setting, then
     *   KANOPI_FIREWALL_CACHE_TIMEOUT.
     * @param string $userAgent
     *   Value sent as `User-Agent`.
     */
    public function __construct(
        private readonly ?float $timeout = null,
        private readonly string $userAgent = 'kanopi-firewall/source-fetcher',
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function supports(SourceDefinition $sourceDefinition): bool
    {
        return $sourceDefinition->isRemote();
    }

    /**
     * {@inheritdoc}
     */
    public function fetch(SourceDefinition $sourceDefinition, array $validators = []): FetchResult
    {
        $upstream = $sourceDefinition->upstream;

        $etag = is_string($validators['etag'] ?? null) ? $validators['etag'] : null;
        $lastModified = is_string($validators['last_modified'] ?? null) ? $validators['last_modified'] : null;

        $headers = [
            'User-Agent' => $this->userAgent,
            'Accept' => '*/*',
        ] + $upstream->requestHeaders();

        if ($etag !== null && $etag !== '') {
            $headers['If-None-Match'] = $etag;
        }

        if ($lastModified !== null && $lastModified !== '') {
            $headers['If-Modified-Since'] = $lastModified;
        }

        $url = $upstream->requestUrl();
        $origin = $this->origin($url);
        $method = $upstream->method;
        $body = $upstream->body;
        $hops = 0;

        while (true) {
            [$status, $responseHeaders, $responseBody] = $this->request(
                $sourceDefinition,
                $url,
                $method,
                $headers,
                $body
            );

            if (!in_array($status, self::REDIRECTS, true) || $hops >= $upstream->maxRedirects) {
                break;
            }

            $location = $this->header($responseHeaders, 'location');

            if ($location === null) {
                break;
            }

            $url = $this->resolve($url, $location);
            $hops++;

            if ($this->origin($url) !== $origin) {
                // A redirect off the original origin must not carry the
                // credential with it. Anything the operator set by hand goes
                // too — an API key header is a credential whatever it is called.
                $headers = array_diff_key($headers, $upstream->requestHeaders());
                $origin = $this->origin($url);

                $this->getLogger()->debug('Source redirect crossed origins; credentials dropped', [
                    'source' => $sourceDefinition->name,
                    'to' => $upstream->display(),
                ]);
            }

            // 303 always becomes a GET; 301 and 302 do in practice for anything
            // that was not already one. 307 and 308 preserve the method.
            if ($status === 303 || (in_array($status, [301, 302], true) && $method !== 'GET')) {
                $method = 'GET';
                $body = null;
            }
        }

        if ($status === 304) {
            $this->getLogger()->debug('Source unchanged upstream', [
                'source' => $sourceDefinition->name,
                'status' => $status,
            ]);

            return FetchResult::unchanged($etag, $lastModified);
        }

        if ($status < 200 || $status >= 300) {
            throw new SourceException(sprintf(
                'Source "%s": upstream returned HTTP %d.%s',
                $sourceDefinition->name,
                $status,
                in_array($status, [401, 403], true)
                    ? ' Check the upstream.auth credentials.'
                    : ''
            ));
        }

        if ($responseBody === false) {
            throw new SourceException(sprintf(
                'Source "%s": upstream returned HTTP %d but the body could not be read.',
                $sourceDefinition->name,
                $status
            ));
        }

        return new FetchResult(
            $responseBody,
            false,
            $this->header($responseHeaders, 'etag') ?? $etag,
            $this->header($responseHeaders, 'last-modified') ?? $lastModified
        );
    }

    /**
     * Perform one request, without following anything.
     *
     * @param SourceDefinition $sourceDefinition
     *   The source being fetched, for error messages.
     * @param string $url
     *   The URL to request.
     * @param string $method
     *   HTTP method.
     * @param array<string, string> $headers
     *   Request headers.
     * @param string|null $body
     *   Request body.
     *
     * @return array{0: int, 1: array<int, string>, 2: string|false}
     *   Status, response headers, and body.
     *
     * @throws SourceException
     *   When the stream cannot be opened or answers nothing.
     */
    private function request(
        SourceDefinition $sourceDefinition,
        string $url,
        string $method,
        array $headers,
        ?string $body
    ): array {
        $lines = [];

        foreach ($headers as $header => $value) {
            $lines[] = $header . ': ' . $value;
        }

        $options = [
            'method' => $method,
            'header' => implode("\r\n", $lines),
            'timeout' => $this->timeout($sourceDefinition),
            // Redirects are followed by hand so credentials can be dropped
            // when the origin changes.
            'follow_location' => 0,
            // Without this a 304 or 404 makes the stream fail to open, and the
            // response headers we need go unread.
            'ignore_errors' => true,
        ];

        if ($body !== null) {
            $options['content'] = $body;
        }

        [$responseBody, $responseHeaders] = $this->readStream($sourceDefinition, $url, $options);

        if ($responseHeaders === []) {
            throw new SourceException(sprintf(
                'Source "%s": no response headers from "%s".',
                $sourceDefinition->name,
                $sourceDefinition->upstream->display()
            ));
        }

        return [$this->status($responseHeaders), $responseHeaders, $responseBody];
    }

    /**
     * Open the URL and return its body and response headers.
     *
     * A seam. The two failure paths below the call — a stream that opens but
     * yields no headers, and one whose body cannot be read despite a 2xx — are
     * real, and neither can be provoked from a test against a working server.
     * Overriding this is how they get exercised.
     *
     * @param SourceDefinition $sourceDefinition
     *   The source being fetched, for error messages.
     * @param string $url
     *   The URL to open.
     * @param array<string, mixed> $options
     *   Stream context `http` options.
     *
     * @return array{0: string|false, 1: array<int, string>}
     *   The body, and the raw response headers.
     *
     * @throws SourceException
     *   When the stream cannot be opened at all.
     */
    protected function readStream(SourceDefinition $sourceDefinition, string $url, array $options): array
    {
        $handle = @fopen($url, 'r', false, stream_context_create(['http' => $options]));

        if ($handle === false) {
            throw new SourceException(sprintf(
                'Source "%s": could not open "%s".',
                $sourceDefinition->name,
                $sourceDefinition->upstream->display()
            ));
        }

        try {
            $meta = stream_get_meta_data($handle);
            $body = stream_get_contents($handle);
        } finally {
            fclose($handle);
        }

        $headers = [];

        foreach ($meta['wrapper_data'] ?? [] as $header) {
            if (is_string($header)) {
                $headers[] = $header;
            }
        }

        return [$body, $headers];
    }

    /**
     * Seconds to wait on the upstream.
     *
     * @param SourceDefinition $sourceDefinition
     *   The source being fetched.
     *
     * @return float
     *   The effective timeout.
     */
    private function timeout(SourceDefinition $sourceDefinition): float
    {
        if ($sourceDefinition->upstream->timeout !== null) {
            return $sourceDefinition->upstream->timeout;
        }

        if ($this->timeout !== null) {
            return $this->timeout;
        }

        $configured = defined('KANOPI_FIREWALL_CACHE_TIMEOUT')
            ? constant('KANOPI_FIREWALL_CACHE_TIMEOUT')
            : null;

        if (is_numeric($configured)) {
            return (float) $configured;
        }

        return self::DEFAULT_TIMEOUT;
    }

    /**
     * The scheme, host, and port a URL belongs to.
     *
     * @param string $url
     *   The URL.
     *
     * @return string
     *   An origin string for comparison.
     */
    private function origin(string $url): string
    {
        $parts = parse_url($url);

        if ($parts === false) {
            return '';
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);

        return sprintf('%s://%s:%d', $scheme, strtolower((string) ($parts['host'] ?? '')), $port);
    }

    /**
     * Resolve a `Location` value against the URL that produced it.
     *
     * @param string $base
     *   The URL that was requested.
     * @param string $location
     *   The `Location` header value, absolute or relative.
     *
     * @return string
     *   An absolute URL.
     */
    private function resolve(string $base, string $location): string
    {
        if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $location) === 1) {
            return $location;
        }

        $parts = parse_url($base);

        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            return $location;
        }

        $root = $parts['scheme'] . '://' . $parts['host'];

        if (isset($parts['port'])) {
            $root .= ':' . $parts['port'];
        }

        if (str_starts_with($location, '/')) {
            return $root . $location;
        }

        $directory = rtrim(dirname($parts['path'] ?? '/'), '/');

        return $root . $directory . '/' . $location;
    }

    /**
     * Read the status code from a response.
     *
     * @param array<int, string> $headers
     *   Raw response headers.
     *
     * @return int
     *   The status code, or 0 when none could be parsed.
     */
    private function status(array $headers): int
    {
        $status = 0;

        foreach ($headers as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#i', $header, $matches) === 1) {
                $status = (int) $matches[1];
            }
        }

        return $status;
    }

    /**
     * Read one header value from a response.
     *
     * @param array<int, string> $headers
     *   Raw response headers.
     * @param string $name
     *   Header name, case-insensitive.
     *
     * @return string|null
     *   The value, or NULL when absent.
     */
    private function header(array $headers, string $name): ?string
    {
        $value = null;

        foreach ($headers as $header) {
            $position = strpos($header, ':');

            if ($position === false) {
                // A status line from an earlier hop; anything it set is
                // superseded by the response that follows.
                if (preg_match('#^HTTP/#i', $header) === 1) {
                    $value = null;
                }

                continue;
            }

            if (strcasecmp(trim(substr($header, 0, $position)), $name) === 0) {
                $value = trim(substr($header, $position + 1));
            }
        }

        return $value === '' ? null : $value;
    }
}
