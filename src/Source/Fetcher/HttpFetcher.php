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
 */
final class HttpFetcher implements FetcherInterface
{
    use LoggingTrait;

    /**
     * Default seconds to wait on a remote list.
     */
    private const DEFAULT_TIMEOUT = 5.0;

    /**
     * @param float|null $timeout
     *   Seconds to wait, or NULL to take KANOPI_FIREWALL_CACHE_TIMEOUT.
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
        $headers = [
            'User-Agent: ' . $this->userAgent,
            'Accept: */*',
        ];

        $etag = $validators['etag'] ?? null;
        $lastModified = $validators['last_modified'] ?? null;

        if (is_string($etag) && $etag !== '') {
            $headers[] = 'If-None-Match: ' . $etag;
        }

        if (is_string($lastModified) && $lastModified !== '') {
            $headers[] = 'If-Modified-Since: ' . $lastModified;
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => implode("\r\n", $headers),
                'timeout' => $this->timeout(),
                'follow_location' => 1,
                'max_redirects' => 5,
                // Without this a 304 or 404 makes the stream fail to open,
                // and the response headers we need go unread.
                'ignore_errors' => true,
            ],
        ]);

        $handle = @fopen($sourceDefinition->upstream, 'r', false, $context);

        if ($handle === false) {
            throw new SourceException(sprintf(
                'Source "%s": could not open "%s".',
                $sourceDefinition->name,
                $sourceDefinition->upstream
            ));
        }

        try {
            $meta = stream_get_meta_data($handle);
            $body = stream_get_contents($handle);
        } finally {
            fclose($handle);
        }

        $responseHeaders = [];

        foreach ($meta['wrapper_data'] ?? [] as $header) {
            if (is_string($header)) {
                $responseHeaders[] = $header;
            }
        }

        if ($responseHeaders === []) {
            throw new SourceException(sprintf(
                'Source "%s": no response headers from "%s".',
                $sourceDefinition->name,
                $sourceDefinition->upstream
            ));
        }

        $status = $this->status($responseHeaders);

        if ($status === 304) {
            $this->getLogger()->debug('Source unchanged upstream', [
                'source' => $sourceDefinition->name,
                'status' => $status,
            ]);

            return FetchResult::unchanged($etag, $lastModified);
        }

        if ($status < 200 || $status >= 300) {
            throw new SourceException(sprintf(
                'Source "%s": upstream returned HTTP %d.',
                $sourceDefinition->name,
                $status
            ));
        }

        if ($body === false) {
            throw new SourceException(sprintf(
                'Source "%s": upstream returned HTTP %d but the body could not be read.',
                $sourceDefinition->name,
                $status
            ));
        }

        return new FetchResult(
            $body,
            false,
            $this->header($responseHeaders, 'etag') ?? $etag,
            $this->header($responseHeaders, 'last-modified') ?? $lastModified
        );
    }

    /**
     * Seconds to wait on the upstream.
     *
     * @return float
     *   The configured timeout.
     */
    private function timeout(): float
    {
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
     * Read the status code from a response.
     *
     * Redirects leave several status lines in the array; the last one is the
     * response we actually got.
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
                // A status line from an earlier hop; anything a redirect set
                // is superseded by the final response.
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
