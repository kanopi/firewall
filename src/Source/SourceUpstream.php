<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Source;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Utility\Path;

/**
 * Where a source's list lives, and how to ask for it.
 *
 * Most upstreams are a bare location, so the declaration is a string:
 *
 * ```yaml
 * upstream: https://example.org/v1/blocklist.txt
 * ```
 *
 * When the request needs more than a URL — a credential, an API key header, a
 * POST body — the same key takes a map instead:
 *
 * ```yaml
 * upstream:
 *   url: https://feeds.example.com/v1/blocklist.json
 *   method: POST
 *   headers:
 *     X-Account: "12345"
 *   auth:
 *     type: bearer
 *     token: "%env(FEED_TOKEN)%"
 * ```
 *
 * Keeping this under `upstream` rather than spreading it across the source
 * leaves the source's own keys about the *list* — format, select, where,
 * template — and everything about *fetching* it in one place. It also removes
 * the ambiguity that a top-level `headers` would otherwise have against the
 * CSV `header_row` option.
 */
final class SourceUpstream
{
    /**
     * HTTP methods a source may use to fetch a list.
     */
    public const METHODS = ['GET', 'POST', 'HEAD'];

    /**
     * @param string $url
     *   Absolute path, relative path, or URL.
     * @param string $method
     *   HTTP method; ignored for local files.
     * @param array<string, string> $headers
     *   Extra request headers.
     * @param SourceAuth|null $auth
     *   Credentials, when the upstream is not public.
     * @param string|null $body
     *   Request body, for methods that take one.
     * @param float|null $timeout
     *   Seconds to wait, or NULL for the configured default.
     * @param int $maxRedirects
     *   Redirect hops to follow. Credentials are dropped on a cross-origin hop.
     * @param bool $allowInsecure
     *   Permit credentials over plain http. Refused by default.
     */
    private function __construct(
        public readonly string $url,
        public readonly string $method = 'GET',
        public readonly array $headers = [],
        public readonly ?SourceAuth $auth = null,
        public readonly ?string $body = null,
        public readonly ?float $timeout = null,
        public readonly int $maxRedirects = 5,
        public readonly bool $allowInsecure = false,
    ) {
    }

    /**
     * Build an upstream from either declaration form.
     *
     * @param mixed $declaration
     *   A URL/path string, or a map of request options.
     * @param string $sourceName
     *   Source name, for error messages.
     *
     * @return self
     *   The validated upstream.
     *
     * @throws SourceException
     *   When the declaration is malformed or a credential would be sent in clear.
     */
    public static function fromDeclaration(mixed $declaration, string $sourceName): self
    {
        if (is_string($declaration)) {
            $declaration = ['url' => $declaration];
        }

        if (!is_array($declaration)) {
            throw new SourceException(sprintf(
                'Source "%s": "upstream" must be a URL string or a map of request options, %s given.',
                $sourceName,
                gettype($declaration)
            ));
        }

        $url = $declaration['url'] ?? null;

        if (!is_string($url) || trim($url) === '') {
            throw new SourceException(sprintf(
                'Source "%s": "upstream" needs a non-empty "url".',
                $sourceName
            ));
        }

        $url = trim($url);
        $method = strtoupper((string) ($declaration['method'] ?? 'GET'));

        if (!in_array($method, self::METHODS, true)) {
            throw new SourceException(sprintf(
                'Source "%s": upstream.method must be one of %s, got "%s".',
                $sourceName,
                implode(', ', self::METHODS),
                $method
            ));
        }

        $auth = $declaration['auth'] ?? null;

        if ($auth !== null) {
            if (!is_array($auth)) {
                throw new SourceException(sprintf(
                    'Source "%s": upstream.auth must be a map, %s given.',
                    $sourceName,
                    gettype($auth)
                ));
            }

            $auth = SourceAuth::fromArray($auth, $sourceName);
        }

        $allowInsecure = (bool) ($declaration['allow_insecure'] ?? false);

        // A credential sent over plain http travels in clear text. Refusing is
        // the right default; an operator on a trusted internal network can say
        // so explicitly rather than doing it by accident.
        if ($auth instanceof \Kanopi\Firewall\Source\SourceAuth && !$allowInsecure && str_starts_with(strtolower($url), 'http://')) {
            throw new SourceException(sprintf(
                'Source "%s": refusing to send credentials over plain http. Use https, or set '
                . 'upstream.allow_insecure: true when the upstream is on a trusted network.',
                $sourceName
            ));
        }

        $timeout = $declaration['timeout'] ?? null;

        if ($timeout !== null && (!is_numeric($timeout) || (float) $timeout <= 0)) {
            throw new SourceException(sprintf(
                'Source "%s": upstream.timeout must be a positive number of seconds.',
                $sourceName
            ));
        }

        $maxRedirects = $declaration['max_redirects'] ?? 5;

        if (!is_numeric($maxRedirects) || (int) $maxRedirects < 0) {
            throw new SourceException(sprintf(
                'Source "%s": upstream.max_redirects must be a non-negative integer.',
                $sourceName
            ));
        }

        $body = $declaration['body'] ?? null;

        if ($body !== null && !is_string($body)) {
            throw new SourceException(sprintf(
                'Source "%s": upstream.body must be a string.',
                $sourceName
            ));
        }

        return new self(
            url: $url,
            method: $method,
            headers: self::headers($declaration, $sourceName),
            auth: $auth,
            body: $body,
            timeout: $timeout === null ? null : (float) $timeout,
            maxRedirects: (int) $maxRedirects,
            allowInsecure: $allowInsecure,
        );
    }

    /**
     * Whether this upstream is remote rather than a local file.
     *
     * @return bool
     *   True when the URL is fetched over the network.
     */
    public function isRemote(): bool
    {
        return Path::looksLikeUrl($this->url);
    }

    /**
     * The URL as it is safe to show.
     *
     * Applied everywhere an upstream reaches a log line, an exception message,
     * or CLI output — unconditionally, because a URL can carry a token even
     * when no `auth` is declared.
     *
     * @return string
     *   The URL with any credential replaced by `***`.
     */
    public function display(): string
    {
        return SourceAuth::redactUrl($this->url);
    }

    /**
     * Every header this request sends, credential included.
     *
     * @return array<string, string>
     *   Header name to value.
     */
    public function requestHeaders(): array
    {
        return $this->auth instanceof \Kanopi\Firewall\Source\SourceAuth ? $this->headers + $this->auth->headers() : $this->headers;
    }

    /**
     * The URL actually requested, with query-parameter auth applied.
     *
     * @return string
     *   The request URL. Never log this — use display().
     */
    public function requestUrl(): string
    {
        return $this->auth instanceof \Kanopi\Firewall\Source\SourceAuth ? $this->auth->applyToUrl($this->url) : $this->url;
    }

    /**
     * The parts of this upstream that can change what comes back.
     *
     * Feeds the source fingerprint. The credential is excluded: rotating a
     * token does not change the list it fetches, and re-decoding every source
     * on a key rotation would be pure waste.
     *
     * @return array<int, mixed>
     *   Values contributing to cache identity.
     */
    public function fingerprintParts(): array
    {
        return [$this->url, $this->method, $this->headers, $this->body];
    }

    /**
     * Read and normalise extra request headers.
     *
     * @param array<array-key, mixed> $declaration
     *   The upstream map.
     * @param string $sourceName
     *   Source name, for error messages.
     *
     * @return array<string, string>
     *   Header name to value.
     *
     * @throws SourceException
     *   When the declaration is not a map of scalars.
     */
    private static function headers(array $declaration, string $sourceName): array
    {
        $declared = $declaration['headers'] ?? null;

        if ($declared === null) {
            return [];
        }

        if (!is_array($declared)) {
            throw new SourceException(sprintf(
                'Source "%s": upstream.headers must be a map of header names to values, %s given.',
                $sourceName,
                gettype($declared)
            ));
        }

        $headers = [];

        foreach ($declared as $header => $value) {
            if (!is_string($header) || trim($header) === '') {
                throw new SourceException(sprintf(
                    'Source "%s": upstream.headers keys must be non-empty header names.',
                    $sourceName
                ));
            }

            if (is_array($value) || is_object($value)) {
                throw new SourceException(sprintf(
                    'Source "%s": upstream header "%s" must be a scalar value.',
                    $sourceName,
                    $header
                ));
            }

            // A newline in a header value would start a header of the
            // upstream author's choosing, or a request body.
            $headers[trim($header)] = str_replace(["\r", "\n"], '', (string) $value);
        }

        return $headers;
    }
}
