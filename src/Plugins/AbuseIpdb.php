<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Symfony\Component\HttpFoundation\Request;

/**
 * Check the client IP's reputation against AbuseIPDB.
 *
 * AbuseIPDB scores an address 0-100 by how confidently it has been reported
 * for abuse. This plugin matches when that confidence reaches `threshold`,
 * so with `response: block` a known-bad address is rejected before the
 * expensive rule-matching plugins ever run.
 *
 * Three behaviours are worth knowing before enabling it.
 *
 * **It fails open.** A lookup that times out, is refused, or runs into a spent
 * quota reports no match, logs at warning level, and lets evaluation continue.
 * Reputation is corroborating evidence, not the last line of defence — a
 * third-party outage must not become an outage here. Nothing in this plugin
 * blocks a request it could not get an answer for.
 *
 * **It is cached, because the quota is small.** The free tier allows 1,000
 * checks a day, which a modest site would burn through before lunch if every
 * request meant a call. Verdicts are cached per address for `cache_ttl`
 * (24h by default), so cost is one call per unique visitor per day; repeat
 * visitors and crawlers are free. Failures are cached too, for a much shorter
 * `error_cache_ttl` — without that, a provider outage would make every request
 * pay the full `timeout`, which is a site slowdown dressed up as failing open.
 *
 * **It never calls the API for an address that cannot be in the database.**
 * Private and reserved ranges are skipped, so a local or intranet deployment
 * spends no quota at all.
 *
 * Addresses AbuseIPDB marks as whitelisted — search-engine crawlers and
 * similar known-good infrastructure — never match, whatever their score.
 *
 * Requires an API key from https://www.abuseipdb.com/account/api. With no
 * `api_key` the plugin is a no-op that matches nothing, so adding it to a
 * config before the key is provisioned is safe.
 */
class AbuseIpdb extends AbstractPluginBase
{
    /**
     * AbuseIPDB v2 single-address check endpoint.
     */
    protected const ENDPOINT = 'https://api.abuseipdb.com/api/v2/check';

    /**
     * Confidence score at or above which the plugin matches.
     *
     * AbuseIPDB's own guidance treats 75 as the point where a report set is
     * strong enough to act on. Below roughly 25 the score mostly reflects a
     * handful of reports and is not worth blocking over.
     */
    protected const DEFAULT_THRESHOLD = 75;

    /**
     * How long a successful verdict stays cached, in seconds.
     */
    protected const DEFAULT_CACHE_TTL = 86400;

    /**
     * How long a failed lookup stays cached, in seconds.
     *
     * Deliberately short: long enough to stop an outage costing every request
     * a full timeout, short enough that recovery is picked up promptly.
     */
    protected const DEFAULT_ERROR_CACHE_TTL = 300;

    /**
     * Seconds to wait on the API before giving up.
     *
     * This sits in the request path, so the ceiling on added latency matters
     * more than getting an answer.
     */
    protected const DEFAULT_TIMEOUT = 2.0;

    /**
     * How far back AbuseIPDB should consider reports, in days.
     */
    protected const DEFAULT_MAX_AGE_IN_DAYS = 30;

    /**
     * {@inheritdoc}
     */
    protected function defaultName(): string
    {
        return 'AbuseIPDB';
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return 'Check the client IP address reputation against AbuseIPDB and match when its abuse confidence reaches the configured threshold';
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        $apiKey = $this->apiKey();
        if ($apiKey === null) {
            // Not configured — the plugin is inert. Returning TRUE here would
            // block every request for someone who added the plugin before
            // provisioning a key.
            $this->getLogger()->debug('AbuseIPDB evaluation skipped - no api_key configured', $this->getContext($request));
            return false;
        }

        $ip = $request->getClientIp();
        if ($ip === null || $ip === '') {
            $this->getLogger()->debug('AbuseIPDB evaluation skipped - no client IP on the request', $this->getContext($request));
            return false;
        }

        if (!$this->isPubliclyRoutable($ip)) {
            // Private and reserved space is never in the database. Calling for
            // it would spend quota to be told nothing.
            $this->getLogger()->debug('AbuseIPDB evaluation skipped - client IP is not publicly routable', $this->getContext($request, [
                'ip' => $ip,
            ]));
            return false;
        }

        $report = $this->lookup($ip, $apiKey, $request);
        if ($report === null) {
            // Already logged at warning level by the lookup. Fail open.
            return false;
        }

        if ($report['is_whitelisted']) {
            $this->getLogger()->debug('AbuseIPDB reports the client IP as whitelisted - not matching', $this->getContext($request, [
                'ip'                     => $ip,
                'abuse_confidence_score' => $report['abuse_confidence_score'],
            ]));
            return false;
        }

        $threshold = $this->threshold();

        // TRUE means "this plugin matched", not "allow the request" — the
        // PluginManager applies the entry's `response:` when we return TRUE.
        // See PluginInterface::evaluate().
        if ($report['abuse_confidence_score'] >= $threshold) {
            $this->getLogger()->info('AbuseIPDB matched a reported IP address', $this->getContext($request, [
                'ip'                     => $ip,
                'abuse_confidence_score' => $report['abuse_confidence_score'],
                'threshold'              => $threshold,
                'total_reports'          => $report['total_reports'],
                'country_code'           => $report['country_code'],
            ]));
            return true;
        }

        $this->getLogger()->debug('AbuseIPDB score is under the threshold', $this->getContext($request, [
            'ip'                     => $ip,
            'abuse_confidence_score' => $report['abuse_confidence_score'],
            'threshold'              => $threshold,
        ]));

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function getStatusCode(?Request $request = null): int
    {
        return (int) ($this->config['block_status'] ?? 403);
    }

    /**
     * {@inheritdoc}
     */
    public function getExpirationTime(?Request $request = null): int
    {
        return (int) ($this->config['block_duration'] ?? 3600);
    }

    /**
     * Resolve an address to a reputation report, cache first.
     *
     * @param string $ip
     *   The address to check. Assumed publicly routable.
     * @param string $apiKey
     *   AbuseIPDB API key.
     * @param Request $request
     *   The request under evaluation, for log context.
     *
     * @return array{abuse_confidence_score: int, is_whitelisted: bool, total_reports: int, country_code: string}|null
     *   The report, or NULL when no answer could be obtained — in which case a
     *   warning has already been logged and the caller must fail open.
     */
    protected function lookup(string $ip, string $apiKey, Request $request): ?array
    {
        $cached = $this->readCache($ip);

        if ($cached !== null && isset($cached['error'])) {
            // A recent failure, still inside error_cache_ttl. Report it at
            // debug rather than warning — the warning was written when the
            // lookup actually failed, and repeating it once per request for
            // the whole window would bury everything else.
            $this->getLogger()->debug('AbuseIPDB lookup skipped - a recent lookup failed and is still cached', $this->getContext($request, [
                'ip'    => $ip,
                'error' => $cached['error'],
            ]));
            return null;
        }

        if ($cached !== null) {
            // Anything still cached and not a failure is a usable verdict.
            return $cached['report'];
        }

        $result = $this->fetch($ip, $apiKey);

        if (isset($result['error'])) {
            $this->getLogger()->warning('AbuseIPDB lookup failed - allowing the request through', $this->getContext($request, [
                'ip'          => $ip,
                'error'       => $result['error'],
                'http_status' => $result['http_status'],
                'hint'        => 'Reputation is advisory here: the request proceeds to the next plugin. Check the API key and the daily quota.',
            ]));
            $this->writeCache($ip, ['error' => $result['error'], 'http_status' => $result['http_status']]);
            return null;
        }

        $this->writeCache($ip, ['report' => $result['report']]);

        return $result['report'];
    }

    /**
     * Call AbuseIPDB for a single address.
     *
     * Uses the stream wrapper rather than an HTTP client library, matching the
     * one other place this package fetches over the network
     * (`Config::fileGetContents()`), and keeping a security library's
     * dependency surface unchanged. `ignore_errors` is on so a 4xx body can be
     * read for its status rather than surfacing as an opaque failure.
     *
     * @param string $ip
     *   The address to check.
     * @param string $apiKey
     *   AbuseIPDB API key.
     *
     * @return array{report: array{abuse_confidence_score: int, is_whitelisted: bool, total_reports: int, country_code: string}, error?: null, http_status?: null}|array{error: string, http_status: int|null, report?: null}
     *   Either a report or a described failure.
     */
    protected function fetch(string $ip, string $apiKey): array
    {
        $url = self::ENDPOINT . '?' . http_build_query([
            'ipAddress'     => $ip,
            'maxAgeInDays'  => $this->maxAgeInDays(),
        ]);

        $context = stream_context_create([
            'http' => [
                'method'        => 'GET',
                'timeout'       => $this->timeout(),
                'ignore_errors' => true,
                'header'        => [
                    'Key: ' . $apiKey,
                    'Accept: application/json',
                ],
            ],
        ]);

        $handle = @fopen($url, 'r', false, $context);
        if ($handle === false) {
            return ['error' => 'could not reach the AbuseIPDB API', 'http_status' => null];
        }

        $metadata = stream_get_meta_data($handle);
        $body = stream_get_contents($handle);
        fclose($handle);

        /** @var array<int, string> $headers */
        $headers = is_array($metadata['wrapper_data'] ?? null) ? $metadata['wrapper_data'] : [];
        $status = $this->statusFromHeaders($headers);

        if ($status !== 200) {
            return ['error' => $this->describeStatus($status), 'http_status' => $status];
        }

        if ($body === false || $body === '') {
            return ['error' => 'the AbuseIPDB API returned an empty body', 'http_status' => $status];
        }

        $decoded = json_decode($body, true);
        if (!is_array($decoded) || !isset($decoded['data']) || !is_array($decoded['data'])) {
            return ['error' => 'the AbuseIPDB API returned a body that is not a check result', 'http_status' => $status];
        }

        $data = $decoded['data'];

        return [
            'report' => [
                'abuse_confidence_score' => (int) ($data['abuseConfidenceScore'] ?? 0),
                'is_whitelisted'         => (bool) ($data['isWhitelisted'] ?? false),
                'total_reports'          => (int) ($data['totalReports'] ?? 0),
                'country_code'           => (string) ($data['countryCode'] ?? ''),
            ],
        ];
    }

    /**
     * Read a cached entry for an address, if one is present and still fresh.
     *
     * Successful verdicts and failures have different lifetimes, so which TTL
     * applies depends on what was stored.
     *
     * @param string $ip
     *   The address to read.
     *
     * @return array{report: array{abuse_confidence_score: int, is_whitelisted: bool, total_reports: int, country_code: string}}|array{error: string, http_status: int|null}|null
     *   The entry, or NULL on a miss, an expired entry, or an unreadable one.
     */
    protected function readCache(string $ip): ?array
    {
        $path = $this->cachePath($ip);
        if ($path === null || !is_file($path)) {
            return null;
        }

        $contents = @file_get_contents($path);
        if ($contents === false) {
            return null;
        }

        $entry = json_decode($contents, true);
        if (!is_array($entry)) {
            // Truncated or hand-edited. Treat it as a miss and let the next
            // successful fetch overwrite it.
            return null;
        }

        $age = time() - (int) @filemtime($path);

        if (isset($entry['error'])) {
            if ($age >= $this->errorCacheTtl()) {
                return null;
            }

            return [
                'error'       => (string) $entry['error'],
                'http_status' => isset($entry['http_status']) ? (int) $entry['http_status'] : null,
            ];
        }

        if ($age >= $this->cacheTtl() || !isset($entry['report']) || !is_array($entry['report'])) {
            return null;
        }

        $report = $entry['report'];

        return [
            'report' => [
                'abuse_confidence_score' => (int) ($report['abuse_confidence_score'] ?? 0),
                'is_whitelisted'         => (bool) ($report['is_whitelisted'] ?? false),
                'total_reports'          => (int) ($report['total_reports'] ?? 0),
                'country_code'           => (string) ($report['country_code'] ?? ''),
            ],
        ];
    }

    /**
     * Store an entry for an address.
     *
     * A cache that cannot be written is not fatal — it costs quota, not
     * correctness — so this reports the problem and returns.
     *
     * @param string $ip
     *   The address the entry describes.
     * @param array<string, mixed> $entry
     *   Either `['report' => [...]]` or `['error' => string, 'http_status' => ?int]`.
     */
    protected function writeCache(string $ip, array $entry): void
    {
        $path = $this->cachePath($ip);
        if ($path === null) {
            return;
        }

        $encoded = json_encode($entry);
        if ($encoded === false) {
            return;
        }

        if (@file_put_contents($path, $encoded, LOCK_EX) === false) {
            $this->getLogger()->warning('AbuseIPDB could not write its cache - every request will spend quota', [
                'plugin' => $this->getName(),
                'path'   => $path,
                'hint'   => 'Point cache_dir at a writable directory. The free tier allows 1,000 checks a day.',
            ]);
        }
    }

    /**
     * Absolute path of the cache entry for an address.
     *
     * The address is hashed rather than used directly: it keeps client IPs out
     * of directory listings, and guarantees a filesystem-safe name for IPv6.
     *
     * @param string $ip
     *   The address to derive a path for.
     *
     * @return string|null
     *   The path, or NULL when the cache directory could not be created.
     */
    protected function cachePath(string $ip): ?string
    {
        $directory = rtrim($this->cacheDir(), '/');

        if (!is_dir($directory) && !@mkdir($directory, 0775, true) && !is_dir($directory)) {
            $this->getLogger()->warning('AbuseIPDB cache directory could not be created - every request will spend quota', [
                'plugin' => $this->getName(),
                'path'   => $directory,
            ]);
            return null;
        }

        return $directory . '/abuseipdb-' . sha1($ip) . '.json';
    }

    /**
     * Whether an address is one AbuseIPDB could plausibly have a report for.
     *
     * @param string $ip
     *   The address to test.
     */
    protected function isPubliclyRoutable(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        ) !== false;
    }

    /**
     * Turn an HTTP status into something an operator can act on.
     *
     * @param int|null $status
     *   The status code, or NULL when none could be parsed.
     */
    protected function describeStatus(?int $status): string
    {
        return match ($status) {
            401 => 'AbuseIPDB rejected the API key',
            422 => 'AbuseIPDB rejected the address as invalid',
            429 => 'AbuseIPDB daily quota is exhausted',
            null => 'the AbuseIPDB API returned no parseable status',
            default => 'the AbuseIPDB API returned HTTP ' . $status,
        };
    }

    /**
     * Extract the status code from stream wrapper headers.
     *
     * @param array<int, string> $headers
     *   Raw response header lines, status line first.
     *
     * @return int|null
     *   The code, or NULL when the status line could not be parsed.
     */
    protected function statusFromHeaders(array $headers): ?int
    {
        foreach ($headers as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $matches) === 1) {
                return (int) $matches[1];
            }
        }

        return null;
    }

    /**
     * The configured API key, or NULL when the plugin is unconfigured.
     */
    protected function apiKey(): ?string
    {
        $key = $this->config['api_key'] ?? null;

        if (!is_string($key) || trim($key) === '') {
            return null;
        }

        return trim($key);
    }

    /**
     * Confidence score at or above which the plugin matches.
     */
    protected function threshold(): int
    {
        return $this->intConfig('threshold', self::DEFAULT_THRESHOLD);
    }

    /**
     * Lifetime of a cached verdict, in seconds.
     */
    protected function cacheTtl(): int
    {
        return $this->intConfig('cache_ttl', self::DEFAULT_CACHE_TTL);
    }

    /**
     * Lifetime of a cached failure, in seconds.
     */
    protected function errorCacheTtl(): int
    {
        return $this->intConfig('error_cache_ttl', self::DEFAULT_ERROR_CACHE_TTL);
    }

    /**
     * How far back AbuseIPDB should consider reports, in days.
     */
    protected function maxAgeInDays(): int
    {
        return $this->intConfig('max_age_in_days', self::DEFAULT_MAX_AGE_IN_DAYS);
    }

    /**
     * Seconds to wait on the API before giving up.
     */
    protected function timeout(): float
    {
        $configured = $this->config['timeout'] ?? null;

        if ($configured === null) {
            return self::DEFAULT_TIMEOUT;
        }

        if (!is_numeric($configured)) {
            $this->getLogger()->warning('AbuseIPDB timeout is not a number - using the default', [
                'plugin'  => $this->getName(),
                'given'   => get_debug_type($configured),
                'default' => self::DEFAULT_TIMEOUT,
            ]);
            return self::DEFAULT_TIMEOUT;
        }

        return (float) $configured;
    }

    /**
     * Directory holding cached verdicts.
     *
     * Follows `Config`'s convention so a deployment that already sets
     * KANOPI_FIREWALL_CACHE_DIR does not have to say it twice, with an
     * explicit `cache_dir` winning when present.
     */
    protected function cacheDir(): string
    {
        $configured = $this->config['cache_dir'] ?? null;

        if (is_string($configured) && trim($configured) !== '') {
            return trim($configured);
        }

        if (defined('KANOPI_FIREWALL_CACHE_DIR')) {
            return (string) constant('KANOPI_FIREWALL_CACHE_DIR');
        }

        return sys_get_temp_dir() . '/kanopi-firewall-abuseipdb';
    }

    /**
     * Read an integer config value, warning rather than silently coercing.
     *
     * Deliberately forgiving: a typo in a YAML file should degrade this plugin
     * to its default, not take a site down.
     *
     * @param string $key
     *   Config key to read.
     * @param int $default
     *   Value to use when the key is absent or unusable.
     */
    protected function intConfig(string $key, int $default): int
    {
        $configured = $this->config[$key] ?? null;

        if ($configured === null) {
            return $default;
        }

        if (!is_numeric($configured)) {
            $this->getLogger()->warning('AbuseIPDB ' . $key . ' is not a number - using the default', [
                'plugin'  => $this->getName(),
                'given'   => get_debug_type($configured),
                'default' => $default,
            ]);
            return $default;
        }

        return (int) $configured;
    }
}
