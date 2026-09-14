<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Reputation;

use Kanopi\Firewall\Exception\ReputationUnavailableException;
use Kanopi\Firewall\Logging\LoggingTrait;

/**
 * AbuseIPDB, and the reference for what a provider looks like (#204).
 *
 * AbuseIPDB scores an address 0-100 by how confidently it has been reported for
 * abuse. Its own guidance treats 75 as the point where a report set is strong
 * enough to act on; below roughly 25 a score mostly reflects a handful of
 * reports and is not worth blocking over.
 *
 * This was the whole of `Plugins\AbuseIpdb` until the caching, the fail-open
 * posture and the threshold moved up into `Plugins\Reputation`, where every
 * provider gets them. What is left here is the three things that are actually
 * about AbuseIPDB: the call, the shape of the response, and what its status
 * codes mean.
 *
 * **It never calls the API for an address that cannot be in the database.**
 * Private and reserved ranges are skipped, so a local or intranet deployment
 * spends no quota at all.
 *
 * **Its default TTL is a day** because the free tier allows 1,000 checks a day,
 * which a modest site would burn through before lunch if every request meant a
 * call.
 *
 * Requires an API key from https://www.abuseipdb.com/account/api. With no
 * `api_key` the provider reports itself unconfigured and the rule matches
 * nothing, so adding it to a config before the key is provisioned is safe.
 */
class AbuseIpdbProvider implements ReputationProviderInterface
{
    use LoggingTrait;

    /**
     * AbuseIPDB v2 single-address check endpoint.
     */
    protected const ENDPOINT = 'https://api.abuseipdb.com/api/v2/check';

    /**
     * How long a successful verdict stays cached, in seconds.
     */
    protected const DEFAULT_CACHE_TTL = 86400;

    /**
     * How long a failed lookup stays cached, in seconds.
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
     * @param array<int|string, mixed> $config
     *   The rule's `config:` block, which is where `api_key` and the rest of
     *   this provider's settings live.
     */
    public function __construct(protected array $config = [])
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'AbuseIPDB';
    }

    /**
     * {@inheritdoc}
     */
    public function getSlug(): string
    {
        return 'abuseipdb';
    }

    /**
     * {@inheritdoc}
     */
    public function getConfigurationProblem(): ?string
    {
        return $this->apiKey() === null ? 'no api_key configured' : null;
    }

    /**
     * {@inheritdoc}
     *
     * Private and reserved space is never in the database. Calling for it
     * would spend quota to be told nothing.
     */
    public function knowsAbout(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        ) !== false;
    }

    /**
     * {@inheritdoc}
     */
    public function getDefaultCacheTtl(): int
    {
        return self::DEFAULT_CACHE_TTL;
    }

    /**
     * {@inheritdoc}
     */
    public function getDefaultErrorCacheTtl(): int
    {
        return self::DEFAULT_ERROR_CACHE_TTL;
    }

    /**
     * {@inheritdoc}
     *
     * Uses the stream wrapper rather than an HTTP client library, matching the
     * one other place this package fetches over the network
     * (`Config::fileGetContents()`), and keeping a security library's
     * dependency surface unchanged. `ignore_errors` is on so a 4xx body can be
     * read for its status rather than surfacing as an opaque failure.
     */
    public function check(string $ip): ReputationVerdict
    {
        $apiKey = $this->apiKey();

        if ($apiKey === null) {
            // Unreachable through the plugin, which asks
            // getConfigurationProblem() first. Stated rather than assumed,
            // because a provider is a public API and this is the one call that
            // would otherwise send `Key: ` and spend a round trip finding out.
            throw new ReputationUnavailableException('AbuseIPDB has no api_key configured');
        }

        $url = self::ENDPOINT . '?' . http_build_query([
            'ipAddress' => $ip,
            'maxAgeInDays' => $this->maxAgeInDays(),
        ]);

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => $this->timeout(),
                'ignore_errors' => true,
                'header' => [
                    'Key: ' . $apiKey,
                    'Accept: application/json',
                ],
            ],
        ]);

        $handle = @fopen($url, 'r', false, $context);

        if ($handle === false) {
            throw new ReputationUnavailableException('could not reach the AbuseIPDB API');
        }

        $metadata = stream_get_meta_data($handle);
        $body = stream_get_contents($handle);
        fclose($handle);

        /** @var array<int, string> $headers */
        $headers = is_array($metadata['wrapper_data'] ?? null) ? $metadata['wrapper_data'] : [];
        $status = HttpStatus::fromHeaders($headers);

        if ($status !== 200) {
            throw new ReputationUnavailableException($this->describeStatus($status), $status);
        }

        if ($body === false || $body === '') {
            throw new ReputationUnavailableException('the AbuseIPDB API returned an empty body', $status);
        }

        $decoded = json_decode($body, true);

        if (!is_array($decoded) || !isset($decoded['data']) || !is_array($decoded['data'])) {
            throw new ReputationUnavailableException(
                'the AbuseIPDB API returned a body that is not a check result',
                $status
            );
        }

        $data = $decoded['data'];

        return new ReputationVerdict(
            (float) (int) ($data['abuseConfidenceScore'] ?? 0),
            (bool) ($data['isWhitelisted'] ?? false),
            [
                'abuse_confidence_score' => (int) ($data['abuseConfidenceScore'] ?? 0),
                'total_reports' => (int) ($data['totalReports'] ?? 0),
                'country_code' => (string) ($data['countryCode'] ?? ''),
            ]
        );
    }

    /**
     * Turn an HTTP status into something an operator can act on.
     *
     * @param int|null $status
     *   The status code, or NULL when none could be parsed.
     *
     * @return string
     *   What to write in the log line.
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
     * The configured API key, or NULL when the provider is unconfigured.
     *
     * @return string|null
     *   The key, trimmed.
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
     * How far back AbuseIPDB should consider reports, in days.
     *
     * @return int
     *   Days.
     */
    protected function maxAgeInDays(): int
    {
        return ProviderConfig::int($this->config, 'max_age_in_days', self::DEFAULT_MAX_AGE_IN_DAYS, $this->getName());
    }

    /**
     * Seconds to wait on the API before giving up.
     *
     * @return float
     *   Seconds.
     */
    protected function timeout(): float
    {
        return ProviderConfig::float($this->config, 'timeout', self::DEFAULT_TIMEOUT, $this->getName());
    }
}
