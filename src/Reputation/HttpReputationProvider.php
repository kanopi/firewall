<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Reputation;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\ReputationUnavailableException;
use Kanopi\Firewall\Source\SourceAuth;
use Kanopi\Firewall\Utility\DotPath;

/**
 * Any JSON endpoint that scores an address, without writing PHP (#204).
 *
 * ```yaml
 * config:
 *   provider: http
 *   url: "https://reputation.example.com/v1/score?ip={ip}"
 *   auth:
 *     type: bearer
 *     token: "%env(REPUTATION_TOKEN)%"
 *   score_path: data.score
 *   trusted_path: data.allowlisted
 *   threshold: 75
 * ```
 *
 * ## It borrows the vocabulary rather than inventing one
 *
 * `auth:` is `SourceAuth` -- the same `bearer`, `basic`, `header` and `query`
 * block that rule sources have taken since #161, including the redaction that
 * keeps a token out of a log line. `score_path` is `DotPath`, the same syntax a
 * source's `select:` uses. Somebody who has configured a rule source has
 * already learned both, and neither had a second implementation written for it.
 *
 * ## The URL has to name the address
 *
 * A URL without `{ip}` returns the same body for every visitor, which is a
 * reputation check that cannot fail and cannot help. It is refused at
 * construction rather than discovered from a log line saying every address
 * scores 4.
 *
 * ## What it does about scores it cannot find
 *
 * A response whose `score_path` resolves to nothing is a failure, not a zero.
 * An endpoint that changed its shape, or that returns `{"error": ...}` with a
 * 200, would otherwise read as "every address is clean" -- protection silently
 * switched off, with a healthy-looking service behind it.
 */
class HttpReputationProvider implements ReputationProviderInterface
{
    /**
     * How long a verdict stays cached, in seconds.
     *
     * An hour rather than AbuseIPDB's day: a service somebody runs themselves
     * is usually free to call and more likely to be updating its own data.
     */
    protected const DEFAULT_CACHE_TTL = 3600;

    /**
     * How long a failed lookup stays cached, in seconds.
     */
    protected const DEFAULT_ERROR_CACHE_TTL = 300;

    /**
     * Seconds to wait on the endpoint before giving up.
     */
    protected const DEFAULT_TIMEOUT = 2.0;

    /**
     * Credentials, when the endpoint is not public.
     */
    protected ?SourceAuth $auth = null;

    /**
     * @param array<int|string, mixed> $config
     *   The rule's `config:` block.
     *
     * @throws ConfigurationException
     *   When there is no usable URL, no `score_path`, or an `auth:` block that
     *   cannot be read. All three are startup failures rather than runtime
     *   ones: a reputation rule that cannot call anything is not a rule, and
     *   discovering that from a warning per request is how it goes unnoticed.
     */
    public function __construct(protected array $config = [])
    {
        $url = $this->url();

        if ($url === '') {
            throw new ConfigurationException(
                'A reputation rule using the `http` provider needs a `url`, containing `{ip}` where the '
                . 'client address goes: `url: "https://example.com/score?ip={ip}"`.'
            );
        }

        if (!str_contains($url, '{ip}')) {
            throw new ConfigurationException(sprintf(
                'The reputation `url` does not contain `{ip}`, so it would return the same answer for '
                . 'every visitor: %s',
                SourceAuth::redactUrl($url)
            ));
        }

        if ($this->scorePath() === '') {
            throw new ConfigurationException(
                'A reputation rule using the `http` provider needs a `score_path` saying where the score '
                . 'is in the response, in the dot syntax a source `select:` uses: `score_path: data.score`.'
            );
        }

        if (isset($this->config['auth'])) {
            if (!is_array($this->config['auth'])) {
                throw new ConfigurationException(sprintf(
                    'The reputation `auth` must be a map with a `type`; got %s.',
                    get_debug_type($this->config['auth'])
                ));
            }

            // SourceException, rethrown as the configuration failure it is
            // here -- a rule source degrades when its credentials are wrong
            // because it has a last known good copy to fall back on, and a
            // reputation rule has nothing.
            try {
                $this->auth = SourceAuth::fromArray($this->config['auth'], $this->getName());
            } catch (\Throwable $throwable) {
                throw new ConfigurationException($throwable->getMessage(), 0, $throwable);
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        $name = $this->config['provider_name'] ?? null;

        return is_string($name) && trim($name) !== '' ? trim($name) : 'Reputation service';
    }

    /**
     * {@inheritdoc}
     *
     * Derived from the endpoint's host, so two services configured on one site
     * do not read each other's cached verdicts -- their scores are on different
     * scales and mean different things.
     */
    public function getSlug(): string
    {
        $host = (string) (parse_url($this->url(), PHP_URL_HOST) ?: 'endpoint');

        return 'http-' . preg_replace('/[^a-z0-9]+/', '-', strtolower($host));
    }

    /**
     * {@inheritdoc}
     *
     * Always ready: everything it needs is checked at construction, where
     * getting it wrong is a startup failure rather than a silent no-op.
     */
    public function getConfigurationProblem(): ?string
    {
        return null;
    }

    /**
     * {@inheritdoc}
     *
     * Public addresses only by default, as a third-party service would want.
     * `public_only: false` is for a service on your own network, which may be
     * the only thing that knows anything about `10.0.0.4`.
     */
    public function knowsAbout(string $ip): bool
    {
        if (($this->config['public_only'] ?? true) === false) {
            return filter_var($ip, FILTER_VALIDATE_IP) !== false;
        }

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
     */
    public function check(string $ip): ReputationVerdict
    {
        $url = str_replace('{ip}', rawurlencode($ip), $this->url());

        if ($this->auth instanceof SourceAuth) {
            $url = $this->auth->applyToUrl($url);
        }

        $headers = ['Accept: application/json'];

        foreach ($this->auth instanceof SourceAuth ? $this->auth->headers() : [] as $name => $value) {
            $headers[] = $name . ': ' . $value;
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => ProviderConfig::float($this->config, 'timeout', self::DEFAULT_TIMEOUT, $this->getName()),
                'ignore_errors' => true,
                'header' => $headers,
            ],
        ]);

        $handle = @fopen($url, 'r', false, $context);

        if ($handle === false) {
            // Redacted, because a `query` credential is in this URL and this
            // message reaches a log line.
            throw new ReputationUnavailableException(sprintf(
                'could not reach %s',
                SourceAuth::redactUrl($this->url())
            ));
        }

        $metadata = stream_get_meta_data($handle);
        $body = stream_get_contents($handle);
        fclose($handle);

        /** @var array<int, string> $headerLines */
        $headerLines = is_array($metadata['wrapper_data'] ?? null) ? $metadata['wrapper_data'] : [];
        $status = HttpStatus::fromHeaders($headerLines);

        if ($status !== 200) {
            throw new ReputationUnavailableException($this->describeStatus($status), $status);
        }

        if ($body === false || $body === '') {
            throw new ReputationUnavailableException('the reputation service returned an empty body', $status);
        }

        $decoded = json_decode($body, true);

        if (!is_array($decoded)) {
            throw new ReputationUnavailableException('the reputation service returned a body that is not JSON', $status);
        }

        $score = DotPath::first($decoded, $this->scorePath());

        if (!is_numeric($score)) {
            // Not a zero. An endpoint that changed shape would otherwise read
            // as "every address is clean", which is protection switched off
            // with a healthy service behind it.
            throw new ReputationUnavailableException(sprintf(
                'the reputation service returned no score at `%s`',
                $this->scorePath()
            ), $status);
        }

        return new ReputationVerdict((float) $score, $this->trusted($decoded), ['score' => (float) $score]);
    }

    /**
     * Whether the response vouches for the address.
     *
     * @param array<array-key, mixed> $decoded
     *   The decoded response body.
     *
     * @return bool
     *   TRUE when `trusted_path` is configured and resolves to something true.
     *   A configured path that resolves to nothing is FALSE rather than a
     *   failure: "this response does not say the address is trusted" is a
     *   complete answer, where a missing score is not.
     */
    protected function trusted(array $decoded): bool
    {
        $path = $this->config['trusted_path'] ?? null;

        if (!is_string($path) || trim($path) === '') {
            return false;
        }

        $value = DotPath::first($decoded, trim($path));

        // Strings, because JSON written by hand says "true" and "yes" as often
        // as it says true, and reading either as FALSE would quietly stop an
        // allow list working.
        if (is_string($value)) {
            return in_array(strtolower(trim($value)), ['1', 'true', 'yes'], true);
        }

        return (bool) $value;
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
            401, 403 => 'the reputation service rejected the credentials',
            404 => 'the reputation service does not know that endpoint',
            429 => 'the reputation service is rate limiting this firewall',
            null => 'the reputation service returned no parseable status',
            default => 'the reputation service returned HTTP ' . $status,
        };
    }

    /**
     * The configured endpoint.
     *
     * @return string
     *   The URL as written, or an empty string when there is none.
     */
    protected function url(): string
    {
        $url = $this->config['url'] ?? null;

        return is_string($url) ? trim($url) : '';
    }

    /**
     * Where the score is in the response.
     *
     * @return string
     *   A dot path, or an empty string when there is none.
     */
    protected function scorePath(): string
    {
        $path = $this->config['score_path'] ?? null;

        return is_string($path) ? trim($path) : '';
    }
}
