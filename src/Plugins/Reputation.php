<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Exception\ReputationUnavailableException;
use Kanopi\Firewall\Reputation\ReputationProviderFactory;
use Kanopi\Firewall\Reputation\ReputationProviderInterface;
use Kanopi\Firewall\Reputation\ReputationVerdict;
use Symfony\Component\HttpFoundation\Request;

/**
 * Match when a reputation service scores the client badly enough (#204).
 *
 * ```yaml
 * - plugin: "Kanopi\\Firewall\\Plugins\\Reputation"
 *   response: block
 *   metadata:
 *     name: internal-reputation
 *   config:
 *     provider: http
 *     url: "https://reputation.example.com/v1/score?ip={ip}"
 *     score_path: data.score
 *     threshold: 75
 * ```
 *
 * Everything that is true of every reputation lookup lives here, and everything
 * that is true of one service lives in its
 * `Reputation\ReputationProviderInterface`. `AbuseIpdb` is this plugin with the
 * provider fixed, which is why its configuration did not change when this was
 * extracted out from under it.
 *
 * ## It fails open
 *
 * A lookup that times out, is refused, runs into a spent quota or returns
 * something that is not a verdict reports no match, logs at warning level, and
 * lets evaluation continue. Reputation is corroborating evidence, not the last
 * line of defence -- a third party's outage must not become an outage here.
 *
 * `on_error: last_known_good` is the one alternative, and it does not weaken
 * that: it reuses a verdict this firewall already fetched for that same address
 * and would otherwise have thrown away for being old. Nothing is ever refused
 * on an answer the provider did not give.
 *
 * ## It is cached, because the quota usually is not generous
 *
 * Verdicts are cached per address and per provider for `cache_ttl`, so cost is
 * one call per unique visitor per period; repeat visitors and crawlers are
 * free. Failures are cached too, for a much shorter `error_cache_ttl` --
 * without that, an outage would make every request pay the full timeout, which
 * is a site slowdown dressed up as failing open.
 *
 * The cache is per provider *slug*, so two services scoring the same address
 * never read each other's answers. Their scales mean different things.
 *
 * ## Trusted beats the score
 *
 * A provider that vouches for an address -- AbuseIPDB's whitelist, a service
 * that knows its customer's monitoring -- never matches, whatever the score.
 */
class Reputation extends AbstractPluginBase
{
    /**
     * Score at or above which the plugin matches.
     *
     * AbuseIPDB's own guidance treats 75 as the point where a report set is
     * strong enough to act on, and providers scoring 0-100 are the common case.
     */
    protected const DEFAULT_THRESHOLD = 75.0;

    /**
     * What to do when the provider cannot answer.
     *
     * Reusing two of the three values a rule source's `on_error` takes (#161),
     * with the same meanings. `abort` is deliberately not among them: a source
     * aborts during bootstrap, where a loud failure is a deploy that stops, but
     * this runs in the request path, where it would be a 500 for a visitor
     * because somebody else's API is slow.
     */
    protected const ERROR_POLICIES = ['fail_open', 'last_known_good'];

    /**
     * The provider, built once per rule instance.
     */
    protected ?ReputationProviderInterface $provider = null;

    /**
     * {@inheritdoc}
     */
    protected function defaultName(): string
    {
        return 'Reputation';
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return 'Check the client IP address against a reputation service and match when its score reaches the configured threshold';
    }

    /**
     * The provider this rule asks, when its `config.provider` names none.
     *
     * @return string
     *   A built-in short name.
     */
    protected function defaultProvider(): string
    {
        return 'http';
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        $provider = $this->provider();
        $problem = $provider->getConfigurationProblem();

        if ($problem !== null) {
            // Not configured -- the rule is inert. Matching here would block
            // every request for somebody who added the rule before
            // provisioning a credential.
            $this->getLogger()->debug(
                sprintf('%s evaluation skipped - %s', $provider->getName(), $problem),
                $this->getContext($request)
            );

            return false;
        }

        $ip = $request->getClientIp();

        if ($ip === null || $ip === '') {
            $this->getLogger()->debug(
                sprintf('%s evaluation skipped - no client IP on the request', $provider->getName()),
                $this->getContext($request)
            );

            return false;
        }

        if (!$provider->knowsAbout($ip)) {
            $this->getLogger()->debug(
                sprintf('%s evaluation skipped - client IP is not one it could have an answer for', $provider->getName()),
                $this->getContext($request, ['ip' => $ip])
            );

            return false;
        }

        $verdict = $this->lookup($ip, $request);

        if (!$verdict instanceof ReputationVerdict) {
            // Already logged at warning level by the lookup. Fail open.
            return false;
        }

        if ($verdict->trusted) {
            $this->getLogger()->debug(
                sprintf('%s reports the client IP as trusted - not matching', $provider->getName()),
                $this->getContext($request, ['ip' => $ip] + $verdict->attributes)
            );

            return false;
        }

        $threshold = $this->threshold();

        // TRUE means "this rule matched", not "allow the request" -- the
        // PluginManager applies the entry's `response:` when we return TRUE.
        // See PluginInterface::evaluate().
        if ($verdict->score >= $threshold) {
            $this->getLogger()->info(
                sprintf('%s matched a reported IP address', $provider->getName()),
                $this->getContext($request, [
                    'ip' => $ip,
                    'score' => $verdict->score,
                    'threshold' => $threshold,
                ] + $verdict->attributes)
            );

            return true;
        }

        $this->getLogger()->debug(
            sprintf('%s score is under the threshold', $provider->getName()),
            $this->getContext($request, [
                'ip' => $ip,
                'score' => $verdict->score,
                'threshold' => $threshold,
            ] + $verdict->attributes)
        );

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
     * The provider this rule asks.
     *
     * Built on first use rather than in the constructor: a provider that
     * refuses to construct -- an `http` one with no `{ip}` in its URL -- then
     * surfaces through the failed-rule report like every other rule that
     * cannot start, instead of during an evaluation.
     *
     * @return ReputationProviderInterface
     *   The provider.
     */
    protected function provider(): ReputationProviderInterface
    {
        if (!$this->provider instanceof ReputationProviderInterface) {
            $configured = $this->config['provider'] ?? null;
            $name = is_string($configured) && trim($configured) !== ''
                ? trim($configured)
                : $this->defaultProvider();

            $this->provider = ReputationProviderFactory::create($name, $this->config);
        }

        return $this->provider;
    }

    /**
     * Resolve an address to a verdict, cache first.
     *
     * @param string $ip
     *   The address to check.
     * @param Request $request
     *   The request under evaluation, for log context.
     *
     * @return ReputationVerdict|null
     *   The verdict, or NULL when no answer could be obtained -- in which case
     *   a warning has already been logged and the caller must fail open.
     */
    protected function lookup(string $ip, Request $request): ?ReputationVerdict
    {
        $provider = $this->provider();
        $error = $this->readError($ip);

        if ($error !== null) {
            // A recent failure, still inside error_cache_ttl. Reported at
            // debug rather than warning -- the warning was written when the
            // lookup actually failed, and repeating it once per request for
            // the whole window would bury everything else.
            $this->getLogger()->debug(
                sprintf('%s lookup skipped - a recent lookup failed and is still cached', $provider->getName()),
                $this->getContext($request, ['ip' => $ip, 'error' => $error])
            );

            return $this->onError($ip, $request);
        }

        $cached = $this->readCache($ip);

        if ($cached instanceof ReputationVerdict) {
            return $cached;
        }

        try {
            $verdict = $provider->check($ip);
        } catch (ReputationUnavailableException $reputationUnavailableException) {
            $this->getLogger()->warning(
                sprintf('%s lookup failed - allowing the request through', $provider->getName()),
                $this->getContext($request, [
                    'ip' => $ip,
                    'error' => $reputationUnavailableException->getMessage(),
                    'http_status' => $reputationUnavailableException->httpStatus,
                    'hint' => 'Reputation is advisory here: the request proceeds to the next rule. '
                        . 'Check the credential and the service.',
                ])
            );

            $this->writeError($ip, $reputationUnavailableException);

            return $this->onError($ip, $request);
        }

        $this->writeCache($ip, ['verdict' => $verdict->toArray()]);

        return $verdict;
    }

    /**
     * What a failed lookup falls back to.
     *
     * @param string $ip
     *   The address that could not be looked up.
     * @param Request $request
     *   The request under evaluation, for log context.
     *
     * @return ReputationVerdict|null
     *   An expired verdict under `on_error: last_known_good`, or NULL to fail
     *   open.
     */
    protected function onError(string $ip, Request $request): ?ReputationVerdict
    {
        if ($this->errorPolicy() !== 'last_known_good') {
            return null;
        }

        $stale = $this->readCache($ip, true);

        if (!$stale instanceof ReputationVerdict) {
            return null;
        }

        // Warning, not debug: the answer being acted on is older than the
        // operator asked for, and that is something they may want to know
        // before reading the block that came out of it.
        $this->getLogger()->warning(
            sprintf('%s is unreachable - using the last known verdict for this address', $this->provider()->getName()),
            $this->getContext($request, [
                'ip' => $ip,
                'score' => $stale->score,
                'age_seconds' => time() - (int) @filemtime((string) $this->cachePath($ip)),
            ])
        );

        return $stale;
    }

    /**
     * Read the cached verdict for an address, if there is a usable one.
     *
     * Verdicts and failures are kept in **separate files**, which is not an
     * implementation detail: a failure written over the verdict it replaced
     * would destroy the only thing `on_error: last_known_good` has to fall back
     * on, at exactly the moment it is needed. Separate files also mean each
     * keeps its own mtime, so the two lifetimes are read from the filesystem
     * rather than from a timestamp this had to remember to write.
     *
     * @param string $ip
     *   The address to read.
     * @param bool $ignoreTtl
     *   Return a verdict however old it is, for `on_error: last_known_good`.
     *
     * @return ReputationVerdict|null
     *   The verdict, or NULL on a miss, an expired entry, or an unreadable one.
     */
    protected function readCache(string $ip, bool $ignoreTtl = false): ?ReputationVerdict
    {
        $path = $this->cachePath($ip);
        $entry = $this->readEntry($path);

        if ($entry === null) {
            return null;
        }

        if (!$ignoreTtl && (time() - (int) @filemtime((string) $path)) >= $this->cacheTtl()) {
            return null;
        }

        return ReputationVerdict::fromArray($entry['verdict'] ?? null) ?? $this->legacyVerdict($entry);
    }

    /**
     * Read the cached failure for an address, if one is still recent.
     *
     * @param string $ip
     *   The address to read.
     *
     * @return string|null
     *   What went wrong, or NULL when there is no failure inside
     *   `error_cache_ttl`.
     */
    protected function readError(string $ip): ?string
    {
        $path = $this->errorPath($ip);
        $entry = $this->readEntry($path);

        if ($entry === null || !isset($entry['error'])) {
            return null;
        }

        if ((time() - (int) @filemtime((string) $path)) >= $this->errorCacheTtl()) {
            return null;
        }

        return (string) $entry['error'];
    }

    /**
     * Decode a cache file, if it is there and says anything.
     *
     * @param string|null $path
     *   The file, or NULL when there is no usable cache directory.
     *
     * @return array<array-key, mixed>|null
     *   The decoded entry, or NULL on a miss or anything unreadable. Forgiving
     *   on purpose: a truncated or hand-edited file counts as a miss, which
     *   costs one lookup, where trusting it costs a wrong verdict.
     */
    protected function readEntry(?string $path): ?array
    {
        if ($path === null || !is_file($path)) {
            return null;
        }

        $contents = @file_get_contents($path);

        if ($contents === false) {
            return null;
        }

        $entry = json_decode($contents, true);

        return is_array($entry) ? $entry : null;
    }

    /**
     * A verdict out of a cache entry an older release wrote.
     *
     * Nothing by default: a shape this version does not recognise is a miss,
     * which costs one lookup. A provider whose entries predate the shared cache
     * overrides this so an upgrade does not spend a day's quota re-asking about
     * addresses it already had answers for.
     *
     * @param array<array-key, mixed> $entry
     *   The decoded cache entry.
     *
     * @return ReputationVerdict|null
     *   The verdict, or NULL when the entry is not one this rule can read.
     */
    protected function legacyVerdict(array $entry): ?ReputationVerdict
    {
        return null;
    }

    /**
     * Remember that a lookup failed, without forgetting what it said last time.
     *
     * Its own file, next to the verdict rather than over it. Without that, the
     * first failure would delete the last known good answer, and the policy
     * that exists to use one would have nothing to use.
     *
     * @param string $ip
     *   The address that could not be looked up.
     * @param ReputationUnavailableException $reputationUnavailableException
     *   What went wrong.
     */
    protected function writeError(string $ip, ReputationUnavailableException $reputationUnavailableException): void
    {
        $this->write($this->errorPath($ip), [
            'error' => $reputationUnavailableException->getMessage(),
            'http_status' => $reputationUnavailableException->httpStatus,
        ]);
    }

    /**
     * Store a verdict for an address.
     *
     * @param string $ip
     *   The address the entry describes.
     * @param array<string, mixed> $entry
     *   `['verdict' => [...]]`.
     */
    protected function writeCache(string $ip, array $entry): void
    {
        $this->write($this->cachePath($ip), $entry);
    }

    /**
     * Write one cache file.
     *
     * A cache that cannot be written is not fatal -- it costs quota, not
     * correctness -- so this reports the problem and returns.
     *
     * @param string|null $path
     *   The file, or NULL when there is no usable cache directory.
     * @param array<string, mixed> $entry
     *   What to store.
     */
    protected function write(?string $path, array $entry): void
    {
        if ($path === null) {
            return;
        }

        $encoded = json_encode($entry);

        if ($encoded === false) {
            return;
        }

        if (@file_put_contents($path, $encoded, LOCK_EX) === false) {
            $this->getLogger()->warning(
                sprintf('%s could not write its cache - every request will spend quota', $this->provider()->getName()),
                [
                    'plugin' => $this->getName(),
                    'path' => $path,
                    'hint' => 'Point cache_dir at a writable directory.',
                ]
            );
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
            $this->getLogger()->warning(
                sprintf('%s cache directory could not be created - every request will spend quota', $this->provider()->getName()),
                [
                    'plugin' => $this->getName(),
                    'path' => $directory,
                ]
            );

            return null;
        }

        return $directory . '/' . $this->provider()->getSlug() . '-' . sha1($ip) . '.json';
    }

    /**
     * Absolute path of the cached failure for an address.
     *
     * @param string $ip
     *   The address to derive a path for.
     *
     * @return string|null
     *   The path, or NULL when the cache directory could not be created.
     */
    protected function errorPath(string $ip): ?string
    {
        $path = $this->cachePath($ip);

        return $path === null ? null : substr($path, 0, -5) . '.error.json';
    }

    /**
     * Directory holding cached verdicts.
     *
     * Follows `Config`'s convention so a deployment that already sets
     * KANOPI_FIREWALL_CACHE_DIR does not have to say it twice, with an
     * explicit `cache_dir` winning when present. The per-provider default
     * keeps an upgrade from orphaning the verdicts an earlier version cached.
     *
     * @return string
     *   The directory.
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

        return sys_get_temp_dir() . '/kanopi-firewall-' . $this->provider()->getSlug();
    }

    /**
     * Score at or above which the rule matches.
     *
     * @return float
     *   The threshold, on the provider's own scale.
     */
    protected function threshold(): float
    {
        return \Kanopi\Firewall\Reputation\ProviderConfig::float(
            $this->config,
            'threshold',
            self::DEFAULT_THRESHOLD,
            $this->provider()->getName()
        );
    }

    /**
     * Lifetime of a cached verdict, in seconds.
     *
     * @return int
     *   Seconds.
     */
    protected function cacheTtl(): int
    {
        return \Kanopi\Firewall\Reputation\ProviderConfig::int(
            $this->config,
            'cache_ttl',
            $this->provider()->getDefaultCacheTtl(),
            $this->provider()->getName()
        );
    }

    /**
     * Lifetime of a cached failure, in seconds.
     *
     * @return int
     *   Seconds.
     */
    protected function errorCacheTtl(): int
    {
        return \Kanopi\Firewall\Reputation\ProviderConfig::int(
            $this->config,
            'error_cache_ttl',
            $this->provider()->getDefaultErrorCacheTtl(),
            $this->provider()->getName()
        );
    }

    /**
     * What to do when the provider cannot answer.
     *
     * @return string
     *   One of self::ERROR_POLICIES.
     */
    protected function errorPolicy(): string
    {
        $configured = $this->config['on_error'] ?? null;
        $policy = is_string($configured) ? strtolower(trim($configured)) : '';

        if ($policy === '') {
            return 'fail_open';
        }

        if (!in_array($policy, self::ERROR_POLICIES, true)) {
            $this->getLogger()->warning('Reputation on_error is not a policy this rule has - failing open', [
                'plugin' => $this->getName(),
                'given' => $configured,
                'expected' => self::ERROR_POLICIES,
            ]);

            return 'fail_open';
        }

        return $policy;
    }
}
