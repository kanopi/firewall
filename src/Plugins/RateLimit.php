<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\RateLimitStorage\PrunableRateLimitStorageInterface;
use Kanopi\Firewall\RateLimitStorage\RateLimitStorageFactory;
use Kanopi\Firewall\RateLimitStorage\RateLimitStorageInterface;
use Kanopi\Firewall\Traits\RequestValueTrait;
use Symfony\Component\HttpFoundation\Request;

/**
 * Rate Limiting.
 */
class RateLimit extends AbstractPluginBase
{
    use RequestValueTrait;

    /**
     * The smallest limit that can be enforced.
     *
     * The check is `$count >= $rate`, and a count is never negative, so a rate
     * of 0 is satisfied by no request at all -- including the first, which has
     * recorded nothing. An operator who writes 0 means "do not limit this";
     * enforced literally it refuses the whole site (#229).
     *
     * A rate below this is therefore treated as "not limited" rather than
     * obeyed. Falling back to `default_rate`'s documented 10 was the other
     * option and is worse: 10 requests per 10 seconds across every unlisted
     * path is close to the outage the operator wrote 0 to avoid.
     */
    protected const MINIMUM_ENFORCEABLE_RATE = 1;

    /**
     * Rate Limit Storage.
     */
    protected ?RateLimitStorageInterface $storage = null;

    /**
     * What a rate limit counts by when nothing says otherwise.
     *
     * The client IP and the rule's pattern: exactly the key every release before 2.27.0
     * built, so a configuration that declares no `key` is unchanged (#200).
     *
     * @var array<int, string>
     */
    private const DEFAULT_KEY = ['client_ip', 'rule_pattern'];

    /**
     * Constructs a new RateLimit object.
     */
    public function __construct(array $metadata = [], array $config = [])
    {
        // Set 10 requests as the default.
        $metadata['default_rate'] ??= 10;
        // Set 10 seconds as the default sample size.
        $metadata['default_sample'] ??= 10;
        parent::__construct($metadata, $config);

        $this->warnAboutUnenforceableRates();

        if (isset($this->metadata['storage'])) {
            $this->storage = RateLimitStorageFactory::create($this->metadata['storage']['type'], $this->metadata['storage']['config'] ?? []);
            $this->getLogger()->debug('Rate limit storage configured', [
                'storage_type' => $this->metadata['storage']['type'],
                'storage_config' => $this->metadata['storage']['config'] ?? [],
            ]);
        } else {
            $this->storage = RateLimitStorageFactory::create();
            $this->getLogger()->debug('Rate limit using default storage');
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function defaultName(): string
    {
        return 'Rate Limit';
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return 'Rate Limit the user.';
    }

    /**
     * Whether paths with no rule of their own are limited.
     *
     * The catch-all applies to every path, so adding a rule to protect
     * `/user/login` used to bring a site-wide cap with it, and put the counter
     * store on the path of every allowed request (#226). Declaring
     * `limit_unlisted_paths: false` limits only what was listed.
     *
     * Defaults to true, which is what the plugin has always done.
     *
     * This is deliberately separate from `default_rate` rather than overloading
     * a rate of 0 to mean "unlimited". `default_rate` is still the fallback for
     * a listed rule that omits its own `rate`, so a value that switched the
     * catch-all off would silently unlimit those rules too.
     *
     * @return bool
     *   True when unlisted paths are limited.
     */
    protected function limitsUnlistedPaths(): bool
    {
        return (bool) ($this->metadata['limit_unlisted_paths'] ?? true);
    }

    /**
     * Tell the operator about any rate that cannot be enforced.
     *
     * Once per construction rather than once per request: a misconfigured rate
     * is a property of the configuration, and repeating it on every request
     * buries it in the traffic it is describing.
     */
    protected function warnAboutUnenforceableRates(): void
    {
        $unenforceable = [];

        if (intval($this->metadata['default_rate']) < self::MINIMUM_ENFORCEABLE_RATE) {
            $unenforceable[] = [
                'setting' => 'metadata.default_rate',
                'rate' => $this->metadata['default_rate'],
            ];
        }

        foreach ($this->config as $index => $rule) {
            if (!is_array($rule)) {
                continue;
            }

            if (!array_key_exists('rate', $rule)) {
                continue;
            }

            if (intval($rule['rate']) < self::MINIMUM_ENFORCEABLE_RATE) {
                $unenforceable[] = [
                    'setting' => sprintf('rule "%s"', strval($rule['path'] ?? '#' . $index)),
                    'rate' => $rule['rate'],
                ];
            }
        }

        foreach ($unenforceable as $problem) {
            $this->getLogger()->warning(
                'Rate limit is below 1 and cannot be enforced - treating it as no limit',
                [
                    'plugin_name' => $this->getName(),
                    'setting' => $problem['setting'],
                    'rate' => $problem['rate'],
                    'detail' => 'A rate of 0 would refuse every request, including the first. '
                        . 'To stop limiting paths with no rule of their own, declare '
                        . 'limit_unlisted_paths: false. Otherwise set a rate of 1 or more.',
                ]
            );
        }
    }

    /**
     * Build the rate key to search for.
     *
     * @param Request $request
     *   Request to get information from.
     * @param array $rule
     *   Rule provided.
     *
     * @return string
     *   Build the key.
     */
    protected function buildRateKey(Request $request, array $rule): string
    {
        $components = $this->keyComponents($rule);

        // The default is the legacy key, byte for byte, rather than a hash of
        // the same two values. A composed key has to be hashed -- see below --
        // and hashing the default as well would reset every counter on every
        // install the moment they upgrade. Rate state is cheap to lose, but
        // losing it site-wide during the upgrade of a firewall is a window
        // nobody asked for.
        if ($components === self::DEFAULT_KEY) {
            return sprintf('rate:%s:%s', $request->getClientIp(), $rule['path']);
        }

        $parts = [];

        foreach ($components as $component) {
            $parts[] = $component . '=' . $this->keyComponentValue($request, $rule, $component);
        }

        // Hashed, because a composed key can name `post.username` or
        // `header.authorization`, and a rate limit is not a reason for a
        // credential to be written to Redis, a database, or a file on disk.
        // The separator is in the hashed material so ["a", "bc"] and ["ab",
        // "c"] cannot collide.
        return 'rate:' . hash('xxh128', implode("\0", $parts));
    }

    /**
     * Which request fields this rule counts by.
     *
     * Per rule, falling back to `metadata.default_key`, falling back to the client IP and
     * the rule's own pattern -- which is what every version before 2.27.0 did, and what
     * every configuration that declares nothing keeps doing.
     *
     * @param array<string, mixed> $rule
     *   The matched rule.
     *
     * @return array<int, string>
     *   Component names, in declaration order.
     */
    protected function keyComponents(array $rule): array
    {
        foreach ([$rule['key'] ?? null, $this->metadata['default_key'] ?? null] as $declared) {
            if (!is_array($declared)) {
                continue;
            }

            $components = array_values(array_filter(
                $declared,
                static fn(mixed $c): bool => is_string($c) && trim($c) !== ''
            ));

            if ($components !== []) {
                return array_map(static fn(string $c): string => strtolower(trim($c)), $components);
            }
        }

        return self::DEFAULT_KEY;
    }

    /**
     * Resolve one component of the key to a string.
     *
     * An unresolvable component -- a header that was not sent, a POST field that is not
     * there -- becomes the empty string rather than being dropped. Dropping it would make
     * a request missing the field share a bucket with one whose field is genuinely empty,
     * and the position of every later component would shift.
     *
     * @param Request $request
     *   The request.
     * @param array<string, mixed> $rule
     *   The matched rule.
     * @param string $component
     *   The component name.
     *
     * @return string
     *   Its value.
     */
    protected function keyComponentValue(Request $request, array $rule, string $component): string
    {
        if ($component === 'client_ip') {
            return (string) $request->getClientIp();
        }

        if ($component === 'rule_pattern') {
            return is_string($rule['path'] ?? null) ? $rule['path'] : '';
        }

        // Everything else is the vocabulary the Url plugin already uses --
        // `path`, `method`, `host`, `header.x`, `post.y`, `cookie.z`,
        // `query.q`. A second spelling of the same idea is how `sample` and
        // `window` came to mean the same thing in two places.
        $value = $this->resolveRequestValue($request, $component);

        // Never an array: `resolveRequestValue()` folds repeated headers to a
        // string and deliberately resolves a nested array under `post` or
        // `query` to NULL, so there is nothing here to guard against. An
        // `is_array()` branch would be unreachable, and unreachable defensive
        // code is a claim about behaviour that nothing checks.
        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        $path = $request->getPathInfo();
        $matchedRule = $this->matchRule($path);

        if (($matchedRule['catch_all'] ?? false) && !$this->limitsUnlistedPaths()) {
            $this->getLogger()->debug('Path is not covered by a rate limit rule, skipping', $this->getContext($request, [
                'path' => $path,
            ]));
            return false;
        }

        $rate = intval($matchedRule['rate']);

        // A rule that cannot be enforced does not count, and does not record.
        // Recording would be pure cost -- the counter store is the expensive
        // part of this plugin, and nothing would ever read what it wrote.
        if ($rate < self::MINIMUM_ENFORCEABLE_RATE) {
            $this->getLogger()->debug('Rate limit rule is not enforceable, skipping', $this->getContext($request, [
                'matched_rule' => $matchedRule['path'],
                'rate_limit' => $rate,
            ]));
            return false;
        }

        $key = $this->buildRateKey($request, $matchedRule);
        $now = time();
        $windowStart = $now - intval($matchedRule['sample']);

        $count = $this->storage?->countRequests($key, $windowStart, $now) ?? 0;

        $this->getLogger()->debug('Rate limit check', $this->getContext($request, [
            'matched_rule' => $matchedRule['path'],
            'rate_limit' => $rate,
            'window_seconds' => intval($matchedRule['sample']),
            'current_count' => $count,
            'key' => $key,
        ]));

        if ($count >= $rate) {
            $this->getLogger()->warning('Rate limit exceeded', $this->getContext($request, [
                'rate_limit' => $rate,
                'window_seconds' => intval($matchedRule['sample']),
                'request_count' => $count,
            ]));
            return true;
        }

        // Drop what has aged out of this key's window before adding to it
        // (#183). Nothing in the storage interface removed a record, so every
        // backend grew -- the file and database ones without any bound at all.
        //
        // The plugin is the only place that knows the cutoff. A rate limit is
        // a rolling window and `$windowStart` is where this key's window now
        // begins, so everything older has already stopped affecting the
        // verdict and can never affect a later one. That is exact, and it
        // needs no retention setting for an operator to choose and then keep
        // in step with the widest `sample` they have configured.
        //
        // Only on this path, deliberately. Records are added here and nowhere
        // else, so pruning here is enough to bound the growth; a key that is
        // over its limit stops being appended to, so it stops growing on its
        // own and does not need the firewall doing extra work on behalf of
        // traffic it is busy refusing.
        if ($this->storage instanceof PrunableRateLimitStorageInterface) {
            $this->storage->forget($key, $windowStart);
        }

        $this->storage?->recordRequest($key, $now);
        return false;
    }

    /**
     * Find the first matching rule for the given path.
     *
     * @param string $path
     *   Path to query against.
     *
     * @return array
     *   Return information about the path or null if not found.
     */
    protected function matchRule(string $path): array
    {
        foreach ($this->config as $rule) {
            // A hand-written config can put a bare string, or a map with no
            // `path`, in the rule list. Reading ['path'] off either was a fatal
            // -- "Cannot access offset of type string on string" -- which turned
            // a typo into a 500 rather than a rule that does not match.
            // warnAboutUnenforceableRates() already guards the same way.
            if (!is_array($rule)) {
                continue;
            }

            if (!is_string($rule['path'] ?? null)) {
                continue;
            }

            $pattern = $this->wildcardToRegex($rule['path']);
            if (preg_match($pattern, $path)) {
                $rule['rate'] ??= $this->metadata['default_rate'];
                $rule['sample'] ??= $this->metadata['default_sample'];

                $this->getLogger()->debug('Rate limit rule matched', [
                    'path' => $path,
                    'rule_pattern' => $rule['path'],
                    'rate' => $rule['rate'],
                    'sample' => $rule['sample'],
                ]);

                return $rule;
            }
        }

        // return the default record.
        $this->getLogger()->debug('Using default rate limit rule', [
            'path' => $path,
            'rate' => $this->metadata['default_rate'],
            'sample' => $this->metadata['default_sample'],
        ]);

        return [
            'path' => '*',
            'rate' => $this->metadata['default_rate'],
            'sample' => $this->metadata['default_sample'],
            // Marks a rule nobody wrote. `path` alone cannot say so: an
            // operator is free to configure a rule whose pattern is literally
            // "*", and that one they do mean.
            'catch_all' => true,
        ];
    }

    /**
     * Convert a wildcard path (e.g. "/example/*") to a regex.
     *
     * @param string $pattern
     *   The string to check against.
     *
     * @return string
     *   Return the regex value.
     */
    protected function wildcardToRegex(string $pattern): string
    {
        // Check if this already looks like a regex (starts and ends with the same non-alphanumeric delimiter)
        if (strlen($pattern) >= 3 && preg_match('/^([^a-zA-Z0-9\s\\\]).+\1[imsxuADSUXJ]*$/', $pattern)) {
            return $pattern; // Already a regex, return as-is
        }

        // Otherwise, treat as wildcard and convert
        $escaped = preg_quote($pattern, '/');
        $regex = str_replace('\*', '.*', $escaped);

        return '/^' . $regex . '$/';
    }

    /**
     * {@inheritdoc}
     */
    public function getStatusCode(?Request $request = null): int
    {
        return 429;
    }
}
