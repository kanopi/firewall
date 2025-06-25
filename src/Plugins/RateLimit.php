<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\RateLimitStorage\RateLimitStorageFactory;
use Kanopi\Firewall\RateLimitStorage\RateLimitStorageInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Rate Limiting.
 */
class RateLimit extends AbstractPluginBase
{
    /**
     * Rate Limit Storage.
     */
    protected ?RateLimitStorageInterface $storage = null;

    /**
     * Constructs a new RateLimit object.
     */
    public function __construct(array $metadata = [], array $config = [])
    {
        parent::__construct($metadata, $config);

        if (isset($this->metadata['storage'])) {
            $this->storage = RateLimitStorageFactory::create($this->metadata['storage']['type'], $this->metadata['storage']['config'] ?? []);
            $this->getLogger()->debug('Rate limit storage configured', [
                'storage_type' => $this->metadata['storage']['type'],
                'storage_config' => $this->metadata['storage']['config'] ?? [],
            ]);
        } else {
            $this->storage = RateLimitStorageFactory::create(null);
            $this->getLogger()->debug('Rate limit using default storage');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
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
        return sprintf(
            'rate:%s:%s',
            $request->getClientIp(),
            $rule['path']
        );
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        $path = $request->getPathInfo();
        $matchedRule = $this->matchRule($path);

        $key = $this->buildRateKey($request, $matchedRule);
        $now = time();
        $windowStart = $now - intval($matchedRule['sample']);

        $count = $this->storage?->countRequests($key, $windowStart, $now) ?? 0;

        $this->getLogger()->debug('Rate limit check', [
            'plugin' => $this->getName(),
            'request_id' => $request->attributes->get('x-request-id'),
            'client_ip' => $request->getClientIp(),
            'path' => $path,
            'matched_rule' => $matchedRule['path'],
            'rate_limit' => intval($matchedRule['rate']),
            'window_seconds' => intval($matchedRule['sample']),
            'current_count' => $count,
            'key' => $key,
        ]);

        if ($count >= intval($matchedRule['rate'])) {
            $this->getLogger()->warning('Rate limit exceeded', [
                'plugin' => $this->getName(),
                'request_id' => $request->attributes->get('x-request-id'),
                'client_ip' => $request->getClientIp(),
                'path' => $path,
                'rate_limit' => intval($matchedRule['rate']),
                'window_seconds' => intval($matchedRule['sample']),
                'request_count' => $count,
            ]);
            return true;
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

                return (array)$rule;
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
    public function getStatusCode(): int
    {
        return 429;
    }
}
