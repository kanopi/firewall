<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Traits;

use GeoIp2\Database\Reader;
use GeoIp2\WebService\Client;
use Kanopi\Firewall\Logging\LoggingTrait;
use Psr\Cache\CacheItemPoolInterface;
use MaxMind\Db\Reader\InvalidDatabaseException;

/**
 * GeoLocation Trait.
 */
trait GeoLocationTrait
{
    use LoggingTrait;

    /**
     * Max Mind Database Reader.
     */
    protected Reader|Client|null $reader = null;

    /**
     * Records already looked up during this request, keyed by method and address.
     *
     * `getValue()` is called once per rule variable, and each call did its own
     * database read -- so `country:US` and `city:London` in one rule set read the
     * same record twice, and `asn` alongside `asn_org` did the same (#6). The
     * record for one address cannot change within a request, so the second read
     * can never return anything different.
     *
     * @var array<string, object|null>
     */
    protected array $lookupMemo = [];

    /**
     * Cross-request pool for resolved values, or null when caching is off.
     */
    protected ?CacheItemPoolInterface $valueCache = null;

    /**
     * Whether the pool has been resolved yet.
     */
    protected bool $valueCacheResolved = false;

    /**
     * Resolve a value for an address, consulting the cross-request cache.
     *
     * Scalars are cached, never the GeoIP2 model. The model is an object, and an object in
     * a shared store is an object somebody may deserialise -- this library keeps PHP
     * deserialisation out of everything it writes and reads back. A country code is a
     * string, and a string is safe wherever it is kept (#6).
     *
     * A resolved null is cached like any other answer. An address with no record will not
     * acquire one, and re-asking costs the same database read that produced the null.
     *
     * @param string $clientIp
     *   Address the value belongs to.
     * @param string $variable
     *   Rule variable being resolved, e.g. `country` or `asn_org`.
     * @param callable(): mixed $resolve
     *   Produces the value on a miss.
     *
     * @return mixed
     *   The value.
     */
    protected function cachedValue(string $clientIp, string $variable, callable $resolve): mixed
    {
        $pool = $this->valuePool();

        if (!$pool instanceof CacheItemPoolInterface) {
            return $resolve();
        }

        // The class is in the key because GeoLocation and Asn resolve different
        // variables and may be configured with different databases; sharing a
        // pool between them must not let one answer for the other.
        $key = 'geo_' . hash('xxh128', static::class . '|' . $clientIp . '|' . $variable);

        try {
            $item = $pool->getItem($key);

            if ($item->isHit()) {
                return $item->get();
            }

            $value = $resolve();

            // Objects are never stored, whatever a plugin returns.
            if (is_object($value)) {
                return $value;
            }

            $item->set($value);
            $item->expiresAfter($this->valueCacheTtl());
            $pool->save($item);

            return $value;
        } catch (\Psr\Cache\InvalidArgumentException) {
            return $resolve();
        }
    }

    /**
     * How long a resolved value stays good.
     *
     * A day by default. An address's country or network can change, but not on the
     * timescale of a request, and the cost of being a day stale is a rule matching the
     * network an address was on yesterday.
     *
     * @return int
     *   Seconds.
     */
    protected function valueCacheTtl(): int
    {
        $configured = is_array($this->metadata['cache'] ?? null)
            ? ($this->metadata['cache']['ttl'] ?? null)
            : null;

        return is_numeric($configured) ? (int) $configured : 86400;
    }

    /**
     * Build the pool once, from `metadata.cache`.
     *
     * Off unless asked for. Measured, a cache is a net loss below roughly a 26% hit rate:
     * a hit costs 0.036 ms against a 0.305 ms database read, but a miss costs the read
     * *plus* a 0.094 ms write. Ordinary traffic clears that easily; an attack arriving from
     * thousands of distinct addresses does not, and that is exactly when the firewall is
     * busiest. Defaulting it on would make the worst case worse.
     *
     * @return CacheItemPoolInterface|null
     *   The pool, or null when caching is off or unusable.
     */
    protected function valuePool(): ?CacheItemPoolInterface
    {
        if ($this->valueCacheResolved) {
            return $this->valueCache;
        }

        $this->valueCacheResolved = true;
        $configured = $this->metadata['cache'] ?? null;

        if ($configured === null || $configured === false) {
            return $this->valueCache = null;
        }

        if ($configured instanceof CacheItemPoolInterface) {
            return $this->valueCache = $configured;
        }

        $adaptor = is_array($configured) ? ($configured['adaptor'] ?? null) : null;

        if ($adaptor instanceof CacheItemPoolInterface) {
            return $this->valueCache = $adaptor;
        }

        if (!is_string($adaptor) || $adaptor === '') {
            $this->getLogger()->warning('GeoIP cache is configured without an adaptor - caching is off', [
                'hint' => 'Set metadata.cache.adaptor to a PSR-6 pool class, or remove metadata.cache.',
            ]);

            return $this->valueCache = null;
        }

        if (!class_exists($adaptor) || !is_subclass_of($adaptor, CacheItemPoolInterface::class)) {
            $this->getLogger()->warning('GeoIP cache adaptor is not a PSR-6 pool - caching is off', [
                'adaptor' => $adaptor,
            ]);

            return $this->valueCache = null;
        }

        try {
            $args = is_array($configured['args'] ?? null) ? $configured['args'] : [];

            return $this->valueCache = new $adaptor(...$args);
        } catch (\Throwable $throwable) {
            // Slower, not broken. Losing the cache costs a database read per
            // variable; losing the rule would cost enforcement.
            $this->getLogger()->warning('GeoIP cache could not be created - lookups will not be cached', [
                'adaptor' => $adaptor,
                'error' => $throwable->getMessage(),
            ]);

            return $this->valueCache = null;
        }
    }

    /**
     * Look a record up once per address per request.
     *
     * A failed lookup is memoised as null and not retried, for the same reason a
     * successful one is not: nothing about the request changes between calls, so
     * a second attempt would fail identically while paying for it again.
     *
     * @param string $method
     *   Reader method to call -- `city` or `asn`.
     * @param string $clientIp
     *   Address to look up.
     *
     * @return object|null
     *   The record, or null when the lookup failed.
     */
    protected function lookupRecord(string $method, string $clientIp): ?object
    {
        $key = $method . ':' . $clientIp;

        if (array_key_exists($key, $this->lookupMemo)) {
            return $this->lookupMemo[$key];
        }

        if (!$this->reader instanceof Reader && !$this->reader instanceof Client) {
            return $this->lookupMemo[$key] = null;
        }

        if (!method_exists($this->reader, $method)) {
            return $this->lookupMemo[$key] = null;
        }

        $record = $this->reader->{$method}($clientIp);

        return $this->lookupMemo[$key] = is_object($record) ? $record : null;
    }

    /**
     * Create an object for use.
     *
     * @param string|null $type
     *   Type of reader to create.
     * @param array $config
     *   Configuration for reader.
     *
     * @return Reader|Client|null
     *   Return the created reader.
     */
    protected function createService(?string $type, array $config = []): Reader|Client|null
    {
        return match ($type) {
            'reader' => $this->getReader($config['db'] ?? ''),
            'client' => $this->getClient(
                $config['accountId'],
                $config['licenseKey'],
                $config['language'] ?? ['en'],
                $config['options'] ?? [],
            ),
            default => null,
        };
    }

    /**
     * Return the Reader Element.
     *
     * @param string $fileLocation
     *   Location of the Database
     *
     * @return Reader|null
     *   Return the new Reader object.
     */
    protected function getReader(string $fileLocation): ?Reader
    {
        if (!is_file($fileLocation) || !file_exists($fileLocation)) {
            $this->getLogger()->warning('GeoLocation database file not found', [
                'file' => $fileLocation,
            ]);
            return null;
        }

        try {
            $reader = new Reader($fileLocation);

            $this->getLogger()->debug('GeoLocation reader created', [
                'file' => $fileLocation,
                'file_size' => filesize($fileLocation),
            ]);

            return $reader;
        } catch (InvalidDatabaseException $invalidDatabaseException) {
            $this->getLogger()->error('Invalid GeoLocation database', [
                'file' => $fileLocation,
                'error' => $invalidDatabaseException->getMessage(),
            ]);
        }

        return null;
    }

    /**
     * Return a new Web Service Client.
     *
     * @param int $accountId
     *   Account ID for the web service.
     * @param string $license
     *   License ID for the web service.
     * @param array $locales
     *   Array of locales to pass in.
     * @param array $options
     *   Additional Options to pass in.
     *
     * @return Client
     *   Web service client.
     */
    protected function getClient(int $accountId, string $license, array $locales = ['en'], array $options = []): Client
    {
        $client = new Client($accountId, $license, $locales, $options);

        $this->getLogger()->debug('GeoLocation web service client created', [
            'account_id' => $accountId,
            'locales' => $locales,
        ]);

        return $client;
    }
}
