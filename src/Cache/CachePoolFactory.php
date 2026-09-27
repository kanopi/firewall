<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Cache;

use Kanopi\Firewall\Utility\Connections;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\MemcachedAdapter;
use Symfony\Component\Cache\Adapter\RedisAdapter;

/**
 * Build a PSR-6 pool from a cache setting (#394).
 *
 * Four settings take a pool -- `CacheRateLimitStorage`'s `adaptor`, the user-agent and
 * GeoIP `metadata.cache`, and reverse DNS's `metadata.verify_cache` -- and three of them
 * each resolved it their own way, with slightly different fallbacks. This is the one way.
 * Each caller still decides what to do when there is no pool, because those decisions
 * really are different: the user-agent cache is on by default and falls back to a file,
 * the GeoIP cache is off by default and stays off.
 *
 * A setting is any of:
 *
 * - an already-built pool, passed through the overrides argument;
 * - `adaptor:` naming a pool, a pool class with `args:`, or a DSN;
 * - the adaptor on its own, as a string, for short.
 *
 * A DSN is what makes Memcached and Redis reachable from YAML. Their adapters take a
 * *connected client* as their first argument, which a YAML value cannot hold; a DSN names
 * the server instead, and Symfony's own `createConnection()` builds the client.
 *
 * ```yaml
 * cache:
 *   adaptor: "memcached://cache.internal:11211"
 *   namespace: firewall_ua
 *   options: { connect_timeout: 500 }
 * ```
 */
final class CachePoolFactory
{
    /**
     * The DSN schemes a pool can be built from.
     */
    public const SCHEMES = ['memcached', 'redis', 'rediss'];

    /**
     * Build the pool a setting describes.
     *
     * @param mixed $configured
     *   The raw setting.
     * @param string $namespace
     *   The namespace for a pool built from a DSN, unless the setting names one. Every
     *   setting has its own, so two caches sharing a server cannot read each other's keys.
     * @param int $defaultLifetime
     *   The default lifetime for a pool built from a DSN, in seconds; 0 for none.
     *
     * @return CacheItemPoolInterface|null
     *   The pool, or null when the setting names none at all -- which each caller treats
     *   as its own default.
     *
     * @throws CachePoolException
     *   When the setting names something that is not a pool, or a pool that could not be
     *   built.
     */
    public static function create(mixed $configured, string $namespace, int $defaultLifetime = 0): ?CacheItemPoolInterface
    {
        if ($configured instanceof CacheItemPoolInterface) {
            return $configured;
        }

        if (is_string($configured)) {
            $configured = ['adaptor' => $configured];
        }

        if (!is_array($configured)) {
            return null;
        }

        $adaptor = $configured['adaptor'] ?? null;

        if ($adaptor === null || $adaptor === '') {
            return null;
        }

        if ($adaptor instanceof CacheItemPoolInterface) {
            return $adaptor;
        }

        $name = is_string($configured['namespace'] ?? null) && $configured['namespace'] !== ''
            ? $configured['namespace']
            : $namespace;

        // A client, not a pool: what `%connection(name)%` resolves to (#395), so a
        // cache can share the connection a storage or a log handler already uses.
        if ($adaptor instanceof \Memcached || $adaptor instanceof \Redis) {
            return self::fromClient($adaptor, $name, $defaultLifetime);
        }

        if (!is_string($adaptor)) {
            throw CachePoolException::notAPool(sprintf(
                'adaptor must be a pool class name, a DSN or a named connection, not %s',
                get_debug_type($adaptor)
            ));
        }

        if (self::isDsn($adaptor)) {
            $options = is_array($configured['options'] ?? null) ? $configured['options'] : [];

            return self::fromDsn($adaptor, $name, $defaultLifetime, $options);
        }

        return self::fromClass($adaptor, is_array($configured['args'] ?? null) ? $configured['args'] : []);
    }

    /**
     * Does this adaptor name a server rather than a class?
     *
     * A class name cannot contain a colon, so anything with a scheme is a DSN -- including
     * one this cannot build, which is better reported as an unsupported scheme than as a
     * class that does not exist.
     */
    public static function isDsn(string $adaptor): bool
    {
        return preg_match('/^[a-z][a-z0-9+.-]*:/i', $adaptor) === 1;
    }

    /**
     * An adaptor fit for a log line.
     *
     * A DSN may carry a password -- `redis://:secret@host` -- and every warning about a
     * pool names its adaptor. The userinfo is replaced, and the query string, which is
     * where Symfony also accepts credentials, is dropped.
     *
     * @param mixed $adaptor
     *   The configured adaptor.
     *
     * @return string
     *   Something safe to log.
     */
    public static function describe(mixed $adaptor): string
    {
        if ($adaptor instanceof CacheItemPoolInterface) {
            return $adaptor::class;
        }

        if (!is_string($adaptor)) {
            return get_debug_type($adaptor);
        }

        if (!self::isDsn($adaptor)) {
            return $adaptor;
        }

        $withoutQuery = explode('?', $adaptor, 2)[0];

        return (string) preg_replace('#^([a-z][a-z0-9+.-]*://)[^@/]*@#i', '$1***@', $withoutQuery);
    }

    /**
     * Build a pool from a class name and its constructor arguments.
     *
     * @param string $class
     *   The pool class.
     * @param array<int|string, mixed> $args
     *   Constructor arguments, spread in declaration order.
     *
     * @throws CachePoolException
     *   When the class is not a pool, or its constructor refuses the arguments.
     */
    private static function fromClass(string $class, array $args): CacheItemPoolInterface
    {
        if (!class_exists($class) || !is_subclass_of($class, CacheItemPoolInterface::class)) {
            throw CachePoolException::notAPool(sprintf('%s is not a PSR-6 pool', $class));
        }

        try {
            return new $class(...$args);
        } catch (\Throwable $throwable) {
            throw CachePoolException::unusable($throwable->getMessage(), $throwable);
        }
    }

    /**
     * Build a Memcached or Redis pool from a DSN.
     *
     * @param string $dsn
     *   The server.
     * @param string $namespace
     *   The pool namespace.
     * @param int $defaultLifetime
     *   Seconds, or 0.
     * @param array<string, mixed> $options
     *   Connection options, over the bounded defaults.
     *
     * @throws CachePoolException
     *   When the scheme is not supported, the extension is missing, or no server answers.
     */
    private static function fromDsn(#[\SensitiveParameter] string $dsn, string $namespace, int $defaultLifetime, array $options): CacheItemPoolInterface
    {
        $scheme = strtolower(explode(':', $dsn, 2)[0]);

        if (!in_array($scheme, self::SCHEMES, true)) {
            throw CachePoolException::unusable(sprintf(
                'the DSN scheme "%s" is not supported; use %s',
                $scheme,
                implode(', ', array_map(static fn (string $supported): string => $supported . '://', self::SCHEMES))
            ));
        }

        $extension = $scheme === 'memcached' ? 'memcached' : 'redis';

        try {
            // Built the way a named connection is, with the same bounded
            // defaults. Redis connects here, and throws when it cannot.
            return self::fromClient(Connections::client($dsn, $options), $namespace, $defaultLifetime);
        } catch (CachePoolException $cachePoolException) {
            throw $cachePoolException;
        } catch (\Throwable $throwable) {
            // Named plainly when it is the extension, which is a different fix from
            // a server that is down. Symfony's exceptions carry no DSN -- it marks
            // it #[SensitiveParameter] -- so the message is safe to log as it is.
            throw CachePoolException::unusable(
                extension_loaded($extension) ? $throwable->getMessage() : sprintf('the %s extension is not installed on this host', $extension),
                $throwable
            );
        }
    }

    /**
     * Wrap a client in a pool, with the marshaller that refuses objects.
     *
     * @throws CachePoolException
     *   When no Memcached server answers.
     */
    private static function fromClient(\Memcached|\Redis $client, string $namespace, int $defaultLifetime): CacheItemPoolInterface
    {
        if ($client instanceof \Redis) {
            return new RedisAdapter($client, $namespace, $defaultLifetime, new NoObjectsMarshaller());
        }

        // Creating a client opens nothing. Without asking for something, a
        // server that is down is only found on the first lookup -- and then on
        // every one after it.
        if (!self::memcachedAnswers($client)) {
            throw CachePoolException::unusable(sprintf('no Memcached server answered (%s)', $client->getResultMessage()));
        }

        return new MemcachedAdapter($client, $namespace, $defaultLifetime, new NoObjectsMarshaller());
    }

    /**
     * Does any configured Memcached server answer?
     *
     * A read rather than `getVersion()`, which reports failure when any one server fails,
     * so a single server down would take the whole cache with it. The same probe as
     * `MemcachedStorage`: one attempt per server, since a failed server is ejected and the
     * next attempt reaches another.
     */
    private static function memcachedAnswers(\Memcached $memcached): bool
    {
        $attempts = max(1, count($memcached->getServerList()));

        for ($attempt = 0; $attempt < $attempts; $attempt++) {
            $memcached->get('kanopi_firewall_cache_probe');

            if (in_array($memcached->getResultCode(), [\Memcached::RES_SUCCESS, \Memcached::RES_NOTFOUND], true)) {
                return true;
            }
        }

        return false;
    }
}
