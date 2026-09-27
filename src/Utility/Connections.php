<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Tools\DsnParser;
use Kanopi\Firewall\Cache\CachePoolFactory;
use Kanopi\Firewall\Exception\ConfigurationException;
use Symfony\Component\Cache\Adapter\MemcachedAdapter;
use Symfony\Component\Cache\Adapter\RedisAdapter;

/**
 * Connections declared once, by name, and handed to whatever asks for one (#395).
 *
 * ```yaml
 * connections:
 *   cache: "memcached://cache.internal:11211"
 *   redis: { dsn: "redis://redis.internal:6379", timeout: 3 }
 *   db:    { driver: pdo_mysql, host: "%env(DB_HOST)%", dbname: firewall }
 *
 * logger:
 *   - class: "Monolog\\Handler\\RedisHandler"
 *     args: ["%connection(redis)%", "firewall:log"]
 * ```
 *
 * `%config(...)%` (#186) already lets two settings share a connection's *description*.
 * What it cannot do is hand over a connection itself: a Monolog handler that takes a Redis
 * client, a storage that should reuse one already open. Those needed PHP. This builds the
 * client once per name, and `%connection(name)%` puts that same object wherever it is
 * referenced -- a handler argument, a backend's `instance:`, a cache's `adaptor:`, a
 * database backend's `connection:`.
 *
 * **Resolved where things are built, not in `Config::load()`.** Loading a configuration --
 * to lint it, to list its rules -- should not open network connections, and nothing here
 * belongs in the compiled config cache, which cannot hold an object (#259). So the token
 * stays a string through loading and caching, and each place that builds components from a
 * configuration resolves it: `Firewall::create()`, `BlockList`, `ChallengePasses`, and the
 * database maintenance commands.
 *
 * **One registry per resolution, never global.** Two firewalls in one process -- tests,
 * multi-tenant hosting, Drupal with several configurations -- each get their own clients,
 * so nothing is shared by accident (#184's second constraint).
 *
 * **A connection nothing references is never built,** and building never connects to
 * anything that can be down: a Memcached client and a DBAL connection both connect on first
 * use, and a Redis client that cannot connect is handed over unconnected. Whatever uses it
 * then degrades in its own terms, exactly as it would with its own connection -- a
 * connection to a server that is down must not stop the firewall starting (#356).
 */
final class Connections
{
    /**
     * A whole-value reference.
     */
    private const TOKEN = '/^%connection\(([^()%\s]+)\)%$/';

    /**
     * Connection defaults for Memcached, in libmemcached's own units.
     *
     * Bounded for the reason every connection in this library is (#273, #312): the case
     * that hangs is a dropped connection, not a refused one. Milliseconds for connect and
     * poll, microseconds for send and receive. A server that fails is taken out of the
     * ring for the rest of the request, so its keys move to the servers still up.
     */
    public const MEMCACHED_DEFAULTS = [
        'connect_timeout' => 1500,
        'poll_timeout' => 1500,
        'send_timeout' => 1500000,
        'recv_timeout' => 1500000,
        'remove_failed_servers' => true,
        'server_failure_limit' => 1,
    ];

    /**
     * Connection defaults for Redis, in seconds.
     */
    public const REDIS_DEFAULTS = [
        'timeout' => 1.5,
        'read_timeout' => 1.5,
    ];

    /**
     * Connections built so far, by name.
     *
     * @var array<string, \Memcached|\Redis|Connection|null>
     */
    private array $built = [];

    /**
     * @param array<string, mixed> $declared
     *   The `connections:` map.
     */
    public function __construct(private readonly array $declared)
    {
    }

    /**
     * The registry a configuration declares.
     *
     * @param array<string, mixed> $config
     *   A loaded configuration.
     */
    public static function fromConfig(array $config): self
    {
        $declared = [];

        foreach (is_array($config['connections'] ?? null) ? $config['connections'] : [] as $name => $definition) {
            $declared[(string) $name] = $definition;
        }

        return new self($declared);
    }

    /**
     * Resolve every reference in a configuration against the connections it declares.
     *
     * The one call every build site makes.
     *
     * @param array<string, mixed> $config
     *   A loaded configuration.
     *
     * @return array<string, mixed>
     *   The same configuration, with each reference replaced by its connection.
     *
     * @throws ConfigurationException
     *   For a reference to a name that is not declared, or a reference inside a larger string.
     */
    public static function resolveIn(array $config): array
    {
        return self::containsReference($config) ? self::fromConfig($config)->resolve($config) : $config;
    }

    /**
     * Does any string in this node mention a connection?
     *
     * Checked first so the common configuration, which declares none, is never walked a
     * second time.
     */
    public static function containsReference(mixed $node): bool
    {
        if (is_string($node)) {
            return str_contains($node, '%connection(');
        }

        if (!is_array($node)) {
            return false;
        }

        foreach ($node as $child) {
            if (self::containsReference($child)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Names referenced but not declared -- for the linter, which should not connect.
     *
     * @param array<string, mixed> $config
     *   A loaded configuration.
     *
     * @return array<int, string>
     *   Undeclared names, each once.
     */
    public static function undeclaredReferences(array $config): array
    {
        $declared = array_map(strval(...), array_keys(is_array($config['connections'] ?? null) ? $config['connections'] : []));
        $referenced = [];

        array_walk_recursive($config, static function (mixed $value) use (&$referenced): void {
            if (is_string($value) && preg_match(self::TOKEN, $value, $matches) === 1) {
                $referenced[] = $matches[1];
            }
        });

        return array_values(array_unique(array_diff($referenced, $declared)));
    }

    /**
     * Replace each reference with its connection.
     *
     * The `connections:` block itself is left as it is: it is where the names are
     * declared, not somewhere they are used.
     *
     * @param array<string, mixed> $config
     *   A loaded configuration.
     *
     * @return array<string, mixed>
     *   The resolved configuration.
     *
     * @throws ConfigurationException
     *   See resolveIn().
     */
    public function resolve(array $config): array
    {
        foreach ($config as $key => $value) {
            if ($key === 'connections') {
                continue;
            }

            $config[$key] = $this->resolveNode($value, (string) $key);
        }

        return $config;
    }

    /**
     * The declared names.
     *
     * @return array<int, string>
     */
    public function names(): array
    {
        return array_keys($this->declared);
    }

    /**
     * The connection a name declares, built on first use.
     *
     * @throws ConfigurationException
     *   For a name that is not declared, or a declaration that cannot describe a connection.
     */
    public function get(string $name): \Memcached|\Redis|Connection|null
    {
        if (array_key_exists($name, $this->built)) {
            return $this->built[$name];
        }

        if (!array_key_exists($name, $this->declared)) {
            throw new ConfigurationException(sprintf(
                'Connection "%s" is referenced but not declared under connections:%s',
                $name,
                $this->declared === [] ? '' : ' (declared: ' . implode(', ', $this->names()) . ')'
            ));
        }

        return $this->built[$name] = $this->build($name, $this->declared[$name]);
    }

    /**
     * A connection's target, fit for a report: no user, no password, no query string.
     */
    public function describe(string $name): string
    {
        $definition = $this->declared[$name] ?? null;

        if (is_string($definition)) {
            return CachePoolFactory::describe($definition);
        }

        if (!is_array($definition)) {
            return get_debug_type($definition);
        }

        if (is_string($definition['dsn'] ?? null)) {
            return CachePoolFactory::describe($definition['dsn']);
        }

        return sprintf(
            '%s://%s%s',
            is_string($definition['driver'] ?? null) ? $definition['driver'] : 'database',
            is_string($definition['host'] ?? null) ? $definition['host'] : (is_string($definition['path'] ?? null) ? $definition['path'] : 'localhost'),
            is_string($definition['dbname'] ?? null) ? '/' . $definition['dbname'] : ''
        );
    }

    /**
     * Can the connection a name declares reach its server? For `firewall-doctor`.
     *
     * @return string|null
     *   Why it cannot, or null when it answered.
     */
    public function probe(string $name): ?string
    {
        try {
            $connection = $this->get($name);

            if ($connection === null) {
                return 'it could not be built; the reason is logged and in Firewall::getDegradedBackends()';
            }

            if ($connection instanceof Connection) {
                $connection->executeQuery('SELECT 1');

                return null;
            }

            if ($connection instanceof \Redis) {
                $connection->ping();

                return null;
            }

            $connection->get('kanopi_firewall_connection_probe');

            return in_array($connection->getResultCode(), [\Memcached::RES_SUCCESS, \Memcached::RES_NOTFOUND], true)
                ? null
                : $connection->getResultMessage();
        } catch (\Throwable $throwable) {
            return $throwable->getMessage();
        }
    }

    /**
     * Build a Memcached or Redis client from a DSN, with the bounded defaults.
     *
     * Shared with `CachePoolFactory`, so a cache and a named connection to the same
     * server are built the same way and time out the same way.
     *
     * @param string $dsn
     *   A `memcached://`, `redis://` or `rediss://` DSN.
     * @param array<string, mixed> $options
     *   Options over the defaults, in Symfony's `createConnection()` names.
     *
     * @throws \Throwable
     *   From Symfony, when the extension is missing, the DSN is malformed, or -- Redis
     *   only, since it connects here -- the server does not answer.
     */
    public static function client(#[\SensitiveParameter] string $dsn, array $options = []): \Memcached|\Redis
    {
        if (self::schemeOf($dsn) === 'memcached') {
            return MemcachedAdapter::createConnection($dsn, $options + self::MEMCACHED_DEFAULTS);
        }

        $client = RedisAdapter::createConnection($dsn, $options + self::REDIS_DEFAULTS);

        // @codeCoverageIgnoreStart
        // Symfony returns a Redis cluster or array for DSNs that ask for one, and a
        // Predis client when that is what is installed. Nothing here can hand those
        // to a consumer that expects \Redis, so they are refused rather than passed
        // through to fail later in a harder place to read.
        if (!$client instanceof \Redis) {
            throw new \RuntimeException(sprintf('the DSN builds a %s, and only a single Redis server is supported here', get_debug_type($client)));
        }

        // @codeCoverageIgnoreEnd

        return $client;
    }

    /**
     * The scheme of a DSN, lowercased.
     */
    public static function schemeOf(string $dsn): string
    {
        return strtolower(explode(':', $dsn, 2)[0]);
    }

    /**
     * Walk one node, replacing references.
     *
     * @param mixed $node
     *   The node.
     * @param string $path
     *   Where it is, for an error message.
     *
     * @throws ConfigurationException
     *   See resolveIn().
     */
    private function resolveNode(mixed $node, string $path): mixed
    {
        if (is_array($node)) {
            foreach ($node as $key => $child) {
                $node[$key] = $this->resolveNode($child, $path . '.' . $key);
            }

            return $node;
        }

        if (!is_string($node) || !str_contains($node, '%connection(')) {
            return $node;
        }

        if (preg_match(self::TOKEN, $node, $matches) !== 1) {
            // A connection is an object. Spliced into a string it would become the
            // word "Object" at best, so it is refused where it is written.
            throw new ConfigurationException(sprintf(
                '%s: %%connection(...)%% must be the whole value, not part of a string ("%s")',
                $path,
                $node
            ));
        }

        return $this->get($matches[1]);
    }

    /**
     * Build what a declaration describes.
     *
     * @param string $name
     *   The name, for reports.
     * @param mixed $definition
     *   A DSN string, or a map with `dsn:` or `driver:`.
     *
     * @throws ConfigurationException
     *   When the declaration describes nothing buildable.
     */
    private function build(string $name, mixed $definition): \Memcached|\Redis|Connection|null
    {
        if (is_string($definition)) {
            $definition = ['dsn' => $definition];
        }

        if (!is_array($definition)) {
            throw new ConfigurationException(sprintf('connections.%s must be a DSN or a map, not %s', $name, get_debug_type($definition)));
        }

        $dsn = is_string($definition['dsn'] ?? null) ? $definition['dsn'] : null;
        $scheme = $dsn === null ? null : self::schemeOf($dsn);

        if ($dsn !== null && in_array($scheme, ['memcached', 'redis', 'rediss'], true)) {
            $options = $definition;
            unset($options['dsn']);

            return $this->cacheClient($name, $dsn, $options);
        }

        return $this->database($name, $definition);
    }

    /**
     * A Memcached or Redis client, degrading rather than failing.
     *
     * @param array<string, mixed> $options
     *   Everything in the declaration but its DSN.
     */
    private function cacheClient(string $name, #[\SensitiveParameter] string $dsn, array $options): \Memcached|\Redis|null
    {
        try {
            return self::client($dsn, $options);
        } catch (\Throwable $throwable) {
            $extension = self::schemeOf($dsn) === 'memcached' ? 'memcached' : 'redis';
            $reason = extension_loaded($extension) ? $throwable->getMessage() : sprintf('the %s extension is not installed on this host', $extension);

            // Recorded rather than thrown: a connection to a server that is down
            // must not stop the firewall starting (#356). Whatever uses it
            // degrades in its own terms and says so.
            DegradedBackends::record('named connection', sprintf('connections.%s (%s)', $name, CachePoolFactory::describe($dsn)), $reason);

            // An unconnected client, where there is an extension to make one:
            // handed null, a backend would fall back to its own defaults -- a
            // server on localhost -- and quietly talk to the wrong place.
            return $extension === 'redis' && extension_loaded('redis') ? new \Redis() : null;
        }
    }

    /**
     * A DBAL connection. It connects on first use, so building one cannot fail on a
     * server that is down -- only on a declaration that describes no database.
     *
     * @param array<string, mixed> $definition
     *   A map with `driver:` and its parameters, or `dsn:`.
     *
     * @throws ConfigurationException
     *   When DBAL refuses the declaration.
     */
    private function database(string $name, array $definition): Connection
    {
        try {
            $params = is_string($definition['dsn'] ?? null) ? (new DsnParser())->parse($definition['dsn']) : $definition;

            if (!is_string($params['driver'] ?? null) && !is_string($params['driverClass'] ?? null)) {
                throw new \InvalidArgumentException('it names no driver, and its DSN is not memcached://, redis:// or a database DSN');
            }

            /** @phpstan-ignore argument.type */
            return DriverManager::getConnection($params);
        } catch (\Throwable $throwable) {
            throw new ConfigurationException(sprintf('connections.%s could not be built: %s', $name, $throwable->getMessage()), 0, $throwable);
        }
    }
}
