<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Redis;

/**
 * Hands out one Redis connection per distinct set of options, per process.
 *
 * `RedisStorage` and `RedisRateLimitStorage` are separate backends and each built its own
 * connection, so a deployment using Redis for both the block list and rate limiting opened
 * two connections to the same server on every request -- measured at 0.3643 ms against
 * 0.1720 ms for one, all of it duplication (#263).
 *
 * That deployment is the one Redis storage was added for, so the pairing is the normal case
 * rather than an exotic one.
 *
 * Keyed on the resolved options, not on the calling class: two backends pointed at
 * different servers, or different databases on one server, still get their own connection.
 * Only genuinely identical targets are shared.
 */
class RedisConnections
{
    /**
     * Connections already opened by this process, keyed by target.
     *
     * @var array<string, Redis>
     */
    private static array $connections = [];

    /**
     * How long to wait for a connection, in seconds, when nothing says otherwise.
     *
     * A method rather than a constant only for consistency with the rest of this
     * package's 8.1 support; there is no trait here.
     *
     * 1.5 seconds is far longer than a Redis on the same network needs -- a
     * handshake across availability zones is single-digit milliseconds -- and far
     * shorter than the alternative.
     *
     * @return float
     *   Seconds.
     */
    private static function defaultTimeout(): float
    {
        return 1.5;
    }

    /**
     * Bound how long a connection may take, because nothing else does.
     *
     * `new Redis($options)` connects during construction when `host` is present,
     * and with no timeout among the options `ext-redis` falls back to
     * `default_socket_timeout` -- 60 seconds on a stock PHP. A Redis host that
     * refuses a connection or fails to resolve answers immediately, so the bad
     * case is the one that silently drops packets: a firewalled port, a wrong
     * subnet, a security group nobody updated. Measured at 60,068 ms, matching
     * the ini value exactly (#273).
     *
     * That lands on a request. The registry above means a process pays it once
     * rather than per request, but every worker is cold after a deploy, and #256
     * put Redis on the block list path as well as the rate limiter -- so a
     * deployment using both has two of them.
     *
     * A bounded timeout turns a minute of hanging into a fast fall into the
     * degrade that is already written and already documented: the backend logs,
     * answers as though nothing were stored, and the firewall carries on
     * enforcing every rule that does not depend on it.
     *
     * Both are overridable, because a deployment reaching a Redis over a link
     * slow enough to need longer should be able to say so:
     *
     * ```yaml
     * redis:
     *   host: redis.internal
     *   connectTimeout: 5
     *   readTimeout: 5
     * ```
     *
     * Applied before the key is taken, so a caller that sets the same value
     * explicitly still shares a connection with one that took the default.
     *
     * @param array<string, mixed> $options
     *   Options as given.
     *
     * @return array<string, mixed>
     *   The same options, with timeouts filled in where absent.
     */
    private static function withTimeouts(array $options): array
    {
        // Spelled exactly as `ext-redis` spells them. An option it does not
        // recognise is skipped with a PHP warning rather than refused, so
        // `connect_timeout` would look configured and do nothing.
        $options['connectTimeout'] ??= self::defaultTimeout();
        $options['readTimeout'] ??= self::defaultTimeout();

        return $options;
    }

    /**
     * A connection for these options, opened once.    /**
     * A connection for these options, opened once.
     *
     * @param array<string, mixed> $options
     *   Options as `ext-redis` accepts them.
     *
     * @return Redis
     *   A connection, possibly shared with another backend.
     *
     * @throws \RedisException
     *   When the connection cannot be established. Callers already handle this: a Redis
     *   that cannot be reached is logged and the backend degrades.
     */
    public static function get(array $options): Redis
    {
        $options = self::withTimeouts($options);
        $key = self::key($options);

        if (isset(self::$connections[$key])) {
            return self::$connections[$key];
        }

        return self::$connections[$key] = new Redis($options);
    }

    /**
     * Forget every connection this process holds.
     *
     * For tests. Nothing in the request path needs it -- a process ends and its connections
     * go with it -- but a suite that shares them between cases is a suite where one test's
     * server can answer for another's.
     */
    public static function reset(): void
    {
        self::$connections = [];
    }

    /**
     * Identify a connection target.
     *
     * `serialize()` over sorted options rather than a hand-picked subset: `ext-redis`
     * accepts more keys than are worth enumerating, and picking a few would quietly share a
     * connection between targets that differ in one nobody thought of.
     *
     * @param array<string, mixed> $options
     *   Connection options.
     *
     * @return string
     *   Target key.
     */
    private static function key(array $options): string
    {
        ksort($options);

        // Objects can appear here -- a stream context, say -- and are not part of what
        // identifies a server. Serialising one would also be a way to get object state into
        // a cache key, which is not what this is for.
        $scalars = array_filter($options, static fn ($value): bool => !is_object($value));

        return hash('xxh128', serialize($scalars));
    }
}
