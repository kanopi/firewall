<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

/**
 * Records a backend that started but cannot reach what it stores things in.
 *
 * Some storage backends refuse to take the site down with them. `RedisStorage` and
 * `RedisRateLimitStorage` catch a connection failure, log it, and answer every read as
 * though nothing were stored, so the firewall carries on enforcing every rule that does not
 * depend on them. That degrade is deliberate and documented -- taking a site down because
 * the block list is unreachable helps nobody.
 *
 * What it costs is visibility. The plugin constructs successfully, so `LazyObjectRegistry`
 * never marks it failed and `Firewall::getFailedRules()` reports nothing (#260 answers a
 * different question: a rule that could not be built at all). A host application with a
 * status report could therefore show a rate limit rule as healthy while its counter store
 * was unreachable and the rule was counting nothing -- which is the exact case #260 was
 * filed to make visible, and the one it did not reach (#273).
 *
 * This is the same shape `Config` already uses for a config file it could not read:
 * loading stays lenient, and the reason stops being thrown away. `Config::getLoadErrors()`
 * is the precedent, deliberately.
 *
 * ## Why a registry rather than a method on the interface
 *
 * An `isAvailable()` on `StorageInterface` would be a better-looking API and a worse
 * change: it breaks every storage backend written outside this package, and it cannot be
 * reached anyway for the case that matters. Rate limit storage is built inside the
 * `RateLimit` plugin and exposed by nothing, so asking it would mean plumbing an accessor
 * through the plugin as well.
 *
 * A backend records where it stands from wherever it happens to be constructed, and the
 * report reads one list.
 *
 * ## What this does and does not catch
 *
 * It records failures at **construction**, which is when a connection is opened and so when
 * an unreachable server is discovered. A backend that connects and later loses the server
 * mid-request is not recorded here; it logs, as it always did.
 */
class DegradedBackends
{
    /**
     * Backends that started degraded, in the order they were recorded.
     *
     * @var array<int, array{component: string, backend: string, error: string}>
     */
    private static array $degraded = [];

    /**
     * Record a backend that started but cannot reach its server.
     *
     * @param string $component
     *   What the backend is for, in the operator's terms -- `block list`,
     *   `rate limit` -- rather than the class doing the storing.
     * @param string $backend
     *   The backend class.
     * @param string $error
     *   What it reported. The actionable half: "Connection refused" against
     *   "No such file or directory".
     */
    public static function record(string $component, string $backend, string $error): void
    {
        foreach (self::$degraded as $existing) {
            // A process can construct the same backend more than once -- two
            // rate limit rules on one server, or a status report that builds
            // every rule to ask. One unreachable server is one fact, and a
            // report listing it three times reads like three problems.
            $same = $existing['component'] === $component
                && $existing['backend'] === $backend
                && $existing['error'] === $error;

            if ($same) {
                return;
            }
        }

        self::$degraded[] = [
            'component' => $component,
            'backend' => $backend,
            'error' => $error,
        ];
    }

    /**
     * Every backend that started degraded in this process.
     *
     * @return array<int, array<string, string>>
     *   Each with the component it serves, the backend class, and what it
     *   reported. Empty when everything reached what it stores things in.
     */
    public static function all(): array
    {
        return self::$degraded;
    }

    /**
     * Forget what has been recorded.
     *
     * For tests, and for a long-running process that wants to reassess rather
     * than carry a failure it has since recovered from.
     */
    public static function reset(): void
    {
        self::$degraded = [];
    }
}
