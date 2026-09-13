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

/**
 * Somewhere that will say how bad an address is (#204).
 *
 * AbuseIPDB was one provider written as one plugin, and its caching, its
 * fail-open posture and its quota budgeting were all good and all welded to it.
 * Spamhaus, Project Honeypot, a client's own scoring endpoint and an internal
 * service all want the same shape, so the shape is here and the plugin owns
 * everything around it.
 *
 * ## What a provider does and does not do
 *
 * A provider looks up one address and says what it found. It does **not**
 * cache, decide a threshold, handle a failure policy, or know what the firewall
 * will do with the answer -- all of that is `Plugins\Reputation`, written once,
 * so a new provider is the HTTP call and the shape of the response and nothing
 * else.
 *
 * ## Failing open is the default because it is not optional here
 *
 * `check()` throws `ReputationUnavailableException` rather than returning
 * something falsy. The plugin catches it, logs it and carries on, so a
 * reputation service that is down cannot take a site down -- a provider gets
 * that by throwing, and cannot accidentally opt out of it.
 *
 * That is the opposite of the identity verification in #199, which fails
 * *closed*: verification guards an allow rule, where "cannot confirm" has to
 * mean "not allowed". Reputation is corroborating evidence for a block, where
 * "cannot confirm" has to mean "carry on".
 */
interface ReputationProviderInterface
{
    /**
     * What to call this provider in a log line.
     *
     * @return string
     *   A human name, like `AbuseIPDB`.
     */
    public function getName(): string;

    /**
     * A filesystem-safe identifier, used to namespace cached verdicts.
     *
     * Two providers asked about the same address must not read each other's
     * answers -- their scores are on different scales and mean different
     * things.
     *
     * @return string
     *   Lowercase, no separators beyond `-`.
     */
    public function getSlug(): string;

    /**
     * Why this provider cannot be used yet, if it cannot.
     *
     * Lets a provider be added to a configuration before its credential is
     * provisioned: the plugin reports the problem once per request at debug and
     * matches nothing, rather than refusing to start or -- much worse --
     * blocking every visitor.
     *
     * @return string|null
     *   The problem, phrased to finish "evaluation skipped - ...", or NULL when
     *   the provider is ready.
     */
    public function getConfigurationProblem(): ?string;

    /**
     * Whether this provider could have an answer for an address.
     *
     * A public reputation service has nothing to say about `10.0.0.4`, and
     * asking costs a call, a timeout's worth of latency and a slice of quota to
     * be told nothing. An internal service may be the opposite.
     *
     * @param string $ip
     *   The client address.
     *
     * @return bool
     *   TRUE when the lookup is worth making.
     */
    public function knowsAbout(string $ip): bool;

    /**
     * Look up one address.
     *
     * @param string $ip
     *   The client address, already checked against `knowsAbout()`.
     *
     * @return ReputationVerdict
     *   What the provider said.
     *
     * @throws ReputationUnavailableException
     *   When no answer could be obtained, for any reason. The plugin treats
     *   every one of them the same way: log, cache briefly, carry on.
     */
    public function check(string $ip): ReputationVerdict;

    /**
     * How long a verdict from this provider stays usable, in seconds.
     *
     * A default, overridden by the plugin's `cache_ttl`. It belongs to the
     * provider because the right answer is a property of the service: a free
     * tier of 1,000 calls a day wants a day, and an internal service on the
     * same network can afford minutes.
     *
     * @return int
     *   Seconds.
     */
    public function getDefaultCacheTtl(): int;

    /**
     * How long a failure from this provider stays cached, in seconds.
     *
     * Short by nature. Long enough that an outage does not cost every request
     * a full timeout -- which is a site slowdown wearing failing-open as a
     * disguise -- and short enough that recovery is picked up promptly.
     *
     * @return int
     *   Seconds.
     */
    public function getDefaultErrorCacheTtl(): int;
}
