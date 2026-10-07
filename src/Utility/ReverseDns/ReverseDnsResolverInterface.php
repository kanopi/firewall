<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility\ReverseDns;

/**
 * Does the two DNS lookups reverse-DNS verification needs (#473).
 *
 * `ReverseDnsVerifier` decides whether a client is the crawler it claims to be. A resolver
 * only answers its two questions -- which hostnames does this address have, and which
 * addresses does this hostname have -- so the decision, and everything that keeps it safe,
 * stays in one place whichever resolver is configured: caching, the circuit breaker, the
 * domain check, the forward confirmation, and validating what comes back.
 *
 * A resolver therefore cannot widen an allow rule past what DNS confirms. A buggy one can be
 * slow, or wrong about DNS, and nothing more.
 *
 * Named in configuration by its fully-qualified class name, built-in or not:
 *
 * ```yaml
 * global:
 *   reverse_dns:
 *     resolver: "App\\Firewall\\PlatformDnsResolver"
 *     resolver_options:
 *       base_url: "https://dns.platform.internal"
 * ```
 *
 * A constructor parameter typed `array` receives the options -- from `resolver_options`, or
 * from the selected provider's `options`.
 *
 * **Every lookup must be bounded in time.** The library cannot put a timeout on arbitrary
 * PHP, and an unbounded lookup on the request path is the outage #473 exists to fix. The
 * verifier times each call and opens its circuit breaker when one is slow, but that is a
 * backstop, not a time limit.
 *
 * A resolver that throws is treated as an unknown result, logged, and reported through
 * `DegradedBackends`.
 */
interface ReverseDnsResolverInterface
{
    /**
     * An IPv4 address record.
     */
    public const TYPE_A = 'A';

    /**
     * An IPv6 address record.
     */
    public const TYPE_AAAA = 'AAAA';

    /**
     * The hostnames an address reverse-resolves to (PTR records).
     *
     * @param string $ip
     *   A valid IPv4 or IPv6 address.
     *
     * @return LookupResult
     *   The hostnames, as found. A trailing dot is fine; validating them is the verifier's
     *   job.
     */
    public function reverse(string $ip): LookupResult;

    /**
     * The addresses a hostname resolves to.
     *
     * @param string $hostname
     *   A hostname the verifier has already validated and matched against the rule's
     *   domains. It came from a PTR record, which the owner of the client's address block
     *   controls, so a resolver that builds it into a URL or a query must still encode it.
     * @param string $type
     *   `TYPE_A` or `TYPE_AAAA`: the family of the client's address, the only one that can
     *   confirm it.
     *
     * @return LookupResult
     *   The addresses, as found.
     */
    public function forward(string $hostname, string $type): LookupResult;
}
