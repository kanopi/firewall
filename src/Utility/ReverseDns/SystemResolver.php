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
 * PHP's own lookups, through the operating system's resolver. The default.
 *
 * `gethostbyaddr()` and `dns_get_record()` are what reverse-DNS verification has always
 * used (#199), and nothing about them changes here. Neither takes a timeout, so each is
 * bounded only by the operating system's resolver -- typically 5 s per nameserver, with two
 * attempts. On a host with a local caching resolver that is rarely felt. On one without, it
 * is the reason `DnsOverHttpResolver` exists (#473).
 *
 * **It never reports an unknown result.** Neither function can tell "no such record" from
 * "the lookup failed": `gethostbyaddr()` returns the address unchanged for both a missing
 * PTR record and an unreachable resolver, and `dns_get_record()` returns `false` for both a
 * missing name and a failure. So both read as no record, and the verdict is remembered for
 * `verify_negative_ttl` -- exactly as every release before this one did.
 */
class SystemResolver implements ReverseDnsResolverInterface
{
    /**
     * {@inheritdoc}
     */
    public function reverse(string $ip): LookupResult
    {
        $host = $this->reverseLookup($ip);

        // The address unchanged when there is no PTR record, and false on failure.
        // Neither is a hostname.
        if ($host === false || $host === $ip) {
            return LookupResult::none();
        }

        return LookupResult::answer([$host]);
    }

    /**
     * {@inheritdoc}
     */
    public function forward(string $hostname, string $type): LookupResult
    {
        $records = $this->forwardLookup($hostname);

        if (!is_array($records)) {
            return LookupResult::none();
        }

        $key = $type === self::TYPE_AAAA ? 'ipv6' : 'ip';
        $addresses = [];

        foreach ($records as $record) {
            if (is_string($record[$key] ?? null)) {
                $addresses[] = $record[$key];
            }
        }

        return LookupResult::answer($addresses);
    }

    /**
     * The PTR lookup, as its own seam so tests need no network.
     *
     * @param string $ip
     *   The address to look up.
     *
     * @return string|false
     *   The hostname, the address unchanged when there is no PTR record, or false.
     *
     * @codeCoverageIgnore
     *   One line wrapping a PHP function, and the reason this seam exists is so the tests
     *   never touch the network.
     */
    protected function reverseLookup(string $ip): string|false
    {
        return @gethostbyaddr($ip);
    }

    /**
     * The forward lookup, as its own seam so tests need no network.
     *
     * Both families in one call, as before; `forward()` keeps the one it was asked for.
     *
     * @param string $host
     *   The hostname to resolve.
     *
     * @return array<int, array<string, mixed>>|false
     *   DNS records, or false.
     *
     * @codeCoverageIgnore
     *   As reverseLookup().
     */
    protected function forwardLookup(string $host): array|false
    {
        return @dns_get_record($host, DNS_A | DNS_AAAA);
    }
}
