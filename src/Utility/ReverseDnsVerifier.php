<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Kanopi\Firewall\Logging\LoggingTrait;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Confirm a client is who its user agent claims, by reverse DNS.
 *
 * A user-agent allow rule is a skeleton key: "Googlebot" in a header is one curl flag away,
 * and `response: allow` short-circuits evaluation entirely, so a match means no block, no
 * challenge and no rate limit. `presets/search-bots.yml` has shipped with that written in
 * its own header, along with the note that the library had no mechanism for the fix (#199).
 *
 * The fix is what Google, Bing, Apple and DuckDuckGo all document: reverse lookup the
 * address, check the hostname belongs to a domain you trust, then forward-resolve that
 * hostname and confirm it comes back to the address you started with. The forward
 * confirmation is what makes it worth doing -- anyone can point reverse DNS for their own
 * address at `crawl-1-2-3-4.googlebot.com`, and only Google can make that name resolve back.
 */
class ReverseDnsVerifier
{
    use LoggingTrait;

    /**
     * @param CacheItemPoolInterface|null $cache
     *   Where verdicts are kept. A DNS round trip on the request path is otherwise
     *   unaffordable -- it is two lookups, and the request waits for both.
     * @param int $ttl
     *   How long a verdict stays good, in seconds.
     */
    public function __construct(
        protected ?CacheItemPoolInterface $cache = null,
        protected int $ttl = 3600
    ) {
    }

    /**
     * Whether the address reverse-resolves into one of the given domains.
     *
     * @param string $ip
     *   The client address.
     * @param list<string> $suffixes
     *   Domains to accept, e.g. `.googlebot.com`.
     *
     * @return bool
     *   True only when the round trip confirms. Anything else -- no PTR record, a hostname
     *   outside the list, a forward lookup that does not come back, DNS unreachable -- is
     *   false. This guards an *allow* rule, so a failure has to narrow it rather than widen
     *   it: the opposite of the fail-open posture that is right for a reputation block.
     */
    public function verify(string $ip, array $suffixes): bool
    {
        if ($ip === '' || $suffixes === []) {
            return false;
        }

        $key = 'rdns_' . hash('sha256', $ip . '|' . implode(',', $suffixes));
        $item = null;

        if ($this->cache instanceof CacheItemPoolInterface) {
            try {
                $item = $this->cache->getItem($key);

                if ($item->isHit()) {
                    return (bool) $item->get();
                }
            } catch (\Psr\Cache\InvalidArgumentException) {
                $item = null;
            }
        }

        $verdict = $this->resolve($ip, $suffixes);

        if ($item instanceof CacheItemInterface && $this->cache instanceof CacheItemPoolInterface) {
            $item->set($verdict);
            $item->expiresAfter($this->ttl);
            $this->cache->save($item);
        }

        return $verdict;
    }

    /**
     * Do the two lookups.
     *
     * @param string $ip
     *   The client address.
     * @param list<string> $suffixes
     *   Domains to accept.
     *
     * @return bool
     *   Whether the round trip confirmed.
     */
    protected function resolve(string $ip, array $suffixes): bool
    {
        $host = $this->reverseLookup($ip);

        // gethostbyaddr() hands back the address unchanged when there is no PTR
        // record, and false on failure. Neither is a hostname.
        if ($host === false || $host === $ip) {
            $this->getLogger()->debug('Reverse DNS returned no hostname', ['ip' => $ip]);
            return false;
        }

        $host = rtrim(strtolower($host), '.');

        if (!$this->matchesSuffix($host, $suffixes)) {
            $this->getLogger()->debug('Reverse DNS hostname is outside the accepted domains', [
                'ip' => $ip,
                'hostname' => $host,
            ]);
            return false;
        }

        if (!$this->forwardConfirms($host, $ip)) {
            $this->getLogger()->debug('Reverse DNS hostname did not forward-confirm', [
                'ip' => $ip,
                'hostname' => $host,
            ]);
            return false;
        }

        return true;
    }

    /**
     * The PTR lookup, as its own seam so tests need no network.
     *
     * @param string $ip
     *   The address to look up.
     *
     * @return string|false
     *   The hostname, the address unchanged when there is no PTR record, or false.
     */
    protected function reverseLookup(string $ip): string|false
    {
        return @gethostbyaddr($ip);
    }

    /**
     * The forward lookup, as its own seam so tests need no network.
     *
     * @param string $host
     *   The hostname to resolve.
     *
     * @return array<int, array<string, mixed>>|false
     *   DNS records, or false.
     */
    protected function forwardLookup(string $host): array|false
    {
        return @dns_get_record($host, DNS_A | DNS_AAAA);
    }

    /**
     * Whether a hostname sits inside one of the accepted domains.
     *
     * Matching is on a label boundary, always. A bare `googlebot.com` would otherwise
     * accept `evilgooglebot.com`, which anyone can register -- so a configured suffix is
     * normalised to a leading dot, and the domain itself is accepted as an exact match.
     *
     * @param string $host
     *   Lower-cased hostname from the PTR record.
     * @param list<string> $suffixes
     *   Domains to accept.
     *
     * @return bool
     *   Whether it matches.
     */
    protected function matchesSuffix(string $host, array $suffixes): bool
    {
        foreach ($suffixes as $suffix) {
            $suffix = rtrim(strtolower(trim((string) $suffix)), '.');

            if ($suffix === '') {
                continue;
            }

            $bare = ltrim($suffix, '.');

            if ($host === $bare || str_ends_with($host, '.' . $bare)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the hostname resolves back to the address it came from.
     *
     * @param string $host
     *   The hostname from the PTR record.
     * @param string $ip
     *   The address to confirm.
     *
     * @return bool
     *   Whether a forward record matches.
     */
    protected function forwardConfirms(string $host, string $ip): bool
    {
        $expected = @inet_pton($ip);

        if ($expected === false) {
            return false;
        }

        $records = $this->forwardLookup($host);

        if (!is_array($records)) {
            return false;
        }

        foreach ($records as $record) {
            $address = $record['ip'] ?? $record['ipv6'] ?? null;

            if (!is_string($address)) {
                continue;
            }

            if (@inet_pton($address) === $expected) {
                return true;
            }
        }

        return false;
    }
}
