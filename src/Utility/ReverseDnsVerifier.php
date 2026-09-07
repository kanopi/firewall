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
     *   unaffordable -- measured at ~38ms for the reverse lookup and ~74ms for the
     *   forward confirmation against an ordinary resolver, so ~112ms cold. The whole
     *   firewall evaluation is 3.5-5ms.
     * @param int $ttl
     *   How long an acceptance stays good, in seconds.
     * @param int $negativeTtl
     *   How long a refusal stays good. Much longer than an acceptance on purpose: a
     *   refusal is the stable fact -- an address that is not Googlebot will not become
     *   Googlebot -- and refusals are what an attacker generates, so they are the ones
     *   worth remembering.
     * @param bool $offline
     *   When true, never resolve. A cached verdict is still used, because reading it
     *   costs no network.
     * @param float $slowThresholdMs
     *   A lookup slower than this trips the breaker.
     * @param int $breakerCooldown
     *   How long to skip DNS entirely after a slow lookup, in seconds.
     */
    public function __construct(
        protected ?CacheItemPoolInterface $cache = null,
        protected int $ttl = 3600,
        protected int $negativeTtl = 86400,
        protected bool $offline = false,
        protected float $slowThresholdMs = 250.0,
        protected int $breakerCooldown = 300
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

        // Past this point the request would pay for DNS. Everything below is a
        // reason not to let it.

        if ($this->offline) {
            $this->getLogger()->debug('Running offline, so the client was not verified', ['ip' => $ip]);
            return false;
        }

        if ($this->breakerIsOpen()) {
            $this->getLogger()->debug('Reverse DNS breaker is open, skipping the lookup', ['ip' => $ip]);
            return false;
        }

        if (!$this->claimLookup($key)) {
            // Another worker is already resolving this address. Waiting would
            // put this request behind a lookup it does not need to make; the
            // verdict will be cached by the time the client comes back.
            $this->getLogger()->debug('Another process is verifying this address', ['ip' => $ip]);
            return false;
        }

        $startedAt = microtime(true);
        $verdict = $this->resolve($ip, $suffixes);
        $elapsedMs = (microtime(true) - $startedAt) * 1000;

        $this->releaseLookup($key);

        if ($elapsedMs > $this->slowThresholdMs) {
            // PHP cannot bound gethostbyaddr() or dns_get_record() -- neither
            // takes a timeout, so they are bounded only by the system resolver,
            // typically 5s per nameserver with two attempts. One worker eating
            // that is survivable; every worker eating it is an outage. Trip
            // the breaker so the rest skip DNS until the resolver recovers.
            $this->tripBreaker();
            $this->getLogger()->warning('Reverse DNS lookup was slow - skipping verification for a while', [
                'ip' => $ip,
                'elapsed_ms' => round($elapsedMs, 2),
                'threshold_ms' => $this->slowThresholdMs,
                'cooldown_seconds' => $this->breakerCooldown,
                'detail' => 'Run a local caching resolver (systemd-resolved, dnsmasq, unbound) '
                    . 'on the host. Verification is unaffordable without one.',
            ]);
        }

        if ($item instanceof CacheItemInterface && $this->cache instanceof CacheItemPoolInterface) {
            $item->set($verdict);
            $item->expiresAfter($verdict ? $this->ttl : $this->negativeTtl);
            $this->cache->save($item);
        }

        return $verdict;
    }

    /**
     * Whether DNS is being skipped after a slow lookup.
     *
     * @return bool
     *   True while the breaker is open.
     */
    protected function breakerIsOpen(): bool
    {
        if (!$this->cache instanceof CacheItemPoolInterface) {
            return false;
        }

        try {
            return $this->cache->getItem('rdns_breaker')->isHit();
        } catch (\Psr\Cache\InvalidArgumentException) {
            return false;
        }
    }

    /**
     * Stop attempting lookups for the cooldown period.
     */
    protected function tripBreaker(): void
    {
        if (!$this->cache instanceof CacheItemPoolInterface) {
            return;
        }

        try {
            $item = $this->cache->getItem('rdns_breaker');
            $item->set(true);
            $item->expiresAfter($this->breakerCooldown);
            $this->cache->save($item);
        } catch (\Psr\Cache\InvalidArgumentException) {
            // Nothing to do -- without a cache there is no breaker.
        }
    }

    /**
     * Try to become the process that resolves this address.
     *
     * Best effort, not a mutex: two workers arriving in the same instant can both
     * claim it. That is fine -- the point is to collapse a stampede of many workers
     * onto one address into roughly one lookup, not to guarantee exactly one.
     *
     * @param string $key
     *   The verdict cache key.
     *
     * @return bool
     *   True when this process should do the lookup.
     */
    protected function claimLookup(string $key): bool
    {
        if (!$this->cache instanceof CacheItemPoolInterface) {
            return true;
        }

        try {
            $item = $this->cache->getItem($key . '_inflight');

            if ($item->isHit()) {
                return false;
            }

            $item->set(true);
            // Short: a crashed worker must not lock an address out for long.
            $item->expiresAfter(10);
            $this->cache->save($item);

            return true;
        } catch (\Psr\Cache\InvalidArgumentException) {
            return true;
        }
    }

    /**
     * Release the claim.
     *
     * @param string $key
     *   The verdict cache key.
     */
    protected function releaseLookup(string $key): void
    {
        if (!$this->cache instanceof CacheItemPoolInterface) {
            return;
        }

        try {
            $this->cache->deleteItem($key . '_inflight');
        } catch (\Psr\Cache\InvalidArgumentException) {
            // It expires on its own.
        }
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
