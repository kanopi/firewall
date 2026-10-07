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
use Kanopi\Firewall\Utility\ReverseDns\LookupResult;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsResolverInterface;
use Kanopi\Firewall\Utility\ReverseDns\SystemResolver;
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
 *
 * The lookups themselves are a resolver's (#473): PHP's own by default, or DNS over HTTPS
 * through a provider, or a site's own class. Everything that keeps the answer safe stays
 * here for all of them -- caching, the in-flight claim, the breaker, the domain check, the
 * forward confirmation, and validating what a resolver returns -- so no resolver can widen
 * an allow rule past what DNS confirms.
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
     * @param int $claimWaitMs
     *   How long a worker that could not claim the lookup will wait for the
     *   holder's verdict before giving up. `0` refuses immediately, which is
     *   what every release before 2.23.0 did.
     * @param ReverseDnsResolverInterface|null $resolver
     *   Who makes the lookups. NULL uses this class's own `reverseLookup()` and
     *   `forwardLookup()` -- PHP's functions, as `SystemResolver` does -- so a subclass
     *   that overrides them keeps working.
     * @param int $unknownTtl
     *   How long a lookup that could not say either way is remembered, as a refusal. Short
     *   on purpose: one network blip must not refuse the real crawler for a day, as
     *   `negativeTtl` would. Not zero, because a client whose own DNS answers SERVFAIL
     *   could otherwise make every one of its requests pay for a lookup.
     * @param string $scope
     *   Which resolver the verdicts and the breaker belong to. Empty for PHP's own
     *   lookups, which keeps the keys every release before this one wrote. A verdict
     *   one resolver reached -- a day-long refusal from a lookup PHP could not finish,
     *   say -- must not outlive a switch to another, and one slow resolver must not
     *   switch verification off for rules that use a different one.
     */
    public function __construct(
        protected ?CacheItemPoolInterface $cache = null,
        protected int $ttl = 3600,
        protected int $negativeTtl = 86400,
        protected bool $offline = false,
        protected float $slowThresholdMs = 250.0,
        protected int $breakerCooldown = 300,
        protected int $claimWaitMs = 0,
        protected ?ReverseDnsResolverInterface $resolver = null,
        protected int $unknownTtl = 60,
        protected string $scope = ''
    ) {
    }

    /**
     * Most PTR hostnames considered for one address. More is not a crawler.
     */
    private const MAX_HOSTNAMES = 10;

    /**
     * Most forward lookups one verification makes.
     *
     * Each hostname inside the accepted domains costs a forward lookup, and the owner of
     * the client's address writes its PTR records -- so without a cap, ten invented
     * `crawl-*.googlebot.com` names are ten lookups for one request. None of them would
     * confirm, but together they outlast the breaker's threshold, and a tripped breaker
     * switches verification off for everybody. `gethostbyaddr()` only ever returned one
     * name; two leaves room for a crawler with a second PTR record.
     */
    private const MAX_FORWARD_LOOKUPS = 2;

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

        $key = 'rdns_' . hash('sha256', ($this->scope === '' ? '' : $this->scope . '|') . $ip . '|' . implode(',', $suffixes));
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
            // Another worker is already resolving this address.
            //
            // Refusing immediately is cheap and wrong often enough to matter.
            // Measured with 25 workers on one uncached address (#245): against a
            // 50 ms resolver 14 of 25 were verified, and against a 300 ms one,
            // 2 of 25. This guards an *allow* rule, so "not verified" means the
            // rule does not match -- a genuine crawler arriving in parallel on a
            // cold cache falls through, and is blocked if a rule below the allow
            // matches it.
            //
            // So a caller may wait a bounded time for the holder's verdict
            // instead (#261). Off by default: it trades latency for a verdict,
            // and which of those an operator wants is not ours to assume.
            $waited = $this->waitForVerdict($key);

            if ($waited !== null) {
                $this->getLogger()->debug('Used a verdict another process was resolving', [
                    'ip' => $ip,
                    'verified' => $waited,
                ]);

                return $waited;
            }

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
            //
            // The same backstop for every resolver: one that bounds its own
            // lookups should never get here, and one that does not is caught.
            $this->tripBreaker();
            $this->getLogger()->warning('Reverse DNS lookup was slow - skipping verification for a while', [
                'ip' => $ip,
                'elapsed_ms' => round($elapsedMs, 2),
                'threshold_ms' => $this->slowThresholdMs,
                'cooldown_seconds' => $this->breakerCooldown,
                'resolver' => ($this->resolver ?? new SystemResolver())::class,
                'detail' => !$this->resolver instanceof \Kanopi\Firewall\Utility\ReverseDns\ReverseDnsResolverInterface || $this->resolver instanceof SystemResolver
                    ? 'Run a local caching resolver (systemd-resolved, dnsmasq, unbound) on the host, '
                        . 'or verify through a DNS-over-HTTPS provider, whose lookups have a time limit. '
                        . 'See docs/configuration/reverse-dns.md.'
                    : 'The resolver took longer than verify_slow_threshold_ms. Check that it bounds '
                        . 'its lookups, and that its timeout fits under the threshold.',
            ]);
        }

        if ($item instanceof CacheItemInterface && $this->cache instanceof CacheItemPoolInterface) {
            $item->set($verdict === true);
            $item->expiresAfter(match ($verdict) {
                true => $this->ttl,
                false => $this->negativeTtl,
                null => $this->unknownTtl,
            });
            $this->cache->save($item);
        }

        return $verdict === true;
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
            return $this->cache->getItem($this->breakerKey())->isHit();
        } catch (\Psr\Cache\InvalidArgumentException) {
            return false;
        }
    }

    /**
     * The breaker's cache key, scoped like the verdicts.
     */
    private function breakerKey(): string
    {
        return $this->scope === '' ? 'rdns_breaker' : 'rdns_breaker_' . hash('sha256', $this->scope);
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
            $item = $this->cache->getItem($this->breakerKey());
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
     * Wait briefly for the worker holding the claim to publish its verdict.
     *
     * The alternative to refusing a request because somebody else is already
     * asking the question it needs answered.
     *
     * Polls rather than blocks, because the claim is a cache entry rather than
     * a lock -- there is nothing to wait on, only somewhere to look. Every
     * interval costs one cache read, which for the filesystem pool is 0.009 ms.
     *
     * Bounded by `verify_claim_wait_ms`, and 0 means "do not", which is what
     * every release before 2.23.0 did. The trade is explicit either way: up to
     * that many milliseconds of latency on a cold-cache collision, against a
     * verdict rather than a refusal.
     *
     * @param string $key
     *   The cache key the holder will write to.
     *
     * @return bool|null
     *   The verdict, or NULL if none appeared in time -- which the caller
     *   treats exactly as it treated a failed claim before this existed.
     */
    protected function waitForVerdict(string $key): ?bool
    {
        if ($this->claimWaitMs <= 0 || !$this->cache instanceof CacheItemPoolInterface) {
            return null;
        }

        $deadline = microtime(true) + ($this->claimWaitMs / 1000);

        // Short enough that a fast resolver is not waited out for no reason,
        // long enough that a 100 ms budget is twenty reads rather than
        // thousands.
        $interval = 5000;

        while (microtime(true) < $deadline) {
            $this->pause($interval);

            try {
                $item = $this->cache->getItem($key);
            } catch (\Psr\Cache\InvalidArgumentException) {
                // The same key the caller already built and read with. If it is
                // rejected now, waiting longer will not change that.
                return null;
            }

            if ($item->isHit()) {
                return (bool) $item->get();
            }
        }

        return null;
    }

    /**
     * Sleep, as a seam.
     *
     * Overridden in tests so a wait can be exercised without one.
     *
     * @param int $microseconds
     *   How long to sleep.
     *
     * @codeCoverageIgnore
     */
    protected function pause(int $microseconds): void
    {
        usleep($microseconds);
    }

    /**
     * Release the claim.    /**
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
     * Every PTR hostname is considered, not just the first: an address can have several,
     * and it is verified when any one of them is in the accepted domains and resolves back
     * to it.
     *
     * @param string $ip
     *   The client address.
     * @param list<string> $suffixes
     *   Domains to accept.
     *
     * @return bool|null
     *   Whether the round trip confirmed, or NULL when a lookup could not say either way --
     *   which is remembered for `unknownTtl` rather than `negativeTtl`.
     */
    protected function resolve(string $ip, array $suffixes): ?bool
    {
        $packed = @inet_pton($ip);

        if ($packed === false) {
            return false;
        }

        $lookupResult = $this->reverseResult($ip);

        if ($lookupResult->isUnknown()) {
            $this->getLogger()->debug('Reverse DNS lookup could not say either way', [
                'ip' => $ip,
                'reason' => $lookupResult->reason,
            ]);

            return null;
        }

        if (!$lookupResult->isAnswer()) {
            $this->getLogger()->debug('Reverse DNS returned no hostname', ['ip' => $ip]);

            return false;
        }

        $type = strlen($packed) === 16 ? ReverseDnsResolverInterface::TYPE_AAAA : ReverseDnsResolverInterface::TYPE_A;
        $unknown = false;
        $forwardLookups = 0;

        foreach (array_slice($lookupResult->values, 0, self::MAX_HOSTNAMES) as $value) {
            $host = rtrim(strtolower($value), '.');

            // The owner of the client's address block writes its PTR records, so what
            // comes back is checked before it is used for anything -- including being
            // built into a resolver's URL for the forward lookup.
            if (!$this->isHostname($host)) {
                $this->getLogger()->debug('Reverse DNS returned something that is not a hostname', [
                    'ip' => $ip,
                    'hostname' => substr($value, 0, 255),
                ]);
                continue;
            }

            if (!$this->matchesSuffix($host, $suffixes)) {
                $this->getLogger()->debug('Reverse DNS hostname is outside the accepted domains', [
                    'ip' => $ip,
                    'hostname' => $host,
                ]);
                continue;
            }

            if ($forwardLookups >= self::MAX_FORWARD_LOOKUPS) {
                $this->getLogger()->debug('Reverse DNS returned more crawler hostnames than are checked', [
                    'ip' => $ip,
                    'checked' => self::MAX_FORWARD_LOOKUPS,
                ]);
                break;
            }

            $forwardLookups++;
            $confirmed = $this->confirms($host, $ip, $packed, $type);

            if ($confirmed === true) {
                return true;
            }

            if ($confirmed === null) {
                $unknown = true;
                continue;
            }

            $this->getLogger()->debug('Reverse DNS hostname did not forward-confirm', [
                'ip' => $ip,
                'hostname' => $host,
            ]);
        }

        return $unknown ? null : false;
    }

    /**
     * The reverse lookup, through the resolver or this class's own seam.
     *
     * @param string $ip
     *   A valid client address.
     */
    private function reverseResult(string $ip): LookupResult
    {
        if (!$this->resolver instanceof ReverseDnsResolverInterface) {
            $host = $this->reverseLookup($ip);

            // gethostbyaddr() hands back the address unchanged when there is no PTR
            // record, and false on failure. Neither is a hostname.
            return $host === false || $host === $ip ? LookupResult::none() : LookupResult::answer([$host]);
        }

        return $this->ask(fn(ReverseDnsResolverInterface $reverseDnsResolver): LookupResult => $reverseDnsResolver->reverse($ip));
    }

    /**
     * Whether a hostname resolves back to the client address.
     *
     * @param string $host
     *   A validated hostname inside the accepted domains.
     * @param string $ip
     *   The client address.
     * @param string $packed
     *   The client address, packed.
     * @param string $type
     *   The record type for the client's address family.
     *
     * @return bool|null
     *   Whether it confirmed, or NULL when the lookup could not say.
     */
    private function confirms(string $host, string $ip, string $packed, string $type): ?bool
    {
        if (!$this->resolver instanceof ReverseDnsResolverInterface) {
            return $this->forwardConfirms($host, $packed);
        }

        $lookupResult = $this->ask(fn(ReverseDnsResolverInterface $reverseDnsResolver): LookupResult => $reverseDnsResolver->forward($host, $type));

        if ($lookupResult->isUnknown()) {
            $this->getLogger()->debug('Forward DNS lookup could not say either way', [
                'ip' => $ip,
                'hostname' => $host,
                'reason' => $lookupResult->reason,
            ]);

            return null;
        }

        foreach ($lookupResult->values as $address) {
            if (@inet_pton($address) === $packed) {
                return true;
            }
        }

        return false;
    }

    /**
     * Call the resolver, treating anything it throws as an unknown result.
     *
     * A resolver is host code, or an HTTP call, and both fail. Neither failure is a reason
     * to widen an allow rule or to fail a request, so it is reported and refused -- the
     * same isolation a decision listener gets.
     *
     * @param \Closure(ReverseDnsResolverInterface): LookupResult $lookup
     *   The call to make.
     */
    private function ask(\Closure $lookup): LookupResult
    {
        /** @var ReverseDnsResolverInterface $resolver */
        $resolver = $this->resolver;

        try {
            return $lookup($resolver);
        } catch (\Throwable $throwable) {
            DegradedBackends::record('reverse DNS', $resolver::class, $throwable->getMessage());

            $this->getLogger()->warning('Reverse DNS resolver threw, so the client was not verified', [
                'resolver' => $resolver::class,
                'error' => $throwable->getMessage(),
            ]);

            return LookupResult::unknown('the resolver threw: ' . $throwable->getMessage());
        }
    }

    /**
     * Whether a PTR answer is a hostname that can safely be looked up.
     *
     * Letters, digits and hyphens in dot-separated labels of at most 63 characters, at
     * most 253 in all. Anything else -- `&`, `/`, `?`, `#`, spaces -- is refused before it
     * goes anywhere near a resolver's URL.
     *
     * @param string $host
     *   Lower-cased, without a trailing dot.
     */
    private function isHostname(string $host): bool
    {
        return strlen($host) <= 253
            && preg_match('/^[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})*$/', $host) === 1;
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
     *   One line wrapping a PHP function, and the reason this seam exists is so
     *   the tests never touch the network. Covering it would mean making a real
     *   DNS query from the unit suite, which is exactly what the seam prevents.
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
     *
     * @codeCoverageIgnore
     *   As reverseLookup(): a one-line seam whose whole purpose is to keep the
     *   network out of the suite.
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
     * Whether the hostname resolves back to the address it came from, through this
     * class's own `forwardLookup()`.
     *
     * @param string $host
     *   The hostname from the PTR record.
     * @param string $expected
     *   The address to confirm, packed. Packed by the caller, which has already refused
     *   an address that does not pack -- so a forward record that does not pack either
     *   can never compare equal to it.
     *
     * @return bool
     *   Whether a forward record matches.
     */
    private function forwardConfirms(string $host, string $expected): bool
    {
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
