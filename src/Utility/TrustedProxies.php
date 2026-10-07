<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Logging\LoggingFactory;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Request;

/**
 * Trusted proxies declared in YAML, applied for the firewall's own reads only (#397).
 *
 * ```yaml
 * global:
 *   trusted_proxies: ["10.0.0.0/8", "173.245.48.0/20"]    # or REMOTE_ADDR, PRIVATE_SUBNETS
 *   trusted_headers: [x-forwarded-for, x-forwarded-proto, x-forwarded-port]
 * ```
 *
 * Every IP rule, allow list and per-IP rate limit reads `getClientIp()`, and Symfony only
 * believes `X-Forwarded-For` from a proxy passed to `Request::setTrustedProxies()`. Until
 * now that call had to be made in the host's bootstrap, so a site whose only integration
 * point is a YAML file had to edit a front controller -- and getting it wrong makes every
 * address rule spoofable.
 *
 * **Why this is not simply a call to `setTrustedProxies()`.** That method is static: it
 * sets process-wide state that every `Request` reads, the host application's included. A
 * library setting it quietly could override a host that configured it more tightly, leak
 * between two firewalls in one process, and change what the host sees as well as what the
 * firewall sees. So these proxies are applied for the length of one evaluation and the
 * previous values put back afterwards, and when the host has already set proxies of its
 * own, the host's are used and these are ignored -- the host knows its infrastructure, and
 * two sources disagreeing is resolved in favour of the one closer to it.
 *
 * One limit, stated rather than hidden: in `mode: block` the firewall sends its response
 * and exits, and PHP does not run `finally` blocks on `exit()`. The process ends there, so
 * only a shutdown function could observe the proxies still applied.
 */
final class TrustedProxies
{
    /**
     * The header names a configuration may trust, and Symfony's flag for each.
     */
    public const HEADERS = [
        'forwarded' => Request::HEADER_FORWARDED,
        'x-forwarded-for' => Request::HEADER_X_FORWARDED_FOR,
        'x-forwarded-host' => Request::HEADER_X_FORWARDED_HOST,
        'x-forwarded-proto' => Request::HEADER_X_FORWARDED_PROTO,
        'x-forwarded-port' => Request::HEADER_X_FORWARDED_PORT,
        'x-forwarded-prefix' => Request::HEADER_X_FORWARDED_PREFIX,
    ];

    /**
     * Trusted when `trusted_headers` is not given.
     *
     * Enough for the client address and scheme, and no more. `X-Forwarded-Host` is left
     * out on purpose: trusting it changes what `getHost()` answers, which reaches log
     * lines and challenge URLs, and a proxy that does not set it would leave it to the
     * client.
     */
    public const DEFAULT_HEADERS = ['x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-port'];

    /**
     * Whether the host's own proxies have already been reported as winning.
     */
    private bool $reportedHostWins = false;

    /**
     * @param array<int, string> $proxies
     *   Addresses and ranges, plus the `REMOTE_ADDR` and `PRIVATE_SUBNETS` keywords.
     * @param int $headerSet
     *   Symfony's trusted header bitmask.
     * @param array<int, string> $headerNames
     *   The same headers, by name, for reports.
     */
    private function __construct(
        private readonly array $proxies,
        private readonly int $headerSet,
        private readonly array $headerNames,
    ) {
    }

    /**
     * The trusted proxies a `global:` block declares, or null when it declares none.
     *
     * @param array<string, mixed> $global
     *   The `global:` block.
     *
     * @throws ConfigurationException
     *   For an entry that is not an address or range, a range that trusts every client,
     *   or a header name that is not one.
     */
    public static function fromGlobal(array $global): ?self
    {
        $declared = $global['trusted_proxies'] ?? null;

        if (in_array($declared, [null, [], ''], true)) {
            return null;
        }

        $proxies = [];

        foreach (is_array($declared) ? $declared : [$declared] as $proxy) {
            $proxies[] = self::proxy($proxy);
        }

        $headerNames = [];
        $headerSet = 0;

        foreach (self::headerNames($global['trusted_headers'] ?? null) as $name) {
            $headerNames[] = $name;
            $headerSet |= self::HEADERS[$name];
        }

        return new self($proxies, $headerSet, $headerNames);
    }

    /**
     * Apply these proxies for one evaluation.
     *
     * @param Request $request
     *   The request being evaluated. `REMOTE_ADDR` is taken from it rather than from
     *   `$_SERVER`, which is what Symfony would read, so a request built by a host or a
     *   test resolves against its own peer.
     *
     * @return callable|null
     *   What puts the previous values back, or null when nothing was applied because the
     *   host's own proxies are in force.
     */
    public function apply(Request $request): ?callable
    {
        if (Request::getTrustedProxies() !== []) {
            if (!$this->reportedHostWins) {
                $this->reportedHostWins = true;

                LoggingFactory::logMessage('warning', 'global.trusted_proxies is ignored - the host application has already called Request::setTrustedProxies()', [
                    'detail' => 'The host knows its infrastructure, so its proxies are used. Remove '
                        . 'global.trusted_proxies, or stop setting them in the bootstrap, so there is one source.',
                ]);
            }

            return null;
        }

        $previousHeaders = Request::getTrustedHeaderSet();
        $peer = $request->server->get('REMOTE_ADDR');

        $proxies = [];

        foreach ($this->proxies as $proxy) {
            // Both keywords expanded here rather than left to Symfony. REMOTE_ADDR
            // because Symfony reads $_SERVER, not the request being evaluated;
            // PRIVATE_SUBNETS because Symfony 6.4 does not know it, and would
            // store the word as a "proxy" matching nothing -- so the setting
            // would trust no proxy at all, and say nothing.
            if ($proxy === 'REMOTE_ADDR') {
                if (is_string($peer) && $peer !== '') {
                    $proxies[] = $peer;
                }

                continue;
            }

            if ($proxy === 'PRIVATE_SUBNETS') {
                array_push($proxies, ...IpUtils::PRIVATE_SUBNETS);

                continue;
            }

            $proxies[] = $proxy;
        }

        Request::setTrustedProxies($proxies, $this->headerSet);

        return static function () use ($previousHeaders): void {
            Request::setTrustedProxies([], $previousHeaders);
        };
    }

    /**
     * What is trusted, for `firewall doctor`.
     */
    public function describe(): string
    {
        return sprintf('%s, trusting %s', implode(', ', $this->proxies), implode(', ', $this->headerNames));
    }

    /**
     * Validate one `trusted_proxies` entry.
     *
     * @throws ConfigurationException
     *   When it is not an address, a range or a keyword, or when it trusts everyone.
     */
    private static function proxy(mixed $proxy): string
    {
        if (!is_string($proxy) || trim($proxy) === '') {
            throw new ConfigurationException(sprintf('global.trusted_proxies: %s is not an address or range', get_debug_type($proxy)));
        }

        $proxy = trim($proxy);

        if ($proxy === 'REMOTE_ADDR' || $proxy === 'PRIVATE_SUBNETS') {
            return $proxy;
        }

        [$address, $prefix] = array_pad(explode('/', $proxy, 2), 2, null);

        if (filter_var($address, FILTER_VALIDATE_IP) === false || ($prefix !== null && preg_match('/^\d{1,3}$/', $prefix) !== 1)) {
            throw new ConfigurationException(sprintf(
                'global.trusted_proxies: "%s" is not an address, a CIDR range, REMOTE_ADDR or PRIVATE_SUBNETS',
                $proxy
            ));
        }

        $maximum = str_contains((string) $address, ':') ? 128 : 32;

        if ($prefix !== null && (int) $prefix > $maximum) {
            throw new ConfigurationException(sprintf('global.trusted_proxies: "%s" has a prefix longer than /%d', $proxy, $maximum));
        }

        // Trusting every address trusts every client's own X-Forwarded-For --
        // the spoofing hole this setting exists to close, with extra steps.
        if ($prefix !== null && (int) $prefix === 0) {
            throw new ConfigurationException(sprintf(
                'global.trusted_proxies: "%s" trusts every client, so any visitor could claim any address. '
                . "List your proxies' own ranges, or use REMOTE_ADDR behind a load balancer.",
                $proxy
            ));
        }

        return $proxy;
    }

    /**
     * The header names to trust.
     *
     * @return array<int, string>
     *
     * @throws ConfigurationException
     *   For a name that is not a forwarding header -- a header silently not trusted is a
     *   quiet version of the problem this exists to fix.
     */
    private static function headerNames(mixed $declared): array
    {
        if ($declared === null || $declared === []) {
            return self::DEFAULT_HEADERS;
        }

        $names = [];

        foreach (is_array($declared) ? $declared : [$declared] as $header) {
            $name = is_string($header) ? strtolower(trim($header)) : '';

            if (!array_key_exists($name, self::HEADERS)) {
                throw new ConfigurationException(sprintf(
                    'global.trusted_headers: "%s" is not a forwarding header (%s)',
                    is_scalar($header) ? (string) $header : get_debug_type($header),
                    implode(', ', array_keys(self::HEADERS))
                ));
            }

            $names[] = $name;
        }

        return array_values(array_unique($names));
    }
}
