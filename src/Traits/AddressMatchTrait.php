<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Traits;

use Kanopi\Firewall\Logging\LoggingTrait;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Address and CIDR matching for the queryable storage backends (#26).
 *
 * Shared so `InMemoryStorage` and `DatabaseStorage` cannot drift apart on what
 * `203.0.113.0/24` means — a range that matched in one backend and not the
 * other would make an un-block silently partial.
 *
 * Matching delegates to Symfony's `IpUtils`, already a hard dependency of this
 * package, rather than hand-rolling the arithmetic: it handles IPv4 and IPv6,
 * and it is considerably better tested than a fresh implementation would be.
 */
trait AddressMatchTrait
{
    use LoggingTrait;

    /**
     * Is this address covered by the pattern?
     *
     * @param string $address
     *   The stored address.
     * @param string $pattern
     *   A single address or a CIDR range.
     *
     * @return bool
     *   TRUE when the pattern covers the address.
     */
    protected function addressMatches(string $address, string $pattern): bool
    {
        if ($address === '' || !$this->isValidPattern($pattern)) {
            return false;
        }

        // A stored key that is not an address cannot be matched by one. This
        // is defensive: getKey() returns the client IP, but a custom storage
        // could have written something else, and we must not hand such a
        // record to a caller who is about to delete what we return.
        if (filter_var($address, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        return IpUtils::checkIp($address, $pattern);
    }

    /**
     * Is the pattern a usable address or CIDR range?
     *
     * Validated up front rather than left to `IpUtils`, which reports a
     * malformed pattern and a genuine non-match identically. The distinction
     * matters here: "your range was nonsense" and "nothing is blocked in that
     * range" call for different responses from an operator.
     *
     * @param string $pattern
     *   The pattern to check.
     *
     * @return bool
     *   TRUE when the pattern can be matched against.
     */
    protected function isValidPattern(string $pattern): bool
    {
        if ($pattern === '') {
            return false;
        }

        if (!str_contains($pattern, '/')) {
            return filter_var($pattern, FILTER_VALIDATE_IP) !== false;
        }

        [$subnet, $prefix] = explode('/', $pattern, 2);

        if (filter_var($subnet, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        if ($prefix === '' || preg_match('/^\d+$/', $prefix) !== 1) {
            return false;
        }

        // A /33 on IPv4 or a /129 on IPv6 is a typo, not a range. Left
        // unchecked, IpUtils treats the prefix as capped and the pattern
        // quietly becomes a single-host match — the caller would delete one
        // record believing they had cleared a range.
        $maximum = filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? 128 : 32;

        return (int) $prefix <= $maximum;
    }

    /**
     * Drop unusable patterns, logging each one.
     *
     * Skipping rather than throwing is deliberate: a typo in one of twenty
     * ranges should not leave the other nineteen blocks in place. The caller
     * still learns what happened, both from the log and from the returned
     * count.
     *
     * Typed `mixed` rather than `string` on purpose. This is the boundary
     * where operator input arrives — a CLI argument, an admin form, a JSON
     * body — and the public contract promising strings does not stop a caller
     * handing over an int or a nested array. Validating here turns that into
     * a logged skip instead of a TypeError that takes the whole un-block down.
     *
     * @param array<int, mixed> $patterns
     *   Raw patterns from the caller.
     *
     * @return array<int, string>
     *   Only the usable ones, reindexed.
     */
    protected function validPatterns(array $patterns): array
    {
        $valid = [];

        foreach ($patterns as $pattern) {
            if (!is_string($pattern) || !$this->isValidPattern($pattern)) {
                $this->getLogger()->warning('Storage query pattern skipped - not a valid address or CIDR range', [
                    'pattern' => is_scalar($pattern) ? (string) $pattern : gettype($pattern),
                ]);
                continue;
            }

            $valid[] = $pattern;
        }

        return $valid;
    }
}
