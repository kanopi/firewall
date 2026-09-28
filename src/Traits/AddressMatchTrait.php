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
     * Is this address inside a `start-end` range?
     *
     * The notation the `IpAddress` plugin has always accepted, and the natural
     * way to describe an office. Kept apart from addressMatches() on purpose:
     * the storage backends query by address or CIDR only, and widening what
     * an un-block accepts is not this method's business (#407).
     *
     * @param string $address
     *   The client address.
     * @param string $range
     *   Two addresses of the same family joined by `-`, lowest first.
     *
     * @return bool
     *   TRUE when the address falls within the range, bounds included.
     */
    protected function addressInRange(string $address, string $range): bool
    {
        $bounds = $this->rangeBounds($range);

        if ($bounds === null) {
            return false;
        }

        $packed = filter_var($address, FILTER_VALIDATE_IP) !== false ? inet_pton($address) : false;

        // A different family is outside the range rather than an error: an
        // IPv6 visitor is simply not in an IPv4 office's range.
        if ($packed === false || strlen($packed) !== strlen($bounds[0])) {
            return false;
        }

        // Packed addresses of one family are fixed-width big-endian strings, so
        // a byte comparison orders them numerically -- for IPv6 too, which
        // ip2long() cannot do.
        return strcmp($packed, $bounds[0]) >= 0 && strcmp($packed, $bounds[1]) <= 0;
    }

    /**
     * Is the range something addressInRange() can match against?
     *
     * @param string $range
     *   The range to check.
     *
     * @return bool
     *   TRUE for two addresses of one family, lowest first.
     */
    protected function isValidRange(string $range): bool
    {
        return $this->rangeBounds($range) !== null;
    }

    /**
     * The packed bounds of a `start-end` range, or NULL when it is not one.
     *
     * Backwards bounds are refused rather than swapped. `.20-.10` matches
     * nothing if read literally, and guessing what the operator meant is how an
     * allowlist ends up covering more than they wrote.
     *
     * @param string $range
     *   The range to parse.
     *
     * @return array{0: string, 1: string}|null
     *   The packed start and end.
     */
    private function rangeBounds(string $range): ?array
    {
        if (substr_count($range, '-') !== 1) {
            return null;
        }

        [$start, $end] = array_map(trim(...), explode('-', $range, 2));

        if (filter_var($start, FILTER_VALIDATE_IP) === false || filter_var($end, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $start = (string) inet_pton($start);
        $end = (string) inet_pton($end);

        if (strlen($start) !== strlen($end) || strcmp($start, $end) > 0) {
            return null;
        }

        return [$start, $end];
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
