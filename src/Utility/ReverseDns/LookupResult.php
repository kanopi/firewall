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
 * What one DNS lookup found: an answer, no such record, or nothing to go on.
 *
 * Three outcomes rather than a value-or-false, because two of them have to be told apart
 * (#473). "No such record" is a fact about the address and is worth remembering for a day:
 * an address that is not Googlebot will not become Googlebot. "Could not tell" -- a
 * timeout, a server failure, a body that would not decode -- is a fact about the network
 * at that moment, and remembering it for a day would refuse the real Googlebot for a day
 * after one blip.
 *
 * A result carries data, never a verdict. Whether a hostname is acceptable, and whether it
 * forward-confirms, is decided by `ReverseDnsVerifier` for every resolver alike.
 */
final class LookupResult
{
    /**
     * The lookup found records.
     */
    public const ANSWER = 'answer';

    /**
     * The name has no records of the type asked for.
     */
    public const NONE = 'none';

    /**
     * The lookup failed in a way that says nothing about the name.
     */
    public const UNKNOWN = 'unknown';

    /**
     * @param string $status
     *   One of the constants above.
     * @param list<string> $values
     *   Hostnames from a reverse lookup, or addresses from a forward one.
     * @param string $reason
     *   Why the result is unknown, for logs. Empty otherwise.
     */
    private function __construct(
        public readonly string $status,
        public readonly array $values = [],
        public readonly string $reason = ''
    ) {
    }

    /**
     * Records were found.
     *
     * An empty list is no answer at all, and is reported as one.
     *
     * @param array<array-key, mixed> $values
     *   Hostnames or addresses. Anything that is not a non-empty string is dropped here;
     *   whether a string is a valid hostname or address is the verifier's to decide.
     */
    public static function answer(array $values): self
    {
        $values = array_values(array_filter(
            $values,
            static fn(mixed $value): bool => is_string($value) && $value !== ''
        ));

        return $values === [] ? self::none() : new self(self::ANSWER, $values);
    }

    /**
     * There is no such record.
     */
    public static function none(): self
    {
        return new self(self::NONE);
    }

    /**
     * The lookup could not say either way.
     *
     * @param string $reason
     *   What went wrong, for logs.
     */
    public static function unknown(string $reason): self
    {
        return new self(self::UNKNOWN, [], $reason);
    }

    /**
     * Whether records were found.
     */
    public function isAnswer(): bool
    {
        return $this->status === self::ANSWER;
    }

    /**
     * Whether the lookup could not say either way.
     */
    public function isUnknown(): bool
    {
        return $this->status === self::UNKNOWN;
    }
}
