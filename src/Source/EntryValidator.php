<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Source;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Logging\LoggingTrait;

/**
 * Asserts that rendered entries look like what the source claimed.
 *
 * This matters most when `upstream` is a URL nobody here controls. A feed that
 * breaks, or is tampered with, otherwise reaches a plugin's rule list intact —
 * emptying a block list, or widening an allow list. `validate` rejects entries
 * of the wrong shape, and `max_delta` rejects a refresh that moved the entry
 * count further than a healthy update ever should.
 */
final class EntryValidator
{
    use LoggingTrait;

    /**
     * Drop entries that do not match the declared shape.
     *
     * Individual bad entries are dropped and logged rather than failing the
     * whole source: one malformed line in a 9,000-entry list should not take
     * the other 8,999 with it.
     *
     * @param array<int, mixed> $entries
     *   Rendered entries.
     * @param string|null $type
     *   One of SourceDefinition::VALIDATORS, or NULL to accept everything.
     * @param string $sourceName
     *   Source name, for log messages.
     *
     * @return array<int, mixed>
     *   The entries that passed, reindexed.
     */
    public function filter(array $entries, ?string $type, string $sourceName): array
    {
        if ($type === null) {
            return array_values($entries);
        }

        $kept = [];
        $rejected = [];

        foreach ($entries as $entry) {
            // Structured entries are rule maps, not values; the scalar
            // validators have nothing to say about them.
            if (is_array($entry)) {
                $kept[] = $entry;
                continue;
            }

            if (!is_string($entry) && !is_int($entry)) {
                $rejected[] = gettype($entry);
                continue;
            }

            $value = (string) $entry;

            if ($this->isValid($value, $type)) {
                $kept[] = $entry;
                continue;
            }

            $rejected[] = $value;
        }

        if ($rejected !== []) {
            $this->getLogger()->warning('Source entries failed validation and were dropped', [
                'source' => $sourceName,
                'validate' => $type,
                'rejected_count' => count($rejected),
                'rejected_sample' => array_slice($rejected, 0, 5),
            ]);
        }

        return $kept;
    }

    /**
     * Reject a refresh whose entry count moved further than allowed.
     *
     * @param int $count
     *   Entry count just produced.
     * @param int|null $previous
     *   Entry count from the last good load, or NULL on a first load.
     * @param float|null $maxDelta
     *   Maximum permitted fractional change, or NULL to skip the check.
     * @param string $sourceName
     *   Source name, for the error message.
     *
     * @throws SourceException
     *   When the change exceeds $maxDelta.
     */
    public function assertDelta(int $count, ?int $previous, ?float $maxDelta, string $sourceName): void
    {
        if ($maxDelta === null || $previous === null || $previous === 0) {
            return;
        }

        $delta = abs($count - $previous) / $previous;

        if ($delta <= $maxDelta) {
            return;
        }

        throw new SourceException(sprintf(
            'Source "%s": entry count moved %.1f%% (%d → %d), beyond the %.1f%% allowed by max_delta.',
            $sourceName,
            $delta * 100,
            $previous,
            $count,
            $maxDelta * 100
        ));
    }

    /**
     * Whether one entry matches a validator.
     *
     * @param string $value
     *   The entry.
     * @param string $type
     *   One of SourceDefinition::VALIDATORS.
     *
     * @return bool
     *   True when the entry is acceptable.
     */
    private function isValid(string $value, string $type): bool
    {
        return match ($type) {
            'ip' => filter_var($value, FILTER_VALIDATE_IP) !== false,
            'cidr' => $this->isAddressExpression($value),
            'regex' => $this->isRegex($value),
            'string' => trim($value) !== '',
            default => true,
        };
    }

    /**
     * Whether a value is an address, a CIDR block, or an address range.
     *
     * Mirrors what the IpAddress plugin actually accepts, so a source declaring
     * `validate: cidr` rejects exactly what that plugin could not have used.
     *
     * @param string $value
     *   The entry.
     *
     * @return bool
     *   True when the expression is a usable address form.
     */
    private function isAddressExpression(string $value): bool
    {
        if (filter_var($value, FILTER_VALIDATE_IP) !== false) {
            return true;
        }

        if (str_contains($value, '/')) {
            [$address, $prefix] = explode('/', $value, 2);

            if (filter_var($address, FILTER_VALIDATE_IP) === false || !ctype_digit($prefix)) {
                return false;
            }

            $bits = filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? 128 : 32;
            $length = (int) $prefix;

            if ($length > $bits) {
                return false;
            }

            if ($length === 0) {
                // /0 covers every address. Legal, essentially never intended,
                // and catastrophic in either an allow or a block list.
                $this->getLogger()->warning('Source entry covers the entire address space', [
                    'entry' => $value,
                ]);
            }

            return true;
        }

        if (str_contains($value, '-')) {
            [$start, $end] = explode('-', $value, 2);

            return filter_var(trim($start), FILTER_VALIDATE_IP) !== false
                && filter_var(trim($end), FILTER_VALIDATE_IP) !== false;
        }

        return false;
    }

    /**
     * Whether a value compiles as a regular expression.
     *
     * @param string $value
     *   The entry.
     *
     * @return bool
     *   True when the pattern compiles.
     */
    private function isRegex(string $value): bool
    {
        if (strlen($value) < 3) {
            return false;
        }

        set_error_handler(static fn (): bool => true);

        try {
            return preg_match($value, '') !== false;
        } finally {
            restore_error_handler();
        }
    }
}
