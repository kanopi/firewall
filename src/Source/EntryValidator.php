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
     * Drop entries that match everybody.
     *
     * A source is the one route by which an entry reaches a block decision
     * without an operator having typed it, and `0.0.0.0/0` in a feed refuses
     * every visitor to the site (#364). `ConfigLinter` already refuses that
     * value when somebody writes it locally and cannot see it here, because
     * linting deliberately does not fetch sources.
     *
     * Separate from `filter()`, which asks whether an entry is well *formed*.
     * `0.0.0.0/0` is a perfectly well-formed CIDR and `validate: cidr` is right
     * to accept it -- there is an existing test saying so. This asks a
     * different question, about what the entry would *do*, and it runs whatever
     * `validate` says including when it says nothing: an unvalidated `txt` feed
     * is the likeliest shape for this to arrive in.
     *
     * The entry is dropped and the rest of the source kept. One bad line
     * should not discard fifty thousand good ones, and `on_error:
     * last_known_good` already covers a source that fails wholesale.
     *
     * ## Why this is not decided by the response bucket
     *
     * `0.0.0.0/0` on an *allow* source is "let everyone through", which is at
     * least arguable. A plugin does not know which bucket it is in --
     * `response:` is read by `PluginConfigNormalizer` and never reaches the
     * instance -- so the refusal cannot be conditioned on it. Refusing by
     * default and letting a source say `allow_catch_all: true` puts the
     * decision where the knowledge is.
     *
     * @param array<int, mixed> $entries
     *   Rendered entries.
     * @param string $sourceName
     *   Source name, for the log line.
     * @param bool $allowCatchAll
     *   Whether this source has declared that it means it.
     *
     * @return array<int, mixed>
     *   The entries that are not catch-alls.
     */
    public function refuseCatchAll(array $entries, string $sourceName, bool $allowCatchAll): array
    {
        if ($allowCatchAll) {
            return $entries;
        }

        $kept = [];
        $refused = [];

        foreach ($entries as $entry) {
            if ((is_string($entry) || is_int($entry)) && $this->matchesEverything((string) $entry)) {
                $refused[] = (string) $entry;
                continue;
            }

            $kept[] = $entry;
        }

        if ($refused !== []) {
            // Error rather than warning. Every other dropped entry is one rule
            // that will not fire; this one would have been every rule firing on
            // every request, and somebody should find it in the log without
            // going looking.
            $this->getLogger()->error('Source entries matching every address were refused', [
                'source' => $sourceName,
                'refused' => $refused,
                'hint' => 'A feed containing 0.0.0.0/0, ::/0 or * would block or allow every '
                    . 'visitor. Set allow_catch_all: true on the source if it is deliberate.',
            ]);
        }

        return $kept;
    }

    /**
     * Whether one entry covers the whole address space.
     *
     * Any prefix of `/0` does, in either family, which is more robust than a
     * list of spellings -- `0/0`, `0.0.0.0/0` and `::/0` are all the same
     * statement and a list would have to enumerate them.
     *
     * @param string $value
     *   The entry.
     *
     * @return bool
     *   TRUE when it matches everything.
     */
    private function matchesEverything(string $value): bool
    {
        $value = strtolower(trim($value));

        if ($value === '*') {
            return true;
        }

        if (str_ends_with($value, '/0')) {
            return true;
        }

        // The range form `IpAddress` also accepts. Only the full span counts;
        // a range that happens to be large is somebody's decision.
        return preg_replace('/\s+/', '', $value) === '0.0.0.0-255.255.255.255';
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
     * Refuse a source whose entries were all thrown away.
     *
     * Separate from `filter()`, and the separation is the point. `filter()`
     * answers "is this entry well formed", one entry at a time, and dropping a
     * bad one while keeping the rest is exactly right -- one malformed line in
     * a 9,000-entry list should not take the other 8,999 with it. There are
     * tests pinning that, and folding this into it broke them, which was the
     * tests being right rather than in the way.
     *
     * This asks a question about the *source*: it decoded to something, and
     * none of it survived. That is not a list with problems, it is not a list.
     * The realistic shape is a CDN or a captive portal answering with an HTML
     * error page, which decodes as `txt` without complaint and yields a few
     * dozen lines that are not addresses (#366).
     *
     * Failing rather than contributing nothing matters because of what nothing
     * does: the rule stops matching, and the only evidence is a warning in a
     * log. Throwing puts it on the `on_error` path, so `last_known_good` keeps
     * the list that was working an hour ago.
     *
     * @param array<int, mixed> $entries
     *   What was offered to the validator.
     * @param array<int, mixed> $kept
     *   What survived it.
     * @param string|null $type
     *   The validator that was applied, or NULL when none was.
     * @param string $sourceName
     *   Source name, for the error message.
     *
     * @throws SourceException
     *   When a non-empty source validated down to nothing.
     */
    public function assertNotEmptied(array $entries, array $kept, ?string $type, string $sourceName): void
    {
        if ($type === null || $entries === [] || $kept !== []) {
            return;
        }

        throw new SourceException(sprintf(
            'Source "%s": every one of its %d entries failed `validate: %s`, so it has nothing to '
            . 'contribute. That is usually an error page where a list should be. First: %s',
            $sourceName,
            count($entries),
            $type,
            implode(', ', array_map(
                static fn(mixed $value): string => is_scalar($value)
                    ? sprintf('"%s"', mb_substr((string) $value, 0, 40))
                    : gettype($value),
                array_slice($entries, 0, 3)
            ))
        ));
    }

    /**
     * Refuse a source contributing more entries than it is allowed to.
     *
     * The neighbour of `max_delta`, asking a different question. `max_delta`
     * bounds how much a list may *change* and needs a previous fetch to compare
     * against, so it says nothing about the first load. This bounds how large a
     * list may *be*, and applies from the first one (#366).
     *
     * Checked on the entries rather than on the decoded records, because
     * entries are what `max_delta` counts, what the cache stores and what the
     * documentation calls them -- one meaning for the word is worth more than
     * the work saved by refusing a little earlier.
     *
     * @param int $count
     *   Entries this load produced.
     * @param int|null $maxEntries
     *   The configured ceiling, or NULL for none.
     * @param string $sourceName
     *   Source name, for the error message.
     *
     * @throws SourceException
     *   When the ceiling is exceeded.
     */
    public function assertEntryCount(int $count, ?int $maxEntries, string $sourceName): void
    {
        if ($maxEntries === null || $count <= $maxEntries) {
            return;
        }

        throw new SourceException(sprintf(
            'Source "%s": produced %d entries, beyond the %d allowed by max_entries. Refusing it '
            . 'rather than using part of a list.',
            $sourceName,
            $count,
            $maxEntries
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
