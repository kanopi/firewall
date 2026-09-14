<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Reputation;

/**
 * What a reputation service said about one address (#204).
 *
 * Three things, because three things are all a firewall can act on:
 *
 * - **A score.** Higher is worse. AbuseIPDB's 0-100 confidence, a home-grown
 *   service's 0-1 probability, a count of recent reports -- the plugin compares
 *   it against a `threshold` and does nothing else with it, so the scale is
 *   whatever the provider's is. Held as a float so a provider scoring 0-1 does
 *   not have to multiply by 100 and lose the distinction between 0.004 and 0.
 * - **Trusted.** A provider's own allow list -- AbuseIPDB's whitelisted flag,
 *   a service that knows its customer's monitoring. It beats the score
 *   outright, because a provider saying "this is known-good infrastructure"
 *   and "this has been reported" at once means the reports are somebody else's
 *   problem.
 * - **Attributes.** Anything else worth putting in a log line: report counts,
 *   a country, a category. Never acted on, only recorded, so a provider can
 *   surface what makes its verdict explainable without this class knowing what
 *   any of it means.
 */
final class ReputationVerdict
{
    /**
     * @param float $score
     *   How bad the address is, on the provider's own scale.
     * @param bool $trusted
     *   Whether the provider vouches for the address, whatever the score.
     * @param array<string, string|int|float|bool> $attributes
     *   Context for the log line, in the provider's own vocabulary.
     */
    public function __construct(
        public readonly float $score,
        public readonly bool $trusted = false,
        public readonly array $attributes = []
    ) {
    }

    /**
     * The verdict as it is cached.
     *
     * @return array<string, mixed>
     *   A JSON-encodable map.
     */
    public function toArray(): array
    {
        return [
            'score' => $this->score,
            'trusted' => $this->trusted,
            'attributes' => $this->attributes,
        ];
    }

    /**
     * Rebuild a verdict from a cache entry.
     *
     * Forgiving on purpose: a cache file is something a deploy can truncate, a
     * disk can fill in the middle of, and an earlier version of this library
     * can have written in another shape. Anything unreadable is a miss, and a
     * miss costs one lookup -- where trusting it costs a wrong verdict.
     *
     * @param mixed $entry
     *   The decoded cache entry.
     *
     * @return self|null
     *   The verdict, or NULL when the entry is not one.
     */
    public static function fromArray(mixed $entry): ?self
    {
        if (!is_array($entry) || !isset($entry['score']) || !is_numeric($entry['score'])) {
            return null;
        }

        $attributes = [];

        if (isset($entry['attributes']) && is_array($entry['attributes'])) {
            foreach ($entry['attributes'] as $key => $value) {
                if (is_string($key) && is_scalar($value)) {
                    $attributes[$key] = $value;
                }
            }
        }

        return new self((float) $entry['score'], (bool) ($entry['trusted'] ?? false), $attributes);
    }
}
