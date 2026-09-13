<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Reputation;

use Kanopi\Firewall\Reputation\ReputationVerdict;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * What a provider said, and what survives a round trip through the cache (#204).
 */
final class ReputationVerdictTest extends AbstractTestCase
{
    /**
     * A verdict comes back out of the cache as it went in.
     */
    public function testAVerdictSurvivesTheCache(): void
    {
        $verdict = new ReputationVerdict(87.5, true, ['total_reports' => 42, 'country_code' => 'RU']);
        $restored = ReputationVerdict::fromArray($verdict->toArray());

        $this->assertInstanceOf(ReputationVerdict::class, $restored);
        $this->assertSame(87.5, $restored->score);
        $this->assertTrue($restored->trusted);
        $this->assertSame(['total_reports' => 42, 'country_code' => 'RU'], $restored->attributes);
    }

    /**
     * A score below one still means something.
     *
     * The reason the score is a float: a provider scoring 0-1 would otherwise
     * have every verdict under 1.0 collapse to zero, and "0.94 probability of
     * abuse" would read as clean.
     */
    public function testAFractionalScoreIsNotRoundedAway(): void
    {
        $restored = ReputationVerdict::fromArray(['score' => 0.94]);

        $this->assertInstanceOf(ReputationVerdict::class, $restored);
        $this->assertSame(0.94, $restored->score);
    }

    /**
     * Anything that is not a verdict is a miss, and a miss costs one lookup.
     *
     * A cache file is something a deploy can truncate and a full disk can cut
     * in half. Trusting a half-written one costs a wrong verdict, which is the
     * more expensive mistake.
     *
     * @param mixed $entry
     *   The decoded cache entry.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('unusableEntries')]
    public function testAnUnusableEntryIsAMiss(mixed $entry): void
    {
        $this->assertNull(ReputationVerdict::fromArray($entry));
    }

    /**
     * @return array<string, array{mixed}>
     *   Keyed by what is wrong with it.
     */
    public static function unusableEntries(): array
    {
        return [
            'null' => [null],
            'a string' => ['87'],
            'no score' => [['trusted' => true]],
            'a score that is not a number' => [['score' => 'high']],
        ];
    }

    /**
     * Attributes are log context, so only what can be written to a log survives.
     *
     * A provider returning a nested structure would otherwise put it in every
     * log line the verdict reaches, where it is unreadable and, for a response
     * that echoes back a request header, potentially sensitive.
     */
    public function testOnlyScalarAttributesSurvive(): void
    {
        $restored = ReputationVerdict::fromArray([
            'score' => 10,
            'attributes' => ['country_code' => 'RU', 'raw' => ['nested' => 'structure'], 7 => 'positional'],
        ]);

        $this->assertInstanceOf(ReputationVerdict::class, $restored);
        $this->assertSame(['country_code' => 'RU'], $restored->attributes);
    }

    /**
     * The defaults are the quiet case: a score and nothing else.
     */
    public function testAVerdictIsJustAScoreUnlessItSaysOtherwise(): void
    {
        $verdict = new ReputationVerdict(12.0);

        $this->assertFalse($verdict->trusted);
        $this->assertSame([], $verdict->attributes);
    }
}
