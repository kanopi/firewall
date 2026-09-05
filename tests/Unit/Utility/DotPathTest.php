<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\DotPath;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Tests the shared dot-path selector.
 */
class DotPathTest extends AbstractTestCase
{
    /**
     * Sample shaped like the AWS ranges document.
     */
    private function awsFixture(): array
    {
        return [
            'syncToken' => '1700000000',
            'prefixes' => [
                ['ip_prefix' => '3.5.140.0/22', 'region' => 'ap-northeast-2', 'service' => 'S3'],
                ['ip_prefix' => '18.34.32.0/20', 'region' => 'us-east-1', 'service' => 'EC2'],
            ],
            'ipv6_prefixes' => [
                ['ipv6_prefix' => '2600:1f01::/40', 'region' => 'us-east-1', 'service' => 'EC2'],
            ],
        ];
    }

    /**
     * A literal path reads a single nested value.
     */
    public function testLiteralPath(): void
    {
        $this->assertSame(['1700000000'], DotPath::values($this->awsFixture(), 'syncToken'));
    }

    /**
     * A wildcard segment matches every key at its depth.
     */
    public function testWildcardMatchesEveryKey(): void
    {
        $values = DotPath::values($this->awsFixture(), 'prefixes.*.ip_prefix');

        $this->assertSame(['3.5.140.0/22', '18.34.32.0/20'], $values);
    }

    /**
     * Brace alternation selects several named collections at once.
     */
    public function testBraceAlternationSpansCollections(): void
    {
        $records = DotPath::values($this->awsFixture(), '{prefixes,ipv6_prefixes}.*');

        $this->assertCount(3, $records);
        $this->assertSame('3.5.140.0/22', $records[0]['ip_prefix']);
        $this->assertSame('2600:1f01::/40', $records[2]['ipv6_prefix']);
    }

    /**
     * Pipe and parenthesised alternation mean the same thing as braces.
     */
    #[DataProvider('alternationSyntaxProvider')]
    public function testAlternationSyntaxesAreEquivalent(string $pattern): void
    {
        $this->assertCount(3, DotPath::values($this->awsFixture(), $pattern));
    }

    /**
     * Every accepted spelling of the same alternation.
     */
    public static function alternationSyntaxProvider(): array
    {
        return [
            'braces' => ['{prefixes,ipv6_prefixes}.*'],
            'pipes' => ['prefixes|ipv6_prefixes.*'],
            'parens' => ['(prefixes|ipv6_prefixes).*'],
        ];
    }

    /**
     * A segment matching nothing yields no results rather than an error.
     */
    public function testUnmatchedSegmentYieldsNothing(): void
    {
        $this->assertSame([], DotPath::values($this->awsFixture(), 'prefixes.*.missing'));
        $this->assertSame([], DotPath::values($this->awsFixture(), 'nope.*'));
    }

    /**
     * Descending into a scalar prunes that branch instead of failing.
     */
    public function testCannotDescendIntoScalar(): void
    {
        $this->assertSame([], DotPath::values(['a' => 'string'], 'a.b'));
    }

    /**
     * Expansion reports the path it took as well as the value.
     */
    public function testExpandReturnsPaths(): void
    {
        $matches = DotPath::expand(['a' => ['b' => 'c']], 'a.b');

        $this->assertSame([['a', 'b'], 'c'], $matches[0]);
    }

    /**
     * first() reads one value with a fallback.
     */
    public function testFirstFallsBackWhenAbsent(): void
    {
        $this->assertSame('c', DotPath::first(['a' => ['b' => 'c']], 'a.b'));
        $this->assertSame('fallback', DotPath::first(['a' => []], 'a.b', 'fallback'));
    }

    /**
     * Segment tokens expand to the alternatives they declare.
     */
    #[DataProvider('alternativesProvider')]
    public function testAlternatives(string $token, array $expected): void
    {
        $this->assertSame($expected, DotPath::alternatives($token));
    }

    /**
     * Token spellings and what each expands to.
     */
    public static function alternativesProvider(): array
    {
        return [
            'wildcard' => ['*', ['*']],
            'literal' => ['service', ['service']],
            'braces' => ['{a,b}', ['a', 'b']],
            'pipes' => ['a|b', ['a', 'b']],
            'parens' => ['(a|b)', ['a', 'b']],
            'padded' => ['{ a , b }', ['a', 'b']],
            'empties dropped' => ['{a,,b}', ['a', 'b']],
        ];
    }

    /**
     * Wildcards work over list indexes, not just string keys.
     */
    public function testWildcardOverList(): void
    {
        $this->assertSame([1, 2, 3], DotPath::values([1, 2, 3], '*'));
    }
}
