<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\EntryValidator;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Tests the guardrails that stop a broken feed reaching a plugin's rule list.
 */
class EntryValidatorTest extends AbstractTestCase
{
    /**
     * The validator under test.
     */
    private EntryValidator $validator;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->validator = new EntryValidator();
    }

    /**
     * With no validator declared, everything is accepted.
     */
    public function testNullValidatorAcceptsEverything(): void
    {
        $entries = ['anything', 42, ['a' => 'b']];

        $this->assertSame($entries, $this->validator->filter($entries, null, 'test'));
    }

    /**
     * An entry matching everybody is refused, whatever `validate` says.
     *
     * A source is the one route by which an entry reaches a block decision
     * without an operator having typed it, and `0.0.0.0/0` in a feed refuses
     * every visitor to the site. `ConfigLinter` refuses that value when
     * somebody writes it locally and cannot see it here, because linting
     * deliberately does not fetch sources (#364).
     *
     * `validate` is NULL in this case on purpose: an unvalidated `txt` feed is
     * the likeliest shape for it to arrive in, and a guard that only ran
     * alongside a declared validator would miss it.
     *
     * @param string $entry
     *   The entry as a feed would carry it.
     */
    #[DataProvider('catchAllProvider')]
    public function testAnEntryMatchingEverybodyIsRefused(string $entry): void
    {
        $this->assertSame([], $this->validator->refuseCatchAll([$entry], 'test', false));
    }

    /**
     * @return array<string, array{string}>
     *   Keyed by how a feed would write it.
     */
    public static function catchAllProvider(): array
    {
        return [
            'every IPv4 address' => ['0.0.0.0/0'],
            'the same, abbreviated' => ['0/0'],
            'every IPv6 address' => ['::/0'],
            'a wildcard' => ['*'],
            'padded by the feed' => ['  0.0.0.0/0  '],
            'the full range form' => ['0.0.0.0-255.255.255.255'],
        ];
    }

    /**
     * The rest of the source survives it.
     *
     * One bad line should not discard fifty thousand good ones — and a feed
     * that is dropped wholesale is what `on_error: last_known_good` is for,
     * which is a different failure.
     */
    public function testTheRestOfTheSourceIsKept(): void
    {
        $this->assertSame(
            ['203.0.113.7', '198.51.100.0/24'],
            $this->validator->refuseCatchAll(['0.0.0.0/0', '203.0.113.7', '198.51.100.0/24'], 'test', false)
        );
    }

    /**
     * A source can say it means it.
     *
     * A plugin does not know whether it is in the allow bucket or the block
     * one — `response:` is read by `PluginConfigNormalizer` and never reaches
     * the instance — so the refusal cannot be conditioned on it. `0.0.0.0/0`
     * on an allow source is at least arguable, so the source is where the
     * intent gets declared.
     */
    public function testASourceCanDeclareThatItMeansIt(): void
    {
        $this->assertSame(
            ['0.0.0.0/0'],
            $this->validator->refuseCatchAll(['0.0.0.0/0'], 'test', true)
        );
    }

    /**
     * Addresses that merely look broad are left alone.
     *
     * `/1` is half the internet and somebody's decision; the guard is for the
     * value that cannot be a decision worth honouring.
     */
    public function testABroadButDeliberateRangeIsKept(): void
    {
        $entries = ['0.0.0.0/1', '10.0.0.0/8', '203.0.113.0-203.0.113.255'];

        $this->assertSame($entries, $this->validator->refuseCatchAll($entries, 'test', false));
    }

    /**
     * `validate: cidr` still accepts it, because it is a well-formed CIDR.
     *
     * The two checks answer different questions and this pins the separation:
     * `filter()` is about shape, `refuseCatchAll()` is about effect. Folding
     * the second into the first broke an existing `cidrProvider` case that was
     * asserting something true.
     */
    public function testShapeValidationStillAcceptsACatchAll(): void
    {
        $this->assertSame(['0.0.0.0/0'], $this->validator->filter(['0.0.0.0/0'], 'cidr', 'test'));
    }

    /**
     * The address validator mirrors what the IpAddress plugin can actually use.
     */
    #[DataProvider('cidrProvider')]
    public function testCidrValidator(string $entry, bool $valid): void
    {
        $kept = $this->validator->filter([$entry], 'cidr', 'test');

        $this->assertSame($valid ? [$entry] : [], $kept);
    }

    /**
     * Address expressions and whether each is usable.
     */
    public static function cidrProvider(): array
    {
        return [
            'ipv4' => ['1.2.3.4', true],
            'ipv6' => ['2600:1f01::1', true],
            'ipv4 cidr' => ['10.0.0.0/8', true],
            'ipv6 cidr' => ['2600:1f01::/40', true],
            'range' => ['192.168.1.100-192.168.1.200', true],
            'whole address space' => ['0.0.0.0/0', true],
            'prefix too long for ipv4' => ['10.0.0.0/33', false],
            'prefix too long for ipv6' => ['2600::/129', false],
            'non-numeric prefix' => ['10.0.0.0/x', false],
            'not an address' => ['example.com', false],
            'empty' => ['', false],
            'partial range' => ['192.168.1.1-', false],
        ];
    }

    /**
     * The ip validator refuses anything with a prefix or range.
     */
    public function testIpValidatorRejectsBlocks(): void
    {
        $this->assertSame(['1.2.3.4'], $this->validator->filter(['1.2.3.4', '10.0.0.0/8'], 'ip', 'test'));
    }

    /**
     * The regex validator keeps patterns that compile.
     */
    public function testRegexValidator(): void
    {
        $kept = $this->validator->filter(['/^abc$/i', '/unterminated', 'ab'], 'regex', 'test');

        $this->assertSame(['/^abc$/i'], $kept);
    }

    /**
     * The string validator only drops blanks.
     */
    public function testStringValidator(): void
    {
        $this->assertSame(['a'], $this->validator->filter(['a', '   ', ''], 'string', 'test'));
    }

    /**
     * One malformed entry is dropped without taking the rest with it.
     */
    public function testBadEntriesDoNotDiscardGoodOnes(): void
    {
        $kept = $this->validator->filter(['1.2.3.4', 'nonsense', '5.6.7.8'], 'cidr', 'test');

        $this->assertSame(['1.2.3.4', '5.6.7.8'], $kept);
    }

    /**
     * Structured entries are rule maps, which the scalar validators do not
     * judge, so they pass through.
     */
    public function testStructuredEntriesArePassedThrough(): void
    {
        $entry = ['type' => 'AND', 'rules' => ['a:b']];

        $this->assertSame([$entry], $this->validator->filter([$entry], 'cidr', 'test'));
    }

    /**
     * A first load has nothing to compare against, so the delta check is inert.
     */
    public function testDeltaSkippedOnFirstLoad(): void
    {
        $this->expectNotToPerformAssertions();

        $this->validator->assertDelta(10, null, 0.25, 'test');
    }

    /**
     * A change inside the allowance is accepted.
     */
    public function testDeltaWithinAllowance(): void
    {
        $this->expectNotToPerformAssertions();

        $this->validator->assertDelta(110, 100, 0.25, 'test');
    }

    /**
     * A collapse beyond the allowance is rejected — this is the case that
     * stops an emptied upstream from silently emptying a rule list.
     */
    public function testDeltaCollapseRejected(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('max_delta');

        $this->validator->assertDelta(3, 9000, 0.25, 'aws');
    }

    /**
     * A sudden explosion is rejected too.
     */
    public function testDeltaGrowthRejected(): void
    {
        $this->expectException(SourceException::class);

        $this->validator->assertDelta(500, 100, 0.5, 'test');
    }

    /**
     * With no allowance declared, any change is accepted.
     */
    public function testDeltaSkippedWithoutAllowance(): void
    {
        $this->expectNotToPerformAssertions();

        $this->validator->assertDelta(0, 9000, null, 'test');
    }
}
