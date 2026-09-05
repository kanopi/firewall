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
