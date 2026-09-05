<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Source\RecordFilter;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Tests `where` filtering, which reuses the request conditional-logic engine.
 */
class RecordFilterTest extends AbstractTestCase
{
    /**
     * The filter under test.
     */
    private RecordFilter $filter;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->filter = new RecordFilter();
    }

    /**
     * Records shaped like the AWS ranges document.
     */
    private function records(): array
    {
        return [
            ['ip_prefix' => '3.5.140.0/22', 'region' => 'ap-northeast-2', 'service' => 'S3'],
            ['ip_prefix' => '18.34.32.0/20', 'region' => 'us-east-1', 'service' => 'EC2'],
            ['ip_prefix' => '52.94.76.0/22', 'region' => 'us-west-2', 'service' => 'EC2'],
        ];
    }

    /**
     * No rules keeps everything.
     */
    public function testEmptyRulesKeepEverything(): void
    {
        $this->assertCount(3, $this->filter->filter($this->records(), []));
    }

    /**
     * A single equality rule narrows the set.
     */
    public function testSingleRule(): void
    {
        $kept = $this->filter->filter($this->records(), ['service:EC2']);

        $this->assertCount(2, $kept);
        $this->assertSame('18.34.32.0/20', $kept[0]['ip_prefix']);
    }

    /**
     * Several rules are AND, not OR. This is the opposite of a plugin's
     * `config:` list, where any rule matching is enough, so it is worth
     * pinning down.
     */
    public function testMultipleRulesAreAnded(): void
    {
        $kept = $this->filter->filter($this->records(), ['service:EC2', 'region@starts_with:us-']);

        $this->assertCount(2, $kept);

        $narrower = $this->filter->filter($this->records(), ['service:EC2', 'region:us-east-1']);

        $this->assertCount(1, $narrower);
        $this->assertSame('18.34.32.0/20', $narrower[0]['ip_prefix']);
    }

    /**
     * An explicit OR group is how you widen instead of narrowing.
     */
    public function testExplicitOrGroup(): void
    {
        $kept = $this->filter->filter($this->records(), [
            [
                'type' => 'OR',
                'rules' => ['service:S3', 'region:us-west-2'],
            ],
        ]);

        $this->assertCount(2, $kept);
    }

    /**
     * Operators from the conditional-logic reference work unchanged.
     */
    public function testOperatorsFromConditionalLogic(): void
    {
        $this->assertCount(2, $this->filter->filter($this->records(), ['region@contains:us-']));
        $this->assertCount(1, $this->filter->filter($this->records(), ['service@in:S3,RDS']));
        $this->assertCount(2, $this->filter->filter($this->records(), ['!service:S3']));
    }

    /**
     * A structured rule is accepted alongside the string shorthand.
     */
    public function testStructuredRule(): void
    {
        $kept = $this->filter->filter($this->records(), [
            ['variable' => 'service', 'operator' => 'equals', 'value' => 'EC2'],
        ]);

        $this->assertCount(2, $kept);
    }

    /**
     * A record missing the field simply fails the rule.
     */
    public function testMissingFieldFailsTheRule(): void
    {
        $kept = $this->filter->filter([['other' => 'x']], ['service:EC2']);

        $this->assertSame([], $kept);
    }

    /**
     * Nested fields are reachable by dot path.
     */
    public function testNestedFieldPath(): void
    {
        $kept = $this->filter->filter([
            ['geo' => ['country' => 'US']],
            ['geo' => ['country' => 'CA']],
        ], ['geo.country:US']);

        $this->assertCount(1, $kept);
    }

    /**
     * A scalar record exposes itself as "value", so a text list is filterable.
     */
    public function testScalarRecordsExposeValue(): void
    {
        $kept = $this->filter->filter(['10.0.0.1', '192.168.0.1', '10.0.0.2'], ['value@starts_with:10.']);

        $this->assertSame(['10.0.0.1', '10.0.0.2'], $kept);
    }

    /**
     * Results are reindexed so callers get a clean list.
     */
    public function testResultsAreReindexed(): void
    {
        $kept = $this->filter->filter($this->records(), ['service:EC2']);

        $this->assertSame([0, 1], array_keys($kept));
    }
}
