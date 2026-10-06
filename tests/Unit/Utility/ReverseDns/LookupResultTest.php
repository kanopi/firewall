<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility\ReverseDns;

use Kanopi\Firewall\Utility\ReverseDns\LookupResult;
use Kanopi\Firewall\Utility\ReverseDns\UnusableResolver;
use PHPUnit\Framework\TestCase;

/**
 * The three outcomes a lookup has (#473).
 */
class LookupResultTest extends TestCase
{
    public function testAnAnswerCarriesItsValues(): void
    {
        $lookupResult = LookupResult::answer(['crawl.googlebot.com.', 'other.googlebot.com.']);

        $this->assertTrue($lookupResult->isAnswer());
        $this->assertFalse($lookupResult->isUnknown());
        $this->assertSame(LookupResult::ANSWER, $lookupResult->status);
        $this->assertSame(['crawl.googlebot.com.', 'other.googlebot.com.'], $lookupResult->values);
    }

    public function testAnAnswerKeepsOnlyNonEmptyStrings(): void
    {
        $lookupResult = LookupResult::answer(['', 12, null, ['x'], 'kept']);

        $this->assertSame(['kept'], $lookupResult->values);
    }

    public function testAnAnswerWithNothingInItIsNoRecord(): void
    {
        $lookupResult = LookupResult::answer(['', null]);

        $this->assertFalse($lookupResult->isAnswer());
        $this->assertSame(LookupResult::NONE, $lookupResult->status);
    }

    public function testNoRecordIsNeitherAnAnswerNorUnknown(): void
    {
        $lookupResult = LookupResult::none();

        $this->assertFalse($lookupResult->isAnswer());
        $this->assertFalse($lookupResult->isUnknown());
        $this->assertSame([], $lookupResult->values);
    }

    public function testUnknownCarriesItsReason(): void
    {
        $lookupResult = LookupResult::unknown('HTTP 503');

        $this->assertTrue($lookupResult->isUnknown());
        $this->assertSame('HTTP 503', $lookupResult->reason);
    }

    public function testTheUnusableResolverKnowsNothing(): void
    {
        $unusableResolver = new UnusableResolver('provider "x" is not defined');

        $this->assertSame('provider "x" is not defined', $unusableResolver->reverse('192.0.2.1')->reason);
        $this->assertTrue($unusableResolver->forward('crawl.googlebot.com', 'A')->isUnknown());
    }
}
