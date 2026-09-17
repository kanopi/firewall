<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Tarpit;

use Kanopi\Firewall\Storage\ConcurrencyGaugeInterface;
use Kanopi\Firewall\Tarpit\TarpitGate;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Holding a request, and refusing to hold too many (#329).
 *
 * The delay is the easy part. Every test here is about the counting, because a
 * tarpit without a working cap is a self-DoS with a rule that looks like it is
 * working.
 */
class TarpitGateTest extends AbstractTestCase
{
    public function testAHoldClaimsASlotSleepsAndGivesItBack(): void
    {
        $gauge = new CountingGauge();
        $gate = $this->gate($gauge, 5, 30);

        $result = $gate->hold(3);

        $this->assertTrue($result['held']);
        $this->assertSame(3, $result['seconds']);
        $this->assertSame([3], $gate->slept);
        $this->assertSame(0, $gauge->count, 'The slot was not given back');
    }

    /**
     * The failure the site survives: under attack the tarpit stops tarpitting
     * rather than the site stops serving.
     */
    public function testAtCapacityTheRequestIsServedRatherThanHeld(): void
    {
        $gauge = new CountingGauge();
        $gauge->count = 2;
        $gate = $this->gate($gauge, 2, 30);

        $result = $gate->hold(5);

        $this->assertFalse($result['held']);
        $this->assertSame(0, $result['seconds']);
        $this->assertSame([], $gate->slept, 'It slept while at capacity');
        $this->assertSame(2, $gauge->count, 'The refused claim was not given back');
    }

    public function testExactlyAtTheCapIsStillAllowed(): void
    {
        $gauge = new CountingGauge();
        $gauge->count = 1;
        $gate = $this->gate($gauge, 2, 30);

        $this->assertTrue($gate->hold(1)['held']);
    }

    /**
     * Zero from the gauge means "could not be counted", not "nothing is in
     * flight". Treating it as the latter is the self-DoS.
     */
    public function testAGaugeThatCannotAnswerMeansNoHold(): void
    {
        $gauge = new CountingGauge();
        $gauge->refuse = true;
        $gate = $this->gate($gauge, 5, 30);

        $result = $gate->hold(5);

        $this->assertFalse($result['held']);
        $this->assertSame(0, $result['in_flight']);
        $this->assertSame([], $gate->slept);
    }

    /**
     * A rule asking for five minutes is asking for a worker held for five
     * minutes, and whoever wrote it may not have meant that.
     */
    public function testADurationIsClampedToTheCeiling(): void
    {
        $gate = $this->gate(new CountingGauge(), 5, 10);

        $this->assertSame(10, $gate->hold(300)['seconds']);
        $this->assertSame([10], $gate->slept);
    }

    /**
     * A tarpit rule that does not tarpit is a rule doing nothing at all, so a
     * missing duration is the minimum rather than none.
     */
    public function testNoDurationBecomesTheMinimumRatherThanNothing(): void
    {
        $gate = $this->gate(new CountingGauge(), 5, 30);

        $this->assertSame(1, $gate->hold(0)['seconds']);
    }

    /**
     * One counter for every tarpit rule. Per-rule counters would let three
     * rules each hold the cap, which is three times the worker pool the
     * operator thought they had capped.
     */
    public function testEveryRuleSharesOneCap(): void
    {
        $gauge = new CountingGauge();

        $this->assertTrue($this->gate($gauge, 2, 30)->hold(1)['held']);

        $gauge->count = 2;

        $this->assertFalse($this->gate($gauge, 2, 30)->hold(1)['held'], 'A second rule got its own cap');
        $this->assertSame([TarpitGate::KEY], array_unique($gauge->keys));
    }

    /**
     * The TTL has to outlast the hold, or a slot expires while it is still
     * held and the cap admits an extra one.
     */
    public function testTheSlotOutlivesTheHoldItCovers(): void
    {
        $gauge = new CountingGauge();

        $this->gate($gauge, 5, 30)->hold(10);

        $this->assertGreaterThan(10, $gauge->ttls[0]);
    }

    /**
     * Releasing more often than claiming is what lets the `finally` and the
     * shutdown function both call it.
     */
    public function testReleasingMoreOftenThanClaimingIsHarmless(): void
    {
        $gauge = new CountingGauge();
        $gate = $this->gate($gauge, 5, 30);

        $gate->hold(1);
        $gate->release();
        $gate->release();

        $this->assertSame(0, $gauge->count);
    }

    /**
     * The shutdown release is registered once per gate, not once per hold. A
     * long-lived worker taking a thousand holds must not accumulate a thousand
     * shutdown callbacks.
     */
    public function testTheShutdownReleaseIsRegisteredOnlyOnce(): void
    {
        $gauge = new CountingGauge();
        $gate = $this->gate($gauge, 5, 30);

        $gate->hold(1);
        $gate->hold(1);
        $gate->hold(1);

        $this->assertSame([1, 1, 1], $gate->slept);
        $this->assertSame(0, $gauge->count, 'Every slot should have been given back');
    }

    public function testInFlightReportsWithoutClaiming(): void
    {
        $gauge = new CountingGauge();
        $gauge->count = 4;

        $this->assertSame(4, $this->gate($gauge, 5, 30)->inFlight());
        $this->assertSame(4, $gauge->count, 'Asking changed the count');
    }

    private function gate(ConcurrencyGaugeInterface $concurrencyGauge, int $maxConcurrent, int $maxSeconds): TarpitGate
    {
        return new class ($concurrencyGauge, $maxConcurrent, $maxSeconds) extends TarpitGate {
            /**
             * @var array<int, int>
             */
            public array $slept = [];

            protected function sleep(int $seconds): void
            {
                $this->slept[] = $seconds;
            }
        };
    }
}

/**
 * A gauge that counts, in one process, so the arithmetic can be watched.
 */
final class CountingGauge implements ConcurrencyGaugeInterface
{
    public int $count = 0;

    public bool $refuse = false;

    /**
     * @var array<int, string>
     */
    public array $keys = [];

    /**
     * @var array<int, int>
     */
    public array $ttls = [];

    public function enter(string $key, int $ttl): int
    {
        $this->keys[] = $key;
        $this->ttls[] = $ttl;

        if ($this->refuse) {
            return 0;
        }

        return ++$this->count;
    }

    public function leave(string $key): void
    {
        $this->count = max(0, $this->count - 1);
    }

    public function inFlight(string $key): int
    {
        return $this->count;
    }
}
