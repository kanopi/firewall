<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Tarpit;

use Kanopi\Firewall\Logging\LoggingTrait;
use Kanopi\Firewall\Storage\ConcurrencyGaugeInterface;

/**
 * Holds a request still for a few seconds, and refuses to hold too many (#329).
 *
 * ## Why the cap is the feature
 *
 * A tarpit costs an attacker throughput by delaying the response. In a
 * synchronous PHP model that means holding a php-fpm worker for the duration --
 * and a worker is a resource the attacker can consume on purpose. With
 * `pm.max_children = 20` and a ten-second tarpit, twenty requests take the site
 * down, and the rule that did it looks like it is working.
 *
 * So the delay is the easy part and the counting is the point. Every hold
 * claims a slot from a `ConcurrencyGaugeInterface` before it sleeps, and a
 * claim that would exceed the cap is given straight back: the request is served
 * normally rather than delayed. **Under attack the tarpit stops tarpitting**,
 * which is the failure the site survives.
 *
 * ## Three things it refuses to do
 *
 * - **Run without an atomic gauge.** A gauge that under-counts admits more
 *   holds than the cap allows, which is the self-DoS again with an extra step.
 *   `Firewall::create()` refuses to start a tarpit rule against a backend that
 *   cannot count, rather than running uncapped.
 * - **Trust a rule's requested duration.** `tarpit.max_seconds` is a ceiling,
 *   because a rule asking for five minutes is asking for a worker held for five
 *   minutes and the operator who wrote it may not have meant that.
 * - **Leak a slot.** Released in a `finally` *and* from a shutdown function,
 *   because the firewall terminates with `exit()` on the paths below this one,
 *   and a slot never given back permanently shrinks the cap.
 */
final class TarpitGate
{
    use LoggingTrait;

    /**
     * Seconds a single hold may last unless configured otherwise.
     */
    public const DEFAULT_MAX_SECONDS = 30;

    /**
     * Holds allowed at once unless configured otherwise.
     *
     * Deliberately small. The number that matters is `pm.max_children`, which
     * this cannot see, and a default that is a large fraction of a small worker
     * pool is the bug this class exists to prevent. Five is safe on the
     * smallest pool anybody runs and is meant to be raised knowingly.
     */
    public const DEFAULT_MAX_CONCURRENT = 5;

    /**
     * The counter key, so one cap covers every tarpit rule.
     *
     * Per-rule counters would let three rules each hold the cap, which is three
     * times the worker pool the operator thought they had capped.
     */
    public const KEY = 'tarpit';

    /**
     * Slots this instance is holding, for the shutdown release.
     */
    private int $held = 0;

    /**
     * Whether the shutdown release has been registered.
     */
    private bool $registered = false;

    /**
     * @param ConcurrencyGaugeInterface $concurrencyGauge
     *   Where holds are counted.
     * @param int $maxConcurrent
     *   Holds allowed at once.
     * @param int $maxSeconds
     *   Ceiling on a single hold's duration.
     */
    public function __construct(
        private readonly ConcurrencyGaugeInterface $concurrencyGauge,
        private readonly int $maxConcurrent = self::DEFAULT_MAX_CONCURRENT,
        private readonly int $maxSeconds = self::DEFAULT_MAX_SECONDS,
    ) {
    }

    /**
     * Delay this request, if there is room to.
     *
     * @param int $seconds
     *   The delay the rule asked for.
     *
     * @return array{held: bool, seconds: int, in_flight: int}
     *   `held` is whether the request was actually delayed; `seconds` how long
     *   for; `in_flight` how many holds were counted including this one, or 0
     *   when the gauge could not answer.
     */
    public function hold(int $seconds): array
    {
        $seconds = $this->clamp($seconds);

        // A slot is claimed before the sleep and the returned count is what
        // decides. Reading first and then claiming is two operations, and the
        // gap between them is exactly where a cap stops holding.
        $inFlight = $this->concurrencyGauge->enter(self::KEY, $seconds + $this->maxSeconds);

        if ($inFlight === 0) {
            // The gauge could not count. Not "nothing is in flight" -- that is
            // why the interface reserves zero -- so the request is served
            // rather than held.
            $this->getLogger()->warning('Tarpit skipped: the concurrency gauge could not answer', [
                'requested_seconds' => $seconds,
            ]);

            return ['held' => false, 'seconds' => 0, 'in_flight' => 0];
        }

        if ($inFlight > $this->maxConcurrent) {
            $this->concurrencyGauge->leave(self::KEY);

            // Warning, not debug: this is the line that says the tarpit stopped
            // tarpitting, which an operator watching an attack needs to see and
            // which looks like nothing at all from the outside.
            $this->getLogger()->warning('Tarpit at capacity; serving the request instead of holding it', [
                'in_flight' => $inFlight - 1,
                'max_concurrent' => $this->maxConcurrent,
            ]);

            return ['held' => false, 'seconds' => 0, 'in_flight' => $inFlight - 1];
        }

        $this->held++;
        $this->registerRelease();

        try {
            $this->sleep($seconds);
        } finally {
            $this->release();
        }

        return ['held' => true, 'seconds' => $seconds, 'in_flight' => $inFlight];
    }

    /**
     * How many holds are counted right now.
     *
     * For reporting only. A cap uses `hold()`, which claims and reads as one
     * operation.
     *
     * @return int
     *   Holds in flight.
     */
    public function inFlight(): int
    {
        return $this->concurrencyGauge->inFlight(self::KEY);
    }

    /**
     * Give back a slot this instance is holding.
     *
     * Safe to call more often than slots were claimed, which is what lets the
     * `finally` and the shutdown function both call it.
     */
    public function release(): void
    {
        if ($this->held <= 0) {
            return;
        }

        $this->held--;
        $this->concurrencyGauge->leave(self::KEY);
    }

    /**
     * Sleep, as a seam.
     *
     * A test that actually waited would be a test suite that waits. Overriding
     * this is how the counting is exercised without the delay.
     *
     * @param int $seconds
     *   How long to wait.
     */
    protected function sleep(int $seconds): void
    {
        // @codeCoverageIgnoreStart
        sleep($seconds);
        // @codeCoverageIgnoreEnd
    }

    /**
     * Arrange for a held slot to be released even if this frame never returns.
     *
     * The firewall terminates with `exit()` on the block and challenge paths,
     * and a fatal ends the process outright. Shutdown functions run in both
     * cases; a `finally` alone does not. A slot never given back permanently
     * shrinks the cap, so the belt and the braces are both worth having.
     */
    private function registerRelease(): void
    {
        if ($this->registered) {
            return;
        }

        $this->registered = true;

        // The method itself rather than a closure around it: a closure body
        // only runs at shutdown, which is after any test that could assert on
        // it, and a line no test can reach is a line nobody is checking.
        register_shutdown_function($this->release(...));
    }

    /**
     * Reduce a requested delay to what is permitted.
     *
     * @param int $seconds
     *   What the rule asked for.
     *
     * @return int
     *   At least one second, at most `tarpit.max_seconds`.
     */
    private function clamp(int $seconds): int
    {
        if ($seconds > $this->maxSeconds) {
            $this->getLogger()->warning('Tarpit rule asks for a longer hold than tarpit.max_seconds allows', [
                'requested_seconds' => $seconds,
                'seconds' => $this->maxSeconds,
            ]);

            return $this->maxSeconds;
        }

        return max(1, $seconds);
    }
}
