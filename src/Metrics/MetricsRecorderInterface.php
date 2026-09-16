<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Metrics;

/**
 * Somewhere to put a number (#222).
 *
 * Deliberately two methods. An exporter interface grows histograms, summaries,
 * timers and quantiles if you let it, and each one is a thing every
 * implementation then has to support or fake. Counters and gauges answer the
 * questions the issue actually lists, and anything richer is a backend's job
 * rather than this library's.
 *
 * **Nothing here may affect a request.** A recorder is called from a PSR-14
 * listener, on the request path, after a decision has been made. It must not
 * throw, must not block, and must not wait for a remote service to answer.
 * `Firewall::announce()` catches a listener that throws, which stops an
 * exception becoming an outage -- but nothing catches a socket that hangs, so
 * an implementation that could hang is a slow site rather than a failed one,
 * and the failed one is easier to notice.
 */
interface MetricsRecorderInterface
{
    /**
     * Add to a counter.
     *
     * @param string $metric
     *   One of the `Metric` constants.
     * @param array<string, string> $labels
     *   Label name to value. Every value must come from a bounded set.
     * @param int $by
     *   How much to add. Usually 1.
     */
    public function increment(string $metric, array $labels = [], int $by = 1): void;

    /**
     * Set a gauge to a value.
     *
     * A number that goes up and down and is meaningful at any instant, rather
     * than one that only means something as a rate. "How many of these are in
     * flight right now" is the question, and it is the one the tarpit
     * concurrency cap (#329) asks as well.
     *
     * @param string $metric
     *   The metric name.
     * @param array<string, string> $labels
     *   Label name to value. Every value must come from a bounded set.
     * @param float $value
     *   The current value.
     */
    public function gauge(string $metric, array $labels = [], float $value = 0.0): void;
}
