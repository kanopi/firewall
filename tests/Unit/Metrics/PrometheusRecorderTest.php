<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Metrics;

use Kanopi\Firewall\Metrics\Metric;
use Kanopi\Firewall\Metrics\PrometheusRecorder;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Accumulating metrics and rendering them for a scrape (#222).
 */
class PrometheusRecorderTest extends AbstractTestCase
{
    public function testCountersAccumulateAndRenderWithTheirType(): void
    {
        $recorder = new PrometheusRecorder();

        $recorder->increment(Metric::REQUESTS, ['decision' => 'blocked', 'rule' => 'bad-ips']);
        $recorder->increment(Metric::REQUESTS, ['decision' => 'blocked', 'rule' => 'bad-ips']);
        $recorder->increment(Metric::REQUESTS, ['decision' => 'allowed', 'rule' => 'none']);

        $this->assertSame(
            "# TYPE firewall_requests_total counter\n"
            . "firewall_requests_total{decision=\"blocked\",rule=\"bad-ips\"} 2\n"
            . "firewall_requests_total{decision=\"allowed\",rule=\"none\"} 1\n",
            $recorder->render()
        );
    }

    /**
     * Label order must not create two series for one thing. A dispatcher that
     * happens to build the array differently would otherwise split a counter in
     * half and neither half would be wrong.
     */
    public function testLabelOrderDoesNotSplitASeries(): void
    {
        $recorder = new PrometheusRecorder();

        $recorder->increment(Metric::REQUESTS, ['rule' => 'bad-ips', 'decision' => 'blocked']);
        $recorder->increment(Metric::REQUESTS, ['decision' => 'blocked', 'rule' => 'bad-ips']);

        $this->assertStringContainsString('} 2', $recorder->render());
        $this->assertSame(1, substr_count($recorder->render(), 'firewall_requests_total{'));
    }

    public function testAGaugeReplacesRatherThanAccumulates(): void
    {
        $recorder = new PrometheusRecorder();

        $recorder->gauge('firewall_tarpit_in_flight', [], 4.0);
        $recorder->gauge('firewall_tarpit_in_flight', [], 2.0);

        $this->assertSame(
            "# TYPE firewall_tarpit_in_flight gauge\nfirewall_tarpit_in_flight 2\n",
            $recorder->render()
        );
    }

    public function testAPrefixKeepsTwoInstallationsApartOnOneTarget(): void
    {
        $recorder = new PrometheusRecorder('site_a_');

        $recorder->increment(Metric::REQUESTS, ['decision' => 'blocked']);

        $this->assertStringContainsString('site_a_firewall_requests_total{decision="blocked"} 1', $recorder->render());
    }

    public function testNothingRecordedRendersNothing(): void
    {
        $this->assertSame('', (new PrometheusRecorder())->render());
    }

    /**
     * An unescaped quote or backslash does not spoil one label, it spoils the
     * parse of every line after it.
     */
    public function testLabelValuesAreEscaped(): void
    {
        $recorder = new PrometheusRecorder();

        $recorder->increment(Metric::REQUESTS, ['rule' => 'a "quoted" \\ rule' . "\n" . 'second line']);

        $this->assertStringContainsString('rule="a \"quoted\" \\\\ rule\nsecond line"', $recorder->render());
    }

    public function testAWholeValueRendersAsACountRatherThanAFloat(): void
    {
        $recorder = new PrometheusRecorder();

        $recorder->increment(Metric::REQUESTS, [], 3);
        $recorder->gauge('firewall_ratio', [], 0.5);

        $this->assertStringContainsString('firewall_requests_total 3', $recorder->render());
        $this->assertStringContainsString('firewall_ratio 0.5', $recorder->render());
    }

    /**
     * The mistake a *host* can make by using these recorders for metrics of its
     * own. Bucketed rather than dropped: a series that stops incrementing looks
     * like traffic that stopped.
     */
    public function testSeriesAreCappedAndTheRestBucketed(): void
    {
        $recorder = new PrometheusRecorder('', 2);

        foreach (range(1, 6) as $i) {
            $recorder->increment(Metric::REQUESTS, ['path' => '/page-' . $i]);
        }

        $rendered = $recorder->render();

        $this->assertSame(3, substr_count($rendered, 'firewall_requests_total{'));
        $this->assertStringContainsString('{overflow="other"} 4', $rendered);
    }

    public function testTheCapCanBeTurnedOff(): void
    {
        $recorder = new PrometheusRecorder('', 0);

        foreach (range(1, 6) as $i) {
            $recorder->increment(Metric::REQUESTS, ['path' => '/page-' . $i]);
        }

        $this->assertSame(6, substr_count($recorder->render(), 'firewall_requests_total{'));
    }

    /**
     * Counters add and gauges replace. Two workers that each saw 40 requests
     * saw 80; the sum of two readings of "how many are in flight" is not a
     * number about anything.
     */
    public function testASnapshotAddsCountersAndReplacesGauges(): void
    {
        $first = new PrometheusRecorder();
        $first->increment(Metric::REQUESTS, ['decision' => 'blocked'], 40);
        $first->gauge('firewall_in_flight', [], 3.0);

        $second = new PrometheusRecorder();
        $second->increment(Metric::REQUESTS, ['decision' => 'blocked'], 40);
        $second->gauge('firewall_in_flight', [], 7.0);

        $second->load($first->snapshot());
        $rendered = $second->render();

        $this->assertStringContainsString('firewall_requests_total{decision="blocked"} 80', $rendered);
        $this->assertStringContainsString('firewall_in_flight 3', $rendered);
    }

    public function testLoadingIntoAnEmptyRecorderRestoresIt(): void
    {
        $first = new PrometheusRecorder();
        $first->increment(Metric::REQUESTS, ['decision' => 'blocked'], 5);

        $second = new PrometheusRecorder();
        $second->load($first->snapshot());

        $this->assertSame($first->render(), $second->render());
    }

    /**
     * Read back from a store that may hold an older shape, so anything
     * unrecognised is ignored rather than fatal.
     *
     * @param array<string, mixed> $snapshot
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('unusableSnapshotProvider')]
    public function testAnUnusableSnapshotIsIgnoredRatherThanFatal(array $snapshot): void
    {
        $recorder = new PrometheusRecorder();
        $recorder->load($snapshot);

        $this->assertSame('', $recorder->render());
    }

    /**
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function unusableSnapshotProvider(): array
    {
        return [
            'empty' => [[]],
            'wrong top-level type' => [['counters' => 'nope', 'gauges' => 12]],
            'metric name is not a string' => [['counters' => [['labels' => [], 'value' => 1]]]],
            'series is not an array' => [['counters' => ['m' => 'nope']]],
            'series key is not a string' => [['counters' => ['m' => [['labels' => [], 'value' => 1]]]]],
            'entry is not an array' => [['counters' => ['m' => ['k' => 'nope']]]],
            'labels are not an array' => [['counters' => ['m' => ['k' => ['labels' => 'nope', 'value' => 1]]]]],
            'value is not a number' => [['counters' => ['m' => ['k' => ['labels' => [], 'value' => 'nope']]]]],
        ];
    }

    /**
     * A label value that was not a scalar when it went into the store cannot
     * become one coming out, and must not become "Array".
     */
    public function testANonScalarLabelInASnapshotBecomesEmptyRatherThanNoise(): void
    {
        $recorder = new PrometheusRecorder();
        $recorder->load(['counters' => ['m' => ['k' => ['labels' => ['rule' => ['a']], 'value' => 1]]]]);

        $this->assertStringContainsString('m{rule=""} 1', $recorder->render());
    }
}
