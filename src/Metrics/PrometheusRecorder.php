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
 * Accumulates metrics and renders them in Prometheus exposition format (#222).
 *
 * ## Read this before choosing it
 *
 * Prometheus scrapes; PHP, classically, forgets. Under PHP-FPM every request is
 * a fresh process, so a counter incremented during a request is gone before
 * anything can scrape it, and a scrape lands in a process that has seen almost
 * nothing. That is not a limitation of this class, it is the execution model,
 * and every PHP Prometheus client works around it with shared memory or a
 * shared store.
 *
 * So:
 *
 * | Deployment | What to use |
 * |---|---|
 * | PHP-FPM, mod_php, classic share-nothing | `StatsdRecorder`. Push, do not scrape |
 * | A long-lived worker — RoadRunner, Swoole, FrankenPHP | This, held across requests |
 * | Anything else | This, plus your own shared store around `snapshot()` / `load()` |
 *
 * `snapshot()` and `load()` exist for the third row: hand the array to APCu, a
 * file, or whatever the deployment already has, and hand it back on the next
 * process. They are deliberately plain arrays rather than an interface, because
 * the right store is entirely the host's business and anything this library
 * picked would be wrong somewhere.
 *
 * ## It cannot run an endpoint, and should not
 *
 * `render()` produces the text; serving it at `/metrics` is the host's routing,
 * authentication and access control. A library that opened a port would be a
 * library that opened a port on somebody's firewall host.
 */
final class PrometheusRecorder implements MetricsRecorderInterface
{
    /**
     * Counter totals, keyed by metric name and serialised labels.
     *
     * @var array<string, array<string, array{labels: array<string, string>, value: float}>>
     */
    private array $counters = [];

    /**
     * Gauge values, in the same shape.
     *
     * @var array<string, array<string, array{labels: array<string, string>, value: float}>>
     */
    private array $gauges = [];

    /**
     * Distinct label sets admitted per metric before the rest are bucketed.
     *
     * The listener caps the `rule` label already, which covers the mistake this
     * library can make. This covers the one a *host* can make by using these
     * recorders for metrics of its own, and it is the difference between a
     * mistake costing a vague graph and costing the scrape target.
     */
    public const DEFAULT_SERIES_LIMIT = 2000;

    /**
     * @param string $prefix
     *   Prepended to every metric name, for installations sharing a scrape
     *   target.
     * @param int $seriesLimit
     *   Distinct label sets to admit per metric. Zero removes the cap.
     */
    public function __construct(
        private readonly string $prefix = '',
        private readonly int $seriesLimit = self::DEFAULT_SERIES_LIMIT,
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function increment(string $metric, array $labels = [], int $by = 1): void
    {
        $this->write($this->counters, $metric, $labels, static fn(float $current): float => $current + $by);
    }

    /**
     * {@inheritdoc}
     */
    public function gauge(string $metric, array $labels = [], float $value = 0.0): void
    {
        $this->write($this->gauges, $metric, $labels, static fn(float $current): float => $value);
    }

    /**
     * Everything recorded, in Prometheus exposition format.
     *
     * @return string
     *   Text ready to serve as `text/plain; version=0.0.4`.
     */
    public function render(): string
    {
        $lines = [];

        foreach ([['counter', $this->counters], ['gauge', $this->gauges]] as [$type, $metrics]) {
            foreach ($metrics as $metric => $series) {
                $lines[] = sprintf('# TYPE %s %s', $this->prefix . $metric, $type);

                foreach ($series as $entry) {
                    $lines[] = $this->prefix . $metric . $this->renderLabels($entry['labels'])
                        . ' ' . $this->renderValue($entry['value']);
                }
            }
        }

        return $lines === [] ? '' : implode("\n", $lines) . "\n";
    }

    /**
     * Everything recorded, as an array a host can persist.
     *
     * @return array{counters: array<string, mixed>, gauges: array<string, mixed>}
     *   The accumulated state.
     */
    public function snapshot(): array
    {
        return ['counters' => $this->counters, 'gauges' => $this->gauges];
    }

    /**
     * Restore a snapshot, adding counters and replacing gauges.
     *
     * Counters add because that is what a counter means: two workers that each
     * saw 40 requests saw 80, and taking the larger would lose half of them.
     * Gauges replace because a gauge is a reading at an instant, and the sum of
     * two readings of "how many are in flight" is not a number about anything.
     *
     * @param array<string, mixed> $snapshot
     *   A snapshot from `snapshot()`. Anything unrecognised is ignored rather
     *   than fatal: this is read back from a store that may hold an older shape.
     */
    public function load(array $snapshot): void
    {
        foreach ($this->series($snapshot, 'counters') as $metric => $series) {
            foreach ($series as $key => $entry) {
                $this->counters[$metric][$key] = [
                    'labels' => $entry['labels'],
                    'value' => ($this->counters[$metric][$key]['value'] ?? 0.0) + $entry['value'],
                ];
            }
        }

        foreach ($this->series($snapshot, 'gauges') as $metric => $series) {
            foreach ($series as $key => $entry) {
                $this->gauges[$metric][$key] = $entry;
            }
        }
    }

    /**
     * Read one half of a snapshot, keeping only entries in the right shape.
     *
     * @param array<string, mixed> $snapshot
     *   The snapshot.
     * @param string $key
     *   `counters` or `gauges`.
     *
     * @return array<string, array<string, array{labels: array<string, string>, value: float}>>
     *   The usable entries.
     */
    private function series(array $snapshot, string $key): array
    {
        $found = [];

        foreach (is_array($snapshot[$key] ?? null) ? $snapshot[$key] : [] as $metric => $series) {
            if (!is_string($metric)) {
                continue;
            }

            if (!is_array($series)) {
                continue;
            }

            foreach ($series as $seriesKey => $entry) {
                if (!is_string($seriesKey)) {
                    continue;
                }

                if (!is_array($entry)) {
                    continue;
                }

                if (!is_array($entry['labels'] ?? null)) {
                    continue;
                }

                if (!is_numeric($entry['value'] ?? null)) {
                    continue;
                }

                $labels = [];

                foreach ($entry['labels'] as $label => $value) {
                    $labels[(string) $label] = is_scalar($value) ? (string) $value : '';
                }

                $found[$metric][$seriesKey] = ['labels' => $labels, 'value' => (float) $entry['value']];
            }
        }

        return $found;
    }

    /**
     * Record a value against a metric and label set.
     *
     * @param array<string, array<string, array{labels: array<string, string>, value: float}>> $into
     *   The counter or gauge store, by reference.
     * @param string $metric
     *   The metric name.
     * @param array<string, string> $labels
     *   Label name to value.
     * @param callable(float): float $combine
     *   How the new value relates to the one already there.
     */
    private function write(array &$into, string $metric, array $labels, callable $combine): void
    {
        ksort($labels);
        $key = $this->seriesKey($labels);

        if (!isset($into[$metric][$key]) && $this->seriesLimit > 0 && count($into[$metric] ?? []) >= $this->seriesLimit) {
            // Bucketed rather than dropped, for the same reason the listener
            // buckets an over-limit rule: a series that stops incrementing looks
            // like traffic that stopped.
            $labels = ['overflow' => Metric::OVERFLOW];
            $key = $this->seriesKey($labels);
        }

        $into[$metric][$key] = [
            'labels' => $labels,
            'value' => $combine($into[$metric][$key]['value'] ?? 0.0),
        ];
    }

    /**
     * A stable identity for one label set.
     *
     * @param array<string, string> $labels
     *   Label name to value, already sorted.
     *
     * @return string
     *   The key.
     */
    private function seriesKey(array $labels): string
    {
        return (string) json_encode($labels);
    }

    /**
     * Render a label set as Prometheus writes it.
     *
     * @param array<string, string> $labels
     *   Label name to value.
     *
     * @return string
     *   `{a="1",b="2"}`, or an empty string when there are none.
     */
    private function renderLabels(array $labels): string
    {
        if ($labels === []) {
            return '';
        }

        $pairs = [];

        foreach ($labels as $label => $value) {
            // Backslash, quote and newline are the three the format escapes.
            // An unescaped one does not spoil a label, it spoils the parse of
            // every line after it.
            $pairs[] = $label . '="' . str_replace(['\\', '"', "\n"], ['\\\\', '\\"', '\\n'], $value) . '"';
        }

        return '{' . implode(',', $pairs) . '}';
    }

    /**
     * Render a value the way the exposition format expects.
     *
     * @param float $value
     *   The value.
     *
     * @return string
     *   An integer where the value is whole, so a counter reads as a count.
     */
    private function renderValue(float $value): string
    {
        if ($value === floor($value) && abs($value) < 1.0E+15) {
            return (string) (int) $value;
        }

        return rtrim(rtrim(number_format($value, 6, '.', ''), '0'), '.');
    }
}
