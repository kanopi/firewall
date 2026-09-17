<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Metrics;

use Kanopi\Firewall\Utility\DegradedBackends;

/**
 * Sends metrics to a StatsD agent over UDP (#222).
 *
 * ## UDP, and only UDP
 *
 * StatsD has a TCP mode and this does not offer it, which is a deliberate
 * refusal rather than an omission. A TCP socket connects, and a connect to a
 * host that is up but not answering waits -- so a metrics backend having a bad
 * afternoon becomes a slow site, on the request path, for every visitor. UDP
 * has no handshake, no acknowledgement and no retry: a datagram is written to
 * the local network stack and the call returns.
 *
 * That trade is the right one here. Losing a packet costs one increment on a
 * counter; waiting for one costs a request. `Firewall::announce()` already
 * catches a listener that *throws*, which stops an exception becoming an
 * outage, but nothing catches a listener that *hangs* -- and a slow site is
 * harder to diagnose than a failed one.
 *
 * The socket is opened once and reused, and set non-blocking, so a full send
 * buffer drops the datagram rather than waiting for room.
 *
 * ## An unreachable agent is reported once, not per request
 *
 * A failure goes to `DegradedBackends`, which a status page reads, rather than
 * to a log line per request. Metrics silently not arriving is exactly the kind
 * of thing nobody notices for a month.
 */
final class StatsdRecorder implements MetricsRecorderInterface
{
    /**
     * The opened socket, or NULL before the first send.
     *
     * @var resource|null
     */
    private $socket;

    /**
     * Whether opening it has already failed.
     *
     * One attempt per process. Retrying on every request would put a connect
     * on the request path for a host that is not there, which is the thing UDP
     * was chosen to avoid.
     */
    private bool $unavailable = false;

    /**
     * @param string $host
     *   The StatsD agent's host.
     * @param int $port
     *   Its port.
     * @param string $prefix
     *   Prepended to every metric name, for installations sharing an agent.
     * @param bool $tags
     *   TRUE emits labels as DogStatsD tags (`|#rule:login`), which Datadog,
     *   Telegraf and Vector all read. FALSE folds them into the metric name for
     *   an original StatsD agent, which has no concept of a tag.
     */
    public function __construct(
        private readonly string $host = '127.0.0.1',
        private readonly int $port = 8125,
        private readonly string $prefix = '',
        private readonly bool $tags = true,
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function increment(string $metric, array $labels = [], int $by = 1): void
    {
        $this->send($metric, $labels, $by . '|c');
    }

    /**
     * {@inheritdoc}
     */
    public function gauge(string $metric, array $labels = [], float $value = 0.0): void
    {
        // A gauge carrying a sign is read by StatsD as a *delta* on the
        // previous value, so a legitimately negative reading would silently
        // subtract instead of setting. Zeroing first is the documented way to
        // set one, and costs a second datagram only when the value is negative.
        if ($value < 0) {
            $this->send($metric, $labels, '0|g');
        }

        $this->send($metric, $labels, $this->number($value) . '|g');
    }

    /**
     * Write one datagram.
     *
     * @param string $metric
     *   The metric name.
     * @param array<string, string> $labels
     *   Label name to value.
     * @param string $payload
     *   The value and type, such as `1|c`.
     */
    private function send(string $metric, array $labels, string $payload): void
    {
        $socket = $this->socket();

        if ($socket === null) {
            return;
        }

        $name = $this->prefix . $metric;

        if (!$this->tags && $labels !== []) {
            $name .= '.' . implode('.', array_map(
                $this->sanitize(...),
                $labels
            ));
        }

        $line = $name . ':' . $payload;

        if ($this->tags && $labels !== []) {
            $pairs = [];

            foreach ($labels as $label => $value) {
                $pairs[] = $this->sanitize($label) . ':' . $this->sanitize($value);
            }

            $line .= '|#' . implode(',', $pairs);
        }

        // Suppressed rather than checked: a dropped datagram is the documented
        // behaviour of the transport, not a condition worth reporting per
        // request. An agent that was never reachable is reported once, above.
        @fwrite($socket, $line);
    }

    /**
     * The socket, opened on first use.
     *
     * @return resource|null
     *   The socket, or NULL when the agent could not be reached.
     */
    private function socket()
    {
        if ($this->socket !== null) {
            return $this->socket;
        }

        if ($this->unavailable) {
            return null;
        }

        $address = sprintf('udp://%s:%d', $this->host, $this->port);
        $socket = @stream_socket_client($address, $errorCode, $errorMessage, 0, STREAM_CLIENT_CONNECT);

        if ($socket === false) {
            $this->unavailable = true;

            DegradedBackends::record(
                'metrics',
                'statsd ' . $this->host . ':' . $this->port,
                $errorMessage === '' ? 'could not open a UDP socket' : $errorMessage
            );

            return null;
        }

        // So a full send buffer drops the datagram rather than waiting for
        // room, which is the one way a UDP write can still block.
        stream_set_blocking($socket, false);

        $this->socket = $socket;

        return $this->socket;
    }

    /**
     * Render a gauge value without scientific notation or a locale's comma.
     *
     * @param float $value
     *   The value.
     *
     * @return string
     *   The value as StatsD will read it.
     */
    private function number(float $value): string
    {
        return rtrim(rtrim(number_format($value, 6, '.', ''), '0'), '.');
    }

    /**
     * Remove the characters that mean something in the wire format.
     *
     * A name carrying `:`, `|`, `,` or `#` does not corrupt one metric, it
     * corrupts the parse of the whole datagram -- so the agent misreads a line
     * it was never sent.
     *
     * @param string $value
     *   The raw value.
     *
     * @return string
     *   A value safe to put on the wire.
     */
    private function sanitize(string $value): string
    {
        return str_replace([':', '|', ',', '#', '@', "\n", "\r"], '_', $value);
    }
}
