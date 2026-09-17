<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Logging\Handler;

use Monolog\Handler\BufferHandler;
use Monolog\Handler\HandlerInterface;
use Monolog\Level;

/**
 * Sends log records after the visitor has their response (#379).
 *
 * Every Monolog handler that speaks HTTP — `SlackWebhookHandler`,
 * `LogglyHandler`, `InsightOpsHandler`, `TelegramBotHandler` — makes a
 * **blocking** round trip inside `write()`, once per record, on a component that
 * logs per decision:
 *
 * ```php
 * // Monolog\Handler\SlackWebhookHandler::write()
 * Curl\Util::execute($ch);
 * ```
 *
 * So a log service having a bad afternoon becomes a slow site. That is the same
 * hazard #222 refused for metrics, where StatsD is UDP-only and the missing TCP
 * mode is deliberate. `LoggingFactory` already catches a handler that *throws*
 * (#346); nothing catches one that *hangs*, and a slow site is harder to
 * diagnose than a failed one.
 *
 * ## What it actually does
 *
 * ```
 * handle()   →  buffer in memory, return immediately
 * shutdown   →  fastcgi_finish_request()   ← the visitor is served here
 *            →  flush the buffer to the wrapped handler
 * ```
 *
 * A wrapper rather than a thirteenth HTTP handler. Monolog's are maintained and
 * reimplementing the Datadog, Loki and Splunk payload formats is a treadmill;
 * what was missing is a way to get *any* of them off the request path.
 *
 * ## What it does not do
 *
 * **It cannot bound how long the flush takes.** After the response is sent a
 * hung request is no longer a slow page, but it is still an FPM worker held out
 * of the pool, and enough of them is an outage by another route. Set a timeout
 * on the handler you wrap where it has one — `SocketHandler` has
 * `setConnectionTimeout()` and `setWritingTimeout()`; the curl-based handlers
 * expose none, which is worth knowing before choosing one.
 *
 * **Buffering trades durability for latency.** A fatal that kills the process
 * before shutdown loses the buffer. That is the right trade for a firewall log
 * and the wrong one for an audit log.
 *
 * **It is not the first thing to reach for.** Writing JSON lines to stdout and
 * letting Vector, Fluent Bit or Filebeat ship them costs nothing on the request
 * path at all, and delivery, retries and backpressure are then handled by
 * software built for it. This is for deployments that cannot do that.
 */
final class DeferredHandler extends BufferHandler
{
    /**
     * @param HandlerInterface $handler
     *   The handler to flush into, once the visitor has been served.
     * @param int $bufferLimit
     *   Records to hold before flushing early. `0` holds all of them, which is
     *   what keeps every write off the request path — a limit that is reached
     *   mid-request flushes mid-request, which is the thing being avoided.
     * @param int|string|Level $level
     *   Minimum level to buffer.
     * @param bool $bubble
     *   Whether handlers after this one also see the record.
     * @param bool $flushOnOverflow
     *   Whether reaching `$bufferLimit` flushes rather than discards the oldest.
     */
    public function __construct(
        HandlerInterface $handler,
        int $bufferLimit = 0,
        int|string|Level $level = Level::Debug,
        bool $bubble = true,
        bool $flushOnOverflow = false,
    ) {
        parent::__construct($handler, $bufferLimit, $level, $bubble, $flushOnOverflow);
    }

    /**
     * {@inheritdoc}
     *
     * Called from the shutdown function `BufferHandler` registers on its first
     * record, which runs after `exit()` and after a fatal — both of which the
     * firewall's block and challenge paths use.
     */
    public function close(): void
    {
        $this->finishRequest();

        parent::close();
    }

    /**
     * Release the visitor before anything is sent anywhere.
     *
     * A seam, and one of the few places a seam earns itself twice over:
     * `fastcgi_finish_request()` does not exist under CLI — where
     * `bin/firewall-check` and `firewall-doctor` run — and cannot be provoked
     * into failing from a test on a SAPI that has it.
     *
     * Calling it when the host framework already has is harmless: Symfony's
     * `Response::send()` does exactly this, so on a Symfony application the
     * connection is usually closed long before shutdown and this returns FALSE
     * having done nothing.
     *
     * @return bool
     *   TRUE when the connection was closed here.
     */
    protected function finishRequest(): bool
    {
        foreach (['fastcgi_finish_request', 'litespeed_finish_request'] as $finish) {
            if (function_exists($finish)) {
                // Ignored for coverage rather than worked around. Neither
                // function exists on any SAPI the test suite runs on, so this
                // line cannot be executed there — and the alternatives are
                // worse than the gap: defining a global
                // `fastcgi_finish_request()` in the bootstrap would make it
                // exist for every other test, and an extra indirection just to
                // have something callable would be a seam that tests itself
                // rather than this.
                //
                // What *is* tested is everything around it: that the release
                // happens before the flush, that a SAPI with neither function
                // still flushes rather than dropping records, and that this
                // returns FALSE here.
                // @codeCoverageIgnoreStart
                return $finish();
                // @codeCoverageIgnoreEnd
            }
        }

        // No such call on this SAPI. The buffer still flushes below — deferred
        // to shutdown, which is later than mid-request even when the visitor is
        // not released early. Dropping the records instead would make a CLI run
        // silently log nothing.
        return false;
    }
}
