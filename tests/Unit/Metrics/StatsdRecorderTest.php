<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Metrics;

use Kanopi\Firewall\Metrics\Metric;
use Kanopi\Firewall\Metrics\StatsdRecorder;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\DegradedBackends;

/**
 * Sending metrics to a StatsD agent over UDP (#222).
 *
 * Against a real socket rather than a mock, because the thing worth checking is
 * what goes on the wire — and a UDP listener on localhost costs nothing to
 * stand up.
 */
class StatsdRecorderTest extends AbstractTestCase
{
    /**
     * @var resource|null
     */
    private $server;

    private int $port = 0;

    protected function setUp(): void
    {
        parent::setUp();
        DegradedBackends::reset();

        // Port 0 asks the kernel for a free one, so two test runs at once do
        // not fight over a fixed number.
        $server = stream_socket_server('udp://127.0.0.1:0', $errorCode, $errorMessage, STREAM_SERVER_BIND);
        $this->assertIsResource($server, 'Could not bind a UDP listener: ' . $errorMessage);

        $this->server = $server;
        $name = (string) stream_socket_get_name($server, false);
        $this->port = (int) substr($name, (int) strrpos($name, ':') + 1);

        stream_set_blocking($server, false);
    }

    protected function tearDown(): void
    {
        if (is_resource($this->server)) {
            fclose($this->server);
        }

        DegradedBackends::reset();
        parent::tearDown();
    }

    public function testACounterGoesOnTheWireWithItsLabelsAsTags(): void
    {
        $this->recorder()->increment(Metric::REQUESTS, ['decision' => 'blocked', 'rule' => 'bad-ips']);

        $this->assertSame(
            'firewall_requests_total:1|c|#decision:blocked,rule:bad-ips',
            $this->received()
        );
    }

    public function testACounterCanCarryAnAmount(): void
    {
        $this->recorder()->increment(Metric::REQUESTS, [], 7);

        $this->assertSame('firewall_requests_total:7|c', $this->received());
    }

    public function testAGaugeIsSent(): void
    {
        $this->recorder()->gauge('firewall_in_flight', ['pool' => 'tarpit'], 12.0);

        $this->assertSame('firewall_in_flight:12|g|#pool:tarpit', $this->received());
    }

    /**
     * A gauge carrying a sign is read by StatsD as a *delta* on the previous
     * value, so a negative reading would silently subtract instead of setting.
     * Zeroing first is the documented way to set one.
     */
    public function testANegativeGaugeIsZeroedFirstSoItSetsRatherThanSubtracts(): void
    {
        $this->recorder()->gauge('firewall_drift', [], -5.0);

        $this->assertSame('firewall_drift:0|g', $this->received());
        $this->assertSame('firewall_drift:-5|g', $this->received());
    }

    public function testAFractionalGaugeKeepsItsFraction(): void
    {
        $this->recorder()->gauge('firewall_ratio', [], 0.25);

        $this->assertSame('firewall_ratio:0.25|g', $this->received());
    }

    public function testAPrefixKeepsTwoInstallationsApartOnOneAgent(): void
    {
        $this->recorder('site_a.')->increment(Metric::REQUESTS);

        $this->assertSame('site_a.firewall_requests_total:1|c', $this->received());
    }

    /**
     * Original StatsD has no concept of a tag, so the labels have to become
     * part of the name or be lost.
     */
    public function testWithoutTagsLabelsAreFoldedIntoTheName(): void
    {
        $this->recorder('', false)->increment(Metric::REQUESTS, ['decision' => 'blocked', 'rule' => 'bad-ips']);

        $this->assertSame('firewall_requests_total.blocked.bad-ips:1|c', $this->received());
    }

    /**
     * A value carrying `:` or `|` does not corrupt one metric, it corrupts the
     * parse of the whole datagram — so the agent misreads a line it was never
     * sent.
     */
    public function testWireCharactersInALabelAreNeutralised(): void
    {
        $this->recorder()->increment(Metric::REQUESTS, ['rule' => "a:b|c,d#e\nf"]);

        $this->assertSame('firewall_requests_total:1|c|#rule:a_b_c_d_e_f', $this->received());
    }

    /**
     * An agent that was never reachable is reported once, to the place a status
     * page reads. Metrics silently not arriving is exactly the kind of thing
     * nobody notices for a month.
     */
    public function testAnUnreachableAgentIsReportedAsADegradedBackend(): void
    {
        $recorder = new StatsdRecorder('this is not a host', 8125);

        $recorder->increment(Metric::REQUESTS);
        $recorder->increment(Metric::REQUESTS);

        $degraded = DegradedBackends::all();

        $this->assertCount(1, $degraded, 'It should be reported once per process, not per request');
        $this->assertSame('metrics', $degraded[0]['component']);
        $this->assertStringContainsString('statsd this is not a host:8125', $degraded[0]['backend']);
    }

    /**
     * And having reported it, it stops trying: retrying on every request would
     * put a connect on the request path for a host that is not there, which is
     * the thing UDP was chosen to avoid.
     */
    public function testAnUnreachableAgentIsNotRetriedPerRequest(): void
    {
        $recorder = new StatsdRecorder('this is not a host', 8125);

        foreach (range(1, 5) as $ignored) {
            $recorder->increment(Metric::REQUESTS);
        }

        $this->assertCount(1, DegradedBackends::all());
    }

    private function recorder(string $prefix = '', bool $tags = true): StatsdRecorder
    {
        return new StatsdRecorder('127.0.0.1', $this->port, $prefix, $tags);
    }

    /**
     * The next datagram the listener saw.
     */
    private function received(): string
    {
        $server = $this->server;
        $this->assertIsResource($server);

        // A datagram written to loopback is there almost immediately, but
        // "almost" is not "already" — so poll briefly rather than assuming.
        $deadline = microtime(true) + 2.0;

        while (microtime(true) < $deadline) {
            $datagram = @stream_socket_recvfrom($server, 8192);

            if (is_string($datagram) && $datagram !== '') {
                return $datagram;
            }

            usleep(1000);
        }

        $this->fail('No datagram arrived within two seconds');
    }
}
