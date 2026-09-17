<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Logging\Handler;

use Kanopi\Firewall\Logging\Handler\DeferredHandler;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;

/**
 * Sending log records after the visitor has their response (#379).
 */
class DeferredHandlerTest extends AbstractTestCase
{
    /**
     * The point: nothing reaches the wrapped handler while the request is still
     * being served.
     */
    public function testNothingIsWrittenDuringTheRequest(): void
    {
        $testHandler = new TestHandler();
        $deferred = new DeferredHandler($testHandler);
        $logger = new Logger('test', [$deferred]);

        $logger->warning('something happened');
        $logger->error('something else');

        $this->assertSame([], $testHandler->getRecords(), 'A record was written mid-request');

        $deferred->close();

        $this->assertCount(2, $testHandler->getRecords());
    }

    /**
     * And the visitor is released before the flush, not after — which is the
     * whole difference between this and Monolog's own `BufferHandler`.
     */
    public function testTheVisitorIsReleasedBeforeAnythingIsSent(): void
    {
        $order = [];
        $testHandler = new class ($order) extends TestHandler {
            /**
             * @param array<int, string> $order
             */
            public function __construct(public array &$order)
            {
                parent::__construct();
            }

            public function handleBatch(array $records): void
            {
                $this->order[] = 'flushed';
                parent::handleBatch($records);
            }
        };

        $deferred = $this->deferred($testHandler, $order);
        (new Logger('test', [$deferred]))->warning('x');
        $deferred->close();

        $this->assertSame(['released', 'flushed'], $order);
    }

    /**
     * `fastcgi_finish_request()` does not exist under CLI, where
     * `bin/firewall-check` and `firewall-doctor` run. Dropping the records
     * there would make a command-line run silently log nothing.
     */
    public function testWithNothingToReleaseTheRecordsStillGetThrough(): void
    {
        $testHandler = new TestHandler();
        $deferred = new class ($testHandler) extends DeferredHandler {
            protected function finishRequest(): bool
            {
                return false;
            }
        };

        (new Logger('test', [$deferred]))->warning('x');
        $deferred->close();

        $this->assertCount(1, $testHandler->getRecords());
    }

    /**
     * The real seam, on a SAPI that has neither function — which is every SAPI
     * the test suite runs on, so this is what it actually does there.
     */
    public function testOnThisSapiThereIsNothingToRelease(): void
    {
        $this->assertSame('cli', PHP_SAPI, 'This test only means anything under the CLI SAPI');

        $deferred = new DeferredHandler(new TestHandler());
        $finish = new \ReflectionMethod($deferred, 'finishRequest');

        $this->assertFalse($finish->invoke($deferred));
    }

    /**
     * Level filtering is the wrapped handler's job as much as this one's, and a
     * record below the threshold must not be buffered only to be dropped later.
     */
    public function testARecordBelowTheLevelIsNotBuffered(): void
    {
        $testHandler = new TestHandler();
        $deferred = new DeferredHandler($testHandler, 0, Level::Error);

        $logger = new Logger('test', [$deferred]);
        $logger->info('quiet');
        $logger->error('loud');
        $deferred->close();

        $this->assertCount(1, $testHandler->getRecords());
        $this->assertSame('loud', $testHandler->getRecords()[0]->message);
    }

    /**
     * A limit that is reached mid-request flushes mid-request, which is the
     * thing being avoided — so the default holds everything, and a caller
     * setting a limit is choosing memory over latency knowingly.
     */
    public function testTheDefaultHoldsEveryRecordRatherThanFlushingEarly(): void
    {
        $testHandler = new TestHandler();
        $deferred = new DeferredHandler($testHandler);
        $logger = new Logger('test', [$deferred]);

        foreach (range(1, 500) as $i) {
            $logger->warning('record ' . $i);
        }

        $this->assertSame([], $testHandler->getRecords());

        $deferred->close();

        $this->assertCount(500, $testHandler->getRecords());
    }

    /**
     * A deferred handler with a limit and `flushOnOverflow` is Monolog's
     * behaviour, kept rather than removed: a deployment that would rather bound
     * memory than defer everything can say so.
     */
    public function testAnOverflowingBufferCanBeToldToFlushEarly(): void
    {
        $testHandler = new TestHandler();
        $deferred = new DeferredHandler($testHandler, 2, Level::Debug, true, true);
        $logger = new Logger('test', [$deferred]);

        $logger->warning('one');
        $logger->warning('two');
        $logger->warning('three');

        $this->assertNotSame([], $testHandler->getRecords(), 'flushOnOverflow should have flushed');
    }

    /**
     * Build one whose release is observable.
     *
     * @param array<int, string> $order
     */
    private function deferred(TestHandler $testHandler, array &$order): DeferredHandler
    {
        return new class ($testHandler, $order) extends DeferredHandler {
            /**
             * @param array<int, string> $order
             */
            public function __construct(TestHandler $testHandler, public array &$order)
            {
                parent::__construct($testHandler);
            }

            protected function finishRequest(): bool
            {
                $this->order[] = 'released';

                return true;
            }
        };
    }
}
