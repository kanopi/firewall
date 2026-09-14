<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Logging;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\DegradedBackends;
use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\LogRecord;

/**
 * A log destination that does not work must not stop the firewall (#346).
 *
 * Everywhere else in this library an unreachable backend degrades and is
 * reported: a rule whose constructor throws is skipped and listed by
 * `getFailedRules()`, storage that cannot connect answers empty and is listed
 * by `getDegradedBackends()`, a rule source that cannot be fetched falls back
 * to its last known good copy. Logging was the exception, and it failed the
 * hard way -- out of `Firewall::create()`, which on `mode: block` is not
 * log-only operation but no protection at all.
 *
 * The fix is deliberately only about **writing**. Monolog's `StreamHandler`
 * creates its directory on first write rather than in its constructor, so a
 * destination that does not exist on this host builds cleanly and throws from
 * whatever line happens to log first -- during `create()` that took the
 * firewall down, and after it that would have been a 500 mid-request.
 *
 * A handler whose *constructor* throws is left fatal, because that is an
 * operator error rather than an environment one and this package stops a
 * deploy for those. There is a test for that below too, since the first draft
 * of this fix caught both and an existing test noticed.
 */
final class LoggingDegradesTest extends AbstractTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        DegradedBackends::reset();
    }

    protected function tearDown(): void
    {
        // Process-global, like the rest of the degraded-backend registry.
        DegradedBackends::reset();

        parent::tearDown();
    }

    /**
     * A handler that throws on write leaves the logger usable.
     *
     * The reported case. Without this the exception reaches whatever called
     * `$logger->info()`, which during evaluation is the firewall and during
     * `create()` is the host's bootstrap.
     */
    public function testAHandlerThatThrowsOnWriteDoesNotThrowAtTheCaller(): void
    {
        $logger = LoggingFactory::create([
            ['class' => ThrowsOnWriteHandler::class, 'args' => []],
        ]);

        $logger->error('this must not throw');

        $this->assertTrue(true, 'Writing to a broken destination returned rather than throwing.');
    }

    /**
     * And it says so where something without a logger can read it.
     *
     * Not through the logger: the logger is the thing that just failed, and
     * writing the explanation to it would re-enter the handler that threw.
     */
    public function testAFailedWriteIsRecordedAsADegradedBackend(): void
    {
        $logger = LoggingFactory::create([
            ['class' => ThrowsOnWriteHandler::class, 'args' => []],
        ]);

        $logger->error('anything');

        $degraded = DegradedBackends::all();

        $this->assertCount(1, $degraded);
        $this->assertSame('logger', $degraded[0]['component']);
        $this->assertStringContainsString('cannot reach its destination', $degraded[0]['error']);
    }

    /**
     * A broken destination is one fact however many records hit it.
     *
     * A firewall logs on every request. A report listing the same unreachable
     * destination ten thousand times is a report nobody reads.
     */
    public function testARepeatedlyFailingHandlerIsRecordedOnce(): void
    {
        $logger = LoggingFactory::create([
            ['class' => ThrowsOnWriteHandler::class, 'args' => []],
        ]);

        foreach (range(1, 20) as $ignored) {
            $logger->error('again');
        }

        $this->assertCount(1, DegradedBackends::all());
    }

    /**
     * The handlers that do work keep working.
     *
     * The reason this is per handler rather than per logger: a deployment with
     * a file log and a database log should lose the broken one, not both.
     */
    public function testAWorkingHandlerAlongsideABrokenOneStillReceivesRecords(): void
    {
        $working = new TestHandler(Level::Debug);

        $logger = LoggingFactory::create([
            ['class' => ThrowsOnWriteHandler::class, 'args' => []],
            ['class' => $working],
        ]);

        $logger->error('kept');

        $this->assertTrue($working->hasErrorThatContains('kept'));
    }

    /**
     * A handler whose *constructor* throws still stops the deploy, and should.
     *
     * The line this fix draws, stated as a test because the first version of
     * it did not draw the line and an existing test caught that.
     *
     * `SyslogHandler` handed the string `LOG_USER` instead of the constant is
     * an operator error -- YAML cannot express a PHP constant -- and this
     * package refuses to start for operator errors: a challenge provider that
     * does not resolve, a reputation provider naming no class, a schedule that
     * cannot be read. What #346 is about is the *environment* case: a
     * destination that is correct in configuration and absent on this host,
     * which is only discoverable when something writes.
     */
    public function testAHandlerThatCannotBeConstructedStillStopsTheDeploy(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/cannot be constructed/');

        LoggingFactory::create([['class' => ThrowsOnConstructionHandler::class, 'args' => []]]);
    }

    /**
     * The reported repro, end to end.
     *
     * `logging-pantheon.yml` writes to `/files/private/`, which exists on
     * Pantheon and nowhere else. Included anywhere it does not, this used to be
     * `UnexpectedValueException` out of `Firewall::create()` -- the firewall did
     * not start, so on `mode: block` nothing was protected.
     *
     * The destination here is a directory under a path that is a **file**, not
     * `/files/private` itself: the CI container runs as root, where `/files`
     * can be created and the bug does not reproduce. `mkdir` under a regular
     * file fails with `ENOTDIR` for every user, which is what makes this assert
     * the same thing on a laptop and in the 8.1 container.
     */
    public function testTheFirewallStartsWithAnUnreachableLogDestination(): void
    {
        $firewall = \Kanopi\Firewall\Firewall::create([[
            'logger' => [[
                'class' => \Monolog\Handler\StreamHandler::class,
                'args' => ['/etc/hosts/firewall/firewall.log', 'Monolog\\Level::INFO'],
            ]],
            'plugins' => [[
                'plugin' => \Kanopi\Firewall\Plugins\Url::class,
                'response' => 'block',
                'enable' => true,
                'config' => ['path:/wp-admin'],
            ]],
            'global' => ['mode' => 'exception'],
        ]]);

        $this->assertTrue(
            $firewall->evaluate($this->getRequest('203.0.113.5')),
            'A request must still be evaluated when the log destination is unreachable.'
        );

        $degraded = $firewall->getDegradedBackends();

        $this->assertNotSame([], $degraded, 'And the firewall must be able to say the logs are not being written.');
        $this->assertSame('logger', $degraded[0]['component']);
    }
}

/**
 * Builds, and fails the moment anything is written to it.
 *
 * Monolog's `StreamHandler` behaves this way for a path it cannot create,
 * which is what made the original bug reach a request rather than a boot.
 */
class ThrowsOnWriteHandler extends AbstractProcessingHandler
{
    protected function write(LogRecord $record): void
    {
        throw new \UnexpectedValueException('this handler cannot reach its destination');
    }
}

/**
 * Never builds at all.
 */
class ThrowsOnConstructionHandler extends AbstractProcessingHandler
{
    public function __construct()
    {
        throw new \RuntimeException('this handler cannot be constructed');
    }

    protected function write(LogRecord $record): void
    {
    }
}
