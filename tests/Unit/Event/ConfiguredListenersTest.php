<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Event;

use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Diagnostics\Doctor;
use Kanopi\Firewall\Event\ConfiguredListeners;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\IpAddress;
use Kanopi\Firewall\Tests\Event\ListenerThatCannotBeBuilt;
use Kanopi\Firewall\Tests\Event\RecordingListener;
use Kanopi\Firewall\Tests\Event\ThrowingListener;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Kanopi\Firewall\Utility\DegradedBackends;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Decision listeners and the StatsD exporter, from YAML (#396).
 *
 * Before this both were PHP only: the dispatcher is a create() argument, and a site whose
 * only integration point is a config file could not count a block.
 */
final class ConfiguredListenersTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        putenv('FIREWALL_BYPASS_CLI=1');
        RecordingListener::$journal = [];
        DegradedBackends::reset();
    }

    protected function tearDown(): void
    {
        DegradedBackends::reset();

        parent::tearDown();
    }

    /**
     * A firewall that blocks 203.0.113.5.
     *
     * @param array<string, mixed> $extra
     *   Top-level configuration to add.
     */
    private function firewall(array $extra, ?EventDispatcherInterface $eventDispatcher = null): Firewall
    {
        return Firewall::create([$extra + [
            'global' => ['mode' => 'exception'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'plugins' => [[
                'plugin' => IpAddress::class,
                'response' => 'block',
                'enable' => true,
                'config' => ['203.0.113.5'],
            ]],
        ]], [], $eventDispatcher);
    }

    private function blockedRequest(Firewall $firewall): void
    {
        try {
            $firewall->evaluate(Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.5']));
            $this->fail('The request should have been blocked');
        } catch (FirewallBlockedException) {
            $this->addToAssertionCount(1);
        }
    }

    // -----------------------------------------------------------------------
    // Listeners
    // -----------------------------------------------------------------------

    public function testAConfiguredListenerIsToldOfEveryDecision(): void
    {
        $firewall = $this->firewall(['events' => ['listeners' => [
            ['class' => RecordingListener::class, 'args' => ['yaml']],
        ]]]);

        $this->assertTrue($firewall->evaluate(Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '198.51.100.7'])));
        $this->blockedRequest($firewall);

        $this->assertSame(['yaml:RequestAllowed', 'yaml:RequestBlocked'], RecordingListener::$journal);
    }

    /**
     * The class alone is shorthand for `{class: ...}`.
     */
    public function testAClassNameAloneIsShorthand(): void
    {
        $this->blockedRequest($this->firewall(['events' => ['listeners' => [RecordingListener::class]]]));

        $this->assertSame(['configured:RequestBlocked'], RecordingListener::$journal);
    }

    /**
     * `events:` narrows it, by short name or by class.
     */
    public function testAListenerCanAskForSomeEvents(): void
    {
        $firewall = $this->firewall(['events' => ['listeners' => [
            ['class' => RecordingListener::class, 'args' => ['short'], 'events' => ['RequestBlocked']],
            ['class' => RecordingListener::class, 'args' => ['full'], 'events' => 'Kanopi\\Firewall\\Event\\RequestAllowed'],
        ]]]);

        $firewall->evaluate(Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '198.51.100.7']));
        $this->blockedRequest($firewall);

        $this->assertSame(['full:RequestAllowed', 'short:RequestBlocked'], RecordingListener::$journal);
    }

    /**
     * A host that passes a dispatcher and configures listeners gets both, the host's first.
     */
    public function testTheHostDispatcherIsToldFirstAndBothAreTold(): void
    {
        $host = new class () implements EventDispatcherInterface {
            public function dispatch(object $event): object
            {
                RecordingListener::$journal[] = 'host:' . substr((string) strrchr($event::class, '\\'), 1);

                return $event;
            }
        };

        $this->blockedRequest($this->firewall(['events' => ['listeners' => [RecordingListener::class]]], $host));

        $this->assertSame(['host:RequestBlocked', 'configured:RequestBlocked'], RecordingListener::$journal);
    }

    /**
     * A listener whose downstream is down does not change the verdict, does not stop the
     * next listener, and says so -- in the log and to a status page.
     */
    public function testAThrowingListenerIsIsolatedAndReported(): void
    {
        $firewall = $this->firewall([
            'events' => ['listeners' => [ThrowingListener::class, RecordingListener::class]],
            'logger' => [['class' => TestLogHandler::class]],
        ]);
        $handler = LoggingFactory::logger()->getHandlers()[0];

        $this->blockedRequest($firewall);

        $this->assertSame(['configured:RequestBlocked'], RecordingListener::$journal, 'The next listener still ran');
        $this->assertTrue($handler instanceof TestLogHandler && $handler->hasErrorContaining('configured decision listener threw'));

        $degraded = DegradedBackends::all();
        $this->assertSame('decision listener', $degraded[0]['component'] ?? null);
        $this->assertSame(ThrowingListener::class, $degraded[0]['backend'] ?? null);
        $this->assertSame('the notifier is down', $degraded[0]['error'] ?? null);
    }

    /**
     * A host dispatcher that throws does not silence the configured listeners.
     */
    public function testAThrowingHostDispatcherDoesNotSilenceConfiguredListeners(): void
    {
        $host = new class () implements EventDispatcherInterface {
            public function dispatch(object $event): object
            {
                throw new \RuntimeException('host listener down');
            }
        };

        $this->blockedRequest($this->firewall(['events' => ['listeners' => [RecordingListener::class]]], $host));

        $this->assertSame(['configured:RequestBlocked'], RecordingListener::$journal);
    }

    /**
     * @return array<string, array{0: mixed, 1: string}>
     */
    public static function provideListenersThatCannotBeBuilt(): array
    {
        return [
            'not a list' => ['nope', 'must be a list'],
            'no class' => [[['args' => []]], 'events.listeners.0 needs a class'],
            'a class that does not exist' => [['App\\NoSuchListener'], 'does not exist'],
            'a class that is not callable' => [[\ArrayObject::class], 'is not callable'],
            'a constructor that refuses' => [[ListenerThatCannotBeBuilt::class], 'a webhook URL is required'],
            'an event that is not one' => [[['class' => RecordingListener::class, 'events' => ['RequestBlokced']]], '"RequestBlokced" is not a decision event'],
        ];
    }

    /**
     * Refused at startup, not on the first blocked visitor.
     */
    #[DataProvider('provideListenersThatCannotBeBuilt')]
    public function testAListenerThatCannotBeBuiltStopsTheFirewallStarting(mixed $listeners, string $message): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($message);

        $this->firewall(['events' => ['listeners' => $listeners]]);
    }

    public function testWithNoListenersNothingIsRegistered(): void
    {
        $this->assertSame([], $this->firewall([])->getConfiguredListeners());
        $this->assertTrue(ConfiguredListeners::fromConfig([])->isEmpty());
    }

    public function testListenersDescribeThemselves(): void
    {
        $firewall = $this->firewall([
            'events' => ['listeners' => [
                RecordingListener::class,
                ['class' => RecordingListener::class, 'events' => ['RequestBlocked', 'ChallengeFailed']],
            ]],
            'metrics' => ['statsd' => ['host' => 'metrics.internal', 'port' => 9125]],
        ]);

        $this->assertSame([
            RecordingListener::class,
            RecordingListener::class . ' (RequestBlocked, ChallengeFailed)',
            'StatsD to metrics.internal:9125',
        ], $firewall->getConfiguredListeners());
    }

    // -----------------------------------------------------------------------
    // StatsD
    // -----------------------------------------------------------------------

    /**
     * The same metric the PHP wiring in docs/how-to/metrics.md produces, on the wire.
     */
    public function testStatsdCountsABlockOverUdp(): void
    {
        $server = stream_socket_server('udp://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND);
        $this->assertIsResource($server, $errstr);
        $port = (int) substr((string) strrchr((string) stream_socket_get_name($server, false), ':'), 1);
        stream_set_timeout($server, 2);

        // Prepended as written, so a prefix carries its own separator.
        $this->blockedRequest($this->firewall(['metrics' => ['statsd' => ['port' => $port, 'prefix' => 'site1.']]]));

        $datagram = (string) stream_socket_recvfrom($server, 1024);
        fclose($server);

        $this->assertStringContainsString('site1.firewall_requests_total:1|c', $datagram);
        $this->assertStringContainsString('decision:blocked', $datagram);
    }

    public function testStatsdTrueTakesEveryDefault(): void
    {
        $this->assertSame(['StatsD to 127.0.0.1:8125'], ConfiguredListeners::fromConfig(['metrics' => ['statsd' => true]])->describe());
    }

    /**
     * @return array<string, array{0: mixed, 1: string}>
     */
    public static function provideBadStatsdSettings(): array
    {
        return [
            'not a map' => ['yes please', 'must be a map'],
            'no host' => [['host' => ''], 'host must be'],
            'a port that is not one' => [['port' => 70000], 'port must be a port number'],
            'a prefix that is not text' => [['prefix' => ['fw']], 'prefix must be a string'],
            'a negative rule limit' => [['rule_limit' => -1], 'rule_limit must be zero or more'],
        ];
    }

    #[DataProvider('provideBadStatsdSettings')]
    public function testBadStatsdSettingsStopTheFirewallStarting(mixed $settings, string $message): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($message);

        ConfiguredListeners::fromConfig(['metrics' => ['statsd' => $settings]]);
    }

    public function testTheDoctorListsTheRegisteredListeners(): void
    {
        $dir = sys_get_temp_dir() . '/fw-listeners-' . uniqid();
        mkdir($dir, 0700, true);

        $findings = (new Doctor([[
            'global' => ['mode' => 'block'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\FileStorage', 'config' => ['storage_file' => $dir . '/blocked.data']],
            'plugins' => [],
            'events' => ['listeners' => [RecordingListener::class]],
            'metrics' => ['statsd' => true],
        ]]))->run();

        $found = array_values(array_filter($findings, static fn (Diagnosis $d): bool => $d->title === '2 decision listeners registered'));

        $this->assertCount(1, $found);
        $this->assertSame(RecordingListener::class . '; StatsD to 127.0.0.1:8125', $found[0]->detail);
        $this->assertNotContains('1 decision listener registered', array_map(static fn (Diagnosis $d): string => $d->title, (new Doctor([[
            'global' => ['mode' => 'block'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\FileStorage', 'config' => ['storage_file' => $dir . '/blocked.data']],
            'plugins' => [],
        ]]))->run()));

        @unlink($dir . '/blocked.data');
        @rmdir($dir);
    }
}
