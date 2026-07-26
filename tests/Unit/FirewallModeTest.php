<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\FirewallMode;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Storage\StorageInterface;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\HttpFoundation\Request;

class FirewallModeTest extends AbstractTestCase
{
    private StorageInterface&MockObject $storage;
    private PluginManager&MockObject $blockManager;
    private PluginManager&MockObject $bypassManager;
    private PluginManager&MockObject $challengeManager;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = $this->createMock(StorageInterface::class);
        $this->blockManager = $this->createMock(PluginManager::class);
        $this->bypassManager = $this->createMock(PluginManager::class);
        $this->challengeManager = $this->createMock(PluginManager::class);
    }

    private function createFirewall(array $config = []): Firewall
    {
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $ref->newInstanceWithoutConstructor();
        $constructor = $ref->getConstructor();
        $constructor->setAccessible(true);
        $constructor->invoke(
            $firewall,
            $this->storage,
            $this->blockManager,
            $this->bypassManager,
            $this->challengeManager,
            $config
        );
        return $firewall;
    }

    public function testDisabledModeSkipsEvaluation(): void
    {
        $this->bypassManager->expects($this->never())->method('evaluate');
        $this->blockManager->expects($this->never())->method('evaluate');
        $this->storage->expects($this->never())->method('isBlocked');

        $firewall = $this->createFirewall(['mode' => 'disabled']);
        $request = Request::create('/');
        $this->assertTrue($firewall->evaluate($request));
    }

    public function testLogModeDoesNotBlock(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '1.2.3.4']);
        $request->attributes->set('x-request-id', 'log-test');

        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('Blocker');
        $plugin->method('getStatusCode')->willReturn(403);

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn($plugin);

        $firewall = $this->createFirewall(['mode' => 'log']);
        $this->assertTrue($firewall->evaluate($request));
    }

    /**
     * Regression for #44: `mode: log` is documented as a dry run that
     * neither writes to storage nor terminates the request, but the durable
     * storage blocklist was enforced unconditionally — so an audit-only
     * deployment still hard-blocked every repeat offender and extended
     * their ban.
     *
     * Calls the blocklist check directly: `evaluate()` short-circuits under
     * PHP_SAPI === 'cli' for every mode but `exception`, so the log-mode
     * path is not reachable through it in the unit suite.
     */
    public function testLogModeDoesNotEnforceStorageBlocklist(): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $this->storage->method('getKey')->willReturn('1.2.3.4');
        $this->storage->method('isBlocked')->willReturn(['event_id' => 'prior-block']);
        $this->storage->expects($this->never())->method('addToExpire');
        $this->storage->expects($this->never())->method('recordOffense');

        $firewall = $this->createFirewall(['mode' => 'log']);
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '1.2.3.4']);

        $this->invokeEnforceStorageBlocklist($firewall, $request);

        $this->assertTrue(
            $handler->hasRecordThatContains('Request would be blocked by storage blocklist (log mode)', Level::Warning),
            'Expected a warning naming the blocklist hit that log mode declined to enforce.'
        );
        $this->assertSame(
            'prior-block',
            $request->attributes->get('x-request-id'),
            'The stored event ID should still be adopted so the audit log ties back to the original block.'
        );
    }

    /**
     * Companion to #44: every other mode still enforces the blocklist —
     * recording the offense, extending the ban, and terminating.
     */
    public function testExceptionModeStillEnforcesStorageBlocklist(): void
    {
        $this->storage->method('getKey')->willReturn('1.2.3.4');
        $this->storage->method('isBlocked')->willReturn(['event_id' => 'prior-block']);
        $this->storage->expects($this->once())->method('addToExpire')->with('1.2.3.4', 3600);
        $this->storage->expects($this->once())->method('recordOffense')->with('1.2.3.4');

        $firewall = $this->createFirewall(['mode' => 'exception']);
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '1.2.3.4']);

        $this->expectException(FirewallBlockedException::class);
        $this->invokeEnforceStorageBlocklist($firewall, $request);
    }

    /**
     * Invoke the protected blocklist check, bypassing the CLI guard in
     * evaluate().
     */
    private function invokeEnforceStorageBlocklist(Firewall $firewall, Request $request): void
    {
        $method = new \ReflectionMethod(Firewall::class, 'enforceStorageBlocklist');
        $method->setAccessible(true);
        $method->invoke($firewall, $request);
    }

    public function testExceptionModeThrowsFirewallBlockedException(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '5.6.7.8']);
        $request->attributes->set('x-request-id', 'exc-test');

        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('Blocker');
        $plugin->method('getExpirationTime')->willReturn(600);
        $plugin->method('getStatusCode')->willReturn(403);

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn($plugin);

        $firewall = $this->createFirewall(['mode' => 'exception']);

        $this->expectException(FirewallBlockedException::class);
        $this->expectExceptionCode(403);
        $firewall->evaluate($request);
    }

    public function testExceptionModeIncludesStatusCodeAndMessage(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '5.6.7.8']);
        $request->attributes->set('x-request-id', 'exc-test');

        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('Blocker');
        $plugin->method('getExpirationTime')->willReturn(600);
        $plugin->method('getStatusCode')->willReturn(429);

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn($plugin);

        $firewall = $this->createFirewall([
            'mode' => 'exception',
            'banning_message' => 'Too many requests',
        ]);

        try {
            $firewall->evaluate($request);
            $this->fail('Expected FirewallBlockedException was not thrown');
        } catch (FirewallBlockedException $e) {
            $this->assertSame(429, $e->getStatusCode());
            $this->assertSame('Too many requests', $e->getMessage());
        }
    }

    public function testBlockModeSkipsEvaluationInCli(): void
    {
        $this->bypassManager->expects($this->never())->method('evaluate');
        $this->blockManager->expects($this->never())->method('evaluate');

        $firewall = $this->createFirewall(['mode' => 'block']);
        $request = Request::create('/');
        $this->assertTrue($firewall->evaluate($request));
    }

    public function testInvalidModeDefaultsToBlock(): void
    {
        $firewall = $this->createFirewall(['mode' => 'invalid_mode']);
        $ref = new \ReflectionClass($firewall);
        $prop = $ref->getProperty('firewallMode');
        $this->assertSame(FirewallMode::Block, $prop->getValue($firewall));
    }

    public function testNoModeConfigDefaultsToBlock(): void
    {
        $firewall = $this->createFirewall([]);
        $ref = new \ReflectionClass($firewall);
        $prop = $ref->getProperty('firewallMode');
        $this->assertSame(FirewallMode::Block, $prop->getValue($firewall));
    }

    public function testFirewallModeEnum(): void
    {
        $this->assertSame('block', FirewallMode::Block->value);
        $this->assertSame('log', FirewallMode::Log->value);
        $this->assertSame('exception', FirewallMode::Exception->value);
        $this->assertSame('disabled', FirewallMode::Disabled->value);
    }

    public function testFirewallModeTryFromValid(): void
    {
        $this->assertSame(FirewallMode::Block, FirewallMode::tryFrom('block'));
        $this->assertSame(FirewallMode::Log, FirewallMode::tryFrom('log'));
        $this->assertSame(FirewallMode::Exception, FirewallMode::tryFrom('exception'));
        $this->assertSame(FirewallMode::Disabled, FirewallMode::tryFrom('disabled'));
    }

    public function testFirewallModeTryFromInvalid(): void
    {
        $this->assertNull(FirewallMode::tryFrom('invalid'));
    }
}
