<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\FirewallMode;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Storage\StorageInterface;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\HttpFoundation\Request;

class FirewallModeTest extends AbstractTestCase
{
    private StorageInterface&MockObject $storage;
    private PluginManager&MockObject $blockManager;
    private PluginManager&MockObject $bypassManager;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = $this->createMock(StorageInterface::class);
        $this->blockManager = $this->createMock(PluginManager::class);
        $this->bypassManager = $this->createMock(PluginManager::class);
    }

    private function createFirewall(array $config = []): Firewall
    {
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $ref->newInstanceWithoutConstructor();
        $constructor = $ref->getConstructor();
        $constructor->setAccessible(true);
        $constructor->invoke($firewall, $this->storage, $this->blockManager, $this->bypassManager, $config);
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

    public function testLogModeDoesNotWriteStorage(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '1.2.3.4']);
        $request->attributes->set('x-request-id', 'log-test');

        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('Blocker');
        $plugin->method('getStatusCode')->willReturn(403);

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn($plugin);
        $this->storage->expects($this->never())->method('set');

        $firewall = $this->createFirewall(['mode' => 'log']);
        $firewall->evaluate($request);
    }

    public function testLogModeSkipsStorageCheck(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '1.2.3.4']);
        $request->attributes->set('x-request-id', 'log-test');

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn(false);
        $this->storage->expects($this->never())->method('isBlocked');

        $firewall = $this->createFirewall(['mode' => 'log']);
        $firewall->evaluate($request);
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

    public function testBlockModeDefaultBehavior(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '5.6.7.8']);
        $request->attributes->set('x-request-id', 'block-test');

        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('Blocker');
        $plugin->method('getExpirationTime')->willReturn(600);
        $plugin->method('getStatusCode')->willReturn(403);

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn($plugin);

        $firewall = $this->createFirewall(['mode' => 'block']);

        $this->expectException(FirewallBlockedException::class);
        $this->expectExceptionCode(403);
        $firewall->evaluate($request);
    }

    public function testInvalidModeDefaultsToBlock(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '5.6.7.8']);
        $request->attributes->set('x-request-id', 'invalid-test');

        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('Blocker');
        $plugin->method('getExpirationTime')->willReturn(600);
        $plugin->method('getStatusCode')->willReturn(403);

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn($plugin);

        $firewall = $this->createFirewall(['mode' => 'invalid_mode']);

        $this->expectException(FirewallBlockedException::class);
        $this->expectExceptionCode(403);
        $firewall->evaluate($request);
    }

    public function testNoModeConfigDefaultsToBlock(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '5.6.7.8']);
        $request->attributes->set('x-request-id', 'default-test');

        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('Blocker');
        $plugin->method('getExpirationTime')->willReturn(600);
        $plugin->method('getStatusCode')->willReturn(403);

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn($plugin);

        $firewall = $this->createFirewall([]);

        $this->expectException(FirewallBlockedException::class);
        $this->expectExceptionCode(403);
        $firewall->evaluate($request);
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
