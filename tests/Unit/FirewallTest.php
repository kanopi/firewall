<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Storage\StorageInterface;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\HttpFoundation\Request;

class FirewallTest extends AbstractTestCase
{
    private StorageInterface&MockObject $storage;
    private PluginManager&MockObject $blockManager;
    private PluginManager&MockObject $bypassManager;

    protected function setUp(): void {
        parent::setUp();
        $this->storage = $this->createMock(StorageInterface::class);
        $this->blockManager = $this->createMock(PluginManager::class);
        $this->bypassManager = $this->createMock(PluginManager::class);
    }

    /**
     * Creates a Firewall instance with protected constructor via reflection.
     */
    private function createFirewall(array $config = []): Firewall {
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $ref->newInstanceWithoutConstructor();
        $constructor = $ref->getConstructor();
        $constructor->setAccessible(true);
        $constructor->invoke($firewall, $this->storage, $this->blockManager, $this->bypassManager, $config);
        return $firewall;
    }

    /**
     * Ensure bypass plugin short-circuits evaluation and returns true.
     */
    public function testEvaluateBypassPluginAllows(): void {
        $request = Request::create('/');
        $request->attributes->set('x-request-id', 'abc123');
        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('TestPlugin');
        $this->bypassManager->method('evaluate')->willReturn($plugin);
        $firewall = $this->createFirewall();
        $this->assertTrue($firewall->evaluate($request));
    }

    /**
     * Ensure blocked IP triggers sendBlockingResponse and stops evaluation.
     */
    public function testEvaluateBlockedIp(): void {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '1.2.3.4']);
        $request->attributes->set('x-request-id', 'mock-blocked');

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn(true);

        $firewall = $this->createFirewall();
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('mock-blocked Request Banned');
        $this->expectExceptionCode(400);
        $firewall->evaluate($request);
    }

    /**
     * Ensure blocked IP triggers sendBlockingResponse and stops evaluation.
     */
    public function testEvaluateBlockedIpCustomStatusMessage(): void {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '1.2.3.4']);
        $request->attributes->set('x-request-id', 'mock-blocked');

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn(true);

        $firewall = $this->createFirewall(['banning_status_code' => 429, 'banning_message' => 'You are banned']);
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('You are banned');
        $this->expectExceptionCode(429);
        $firewall->evaluate($request);
    }

    /**
     * Ensure blocking plugin can block and invoke sendBlockingResponse().
     */
    public function testEvaluateBlockingPluginBlocks(): void {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '5.6.7.8']);
        $request->attributes->set('x-request-id', 'plugin-id');

        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('Blocker');
        $plugin->method('getExpirationTime')->willReturn(600);
        $plugin->method('getStatusCode')->willReturn(403);

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn(false);

        $this->blockManager->expects($this->once())->method('evaluate')->willReturn($plugin);
        $this->storage->method('blockIp');

        $firewall = $this->createFirewall();
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('plugin-id Request Banned');
        $this->expectExceptionCode(403);
        $firewall->evaluate($request);
    }

    /**
     * Ensure request not bypassed and not blocked continues to pass through.
     */
    public function testEvaluateContinuesIfNotBlocked(): void {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '9.9.9.9']);
        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn(false);
        $firewall = $this->createFirewall();
        $this->assertTrue($firewall->evaluate($request));
    }

    /**
     * Ensure generated request ID is uppercase 32-character hash.
     */
    public function testGenerateIdReturnsValidHash(): void {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '8.8.8.8']);
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('generateId');
        $method->setAccessible(true);
        $id = $method->invoke($firewall, $request);
        $this->assertMatchesRegularExpression('/^[A-F0-9]{32}$/', $id);
    }

    /**
     * Test the Firewall::create method.
     */
    public function testStaticCreate(): void
    {
        $firewall = Firewall::create();
        $this->assertInstanceOf(Firewall::class, $firewall);
    }

    /**
     * Test the Firewall::evaluate creates Request.
     */
    public function testEvaluate(): void
    {
        $firewall = Firewall::create();
        $response = $firewall->evaluate();
        $this->assertTrue($response);
    }

    /**
     * Test the Interpolate Template function with GET.
     */
    public function testInterpolateTemplateGet(): void {
        $request = Request::create('/', 'GET', ['abc' => '123'], [], [], [
            'REMOTE_ADDR' => '8.8.8.8',
            'HTTP_HOST' => 'localhost',
            'HTTP_PORT' => 80,
            'HTTP_ACCEPT' => 'text/html',
        ]);
        $request->attributes->set('x-request-id', 'ABC123');
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('interpolateTemplate');
        $method->setAccessible(true);

        $message = '{{request.id}} Request Banned';
        $result = $method->invoke($firewall, $message, $request);
        $this->assertEquals('ABC123 Request Banned', $result);

        $message = '{{request.scheme}} {{request.method}} {{request.host}} {{request.ip}} {{request.path}} {{request.query.abc}} {{request.header.accept}}';
        $result = $method->invoke($firewall, $message, $request);
        $this->assertEquals('http GET localhost 8.8.8.8 / 123 text/html', $result);
    }

    /**
     * Test the Interpolate Template function with POST.
     */
    public function testInterpolateTemplatePost(): void
    {
        $request = Request::create('/', 'POST', ['abc' => '123'], [
            'X-REQUEST-ID' => 'ABC123',
        ], [], [
            'REMOTE_ADDR' => '8.8.8.8',
            'HTTP_HOST' => 'localhost',
            'HTTP_PORT' => 80,
            'HTTP_ACCEPT' => 'text/html',
        ]);
        $request->attributes->set('x-request-id', 'ABC123');
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('interpolateTemplate');
        $method->setAccessible(true);

        $message = '{{request.scheme}} {{request.method}} {{request.host}} {{request.ip}} {{request.path}} {{request.post.abc}} {{request.header.accept}} {{request.cookie.X-REQUEST-ID}} {{notfound}} {{context-element}}';
        $result = $method->invoke($firewall, $message, $request, ['context-element' => 'context']);
        $this->assertEquals('http POST localhost 8.8.8.8 / 123 text/html ABC123 {{notfound}} context', $result);
    }
}