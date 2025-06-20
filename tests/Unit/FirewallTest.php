<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Storage\StorageInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;

class FirewallTest extends TestCase {
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
    private function createFirewall(): Firewall {
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $ref->newInstanceWithoutConstructor();
        $constructor = $ref->getConstructor();
        $constructor->setAccessible(true);
        $constructor->invoke($firewall, $this->storage, $this->blockManager, $this->bypassManager);
        return $firewall;
    }

    /**
     * Ensure bypass plugin short-circuits evaluation and returns true.
     */
    public function testEvaluateBypassPluginAllows(): void {
        $request = Request::create('/');
        $this->bypassManager->method('evaluate')->willReturn(true);
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
        $this->storage->method('get')->willReturn(['event_id' => 'mock-blocked']);
        $this->storage->expects($this->once())->method('addToExpire');

        $firewall = $this->createFirewall();
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('mock-blocked Request Banned');
        $this->expectExceptionCode(400);
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
        $this->storage->method('get')->willReturn(false);
        $this->storage->expects($this->once())->method('set')->willReturn(true);

        $this->blockManager->expects($this->once())->method('evaluate')->willReturnCallback(function ($r, $b, $cb) use ($plugin) {
            $cb(true, $r, $plugin);
        });

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
        $this->storage->method('get')->willReturn(false);
        $this->blockManager->expects($this->once())->method('evaluate');
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
     * Ensure blockIp() stores all expected data and returns true.
     */
    public function testBlockIpReturnsTrue(): void {
        $request = Request::create('/', 'GET', [], ['foo' => 'bar'], [], ['REMOTE_ADDR' => '1.1.1.1']);
        $request->attributes->set('x-request-id', 'abc123');
        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('TestPlugin');
        $plugin->method('getExpirationTime')->willReturn(600);

        $this->storage->expects($this->once())->method('set')->willReturn(true);
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('blockIp');
        $method->setAccessible(true);
        $result = $method->invoke($firewall, $request, $plugin);
        $this->assertTrue($result);
    }

    /**
     * Ensure uploaded files are normalized correctly into arrays.
     */
    public function testFormatUploadedFiles(): void {
        $file = $this->createMock(UploadedFile::class);
        $file->method('getClientOriginalName')->willReturn('test.jpg');
        $file->method('getClientMimeType')->willReturn('image/jpeg');
        $file->method('getSize')->willReturn(1234);
        $file->method('getError')->willReturn(0);

        $firewall = $this->createFirewall();
        $ref = new \ReflectionClass(Firewall::class);
        $method = $ref->getMethod('formatUploadedFiles');
        $method->setAccessible(true);

        $result = $method->invoke($firewall, ['file' => $file]);
        $this->assertEquals([
            'file' => [
                'originalName' => 'test.jpg',
                'mimeType' => 'image/jpeg',
                'size' => 1234,
                'error' => 0,
            ]
        ], $result);
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
}