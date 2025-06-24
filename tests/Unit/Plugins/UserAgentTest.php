<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use DeviceDetector\DeviceDetector;
use Kanopi\Firewall\Plugins\UserAgent;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Tests the UserAgent plugin class.
 */
class UserAgentTest extends TestCase
{
    /**
     * Creates a testable UserAgent plugin with mocked DeviceDetector.
     */
    protected function createPluginWithMockDetector(MockObject $mockDetector): UserAgent
    {
        return new class([], []) extends UserAgent {
            public DeviceDetector $mockedDetector;

            public function setMockedDetector(DeviceDetector $mock): void
            {
                $this->mockedDetector = $mock;
            }

            protected function detectDevice(string $userAgent): DeviceDetector
            {
                return $this->mockedDetector;
            }

            public function getRequestValueWrapper(Request $request, string $variable): mixed
            {
                return $this->getRequestValue($request, $variable);
            }

            public function getValueWrapper(Request $request, string $variable): mixed
            {
                return $this->getValue($request, $variable);
            }
        };
    }

    /**
     * Tests that getName returns correct string.
     */
    public function testGetName(): void
    {
        $plugin = new UserAgent([], []);
        $this->assertSame('User Agent', $plugin->getName());
    }

    /**
     * Tests that getDescription returns correct string.
     */
    public function testGetDescription(): void
    {
        $plugin = new UserAgent([], []);
        $this->assertSame('Evaluate the User Agent', $plugin->getDescription());
    }

    /**
     * Tests that evaluate returns false by default.
     */
    public function testEvaluateReturnsFalse(): void
    {
        $request = new Request([], [], [], [], [], ['HTTP_USER_AGENT' => '']);
        $mockDetector = $this->createMock(DeviceDetector::class);
        $plugin = $this->createPluginWithMockDetector($mockDetector);
        $plugin->setMockedDetector($mockDetector);

        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * Tests getRequestValue returns null for invalid/empty input.
     */
    public function testGetRequestValueReturnsNullOnEmpty(): void
    {
        $plugin = new class([], []) extends UserAgent {
            protected function detectDevice(string $userAgent): DeviceDetector
            {
                return $this->createMock(DeviceDetector::class);
            }

            public function getRequestValueWrapper(Request $request, string $variable): mixed
            {
                return $this->getRequestValue($request, $variable);
            }
        };

        $request = Request::create('/');
        $this->assertNull($plugin->getRequestValueWrapper($request, ''));
        $this->assertNull($plugin->getRequestValueWrapper($request, 'nonexistent'));
    }

    /**
     * Tests getRequestValue for bot detection.
     */
    public function testGetRequestValueForBot(): void
    {
        $mock = $this->createMock(DeviceDetector::class);
        $mock->method('isBot')->willReturn(true);
        $mock->method('getBot')->willReturn(['name' => 'Googlebot']);

        $plugin = $this->createPluginWithMockDetector($mock);
        $plugin->setMockedDetector($mock);

        $request = Request::create('/');
        $plugin->evaluate($request);
        $this->assertSame('true', $plugin->getRequestValueWrapper($request, 'bot'));
        $this->assertSame('Googlebot', $plugin->getRequestValueWrapper($request, 'bot.name'));
    }

    /**
     * Tests getRequestValue for client, os, device, brand, model with nested keys.
     */
    public function testGetRequestValueForVariousFields(): void
    {
        $mock = $this->createMock(DeviceDetector::class);
        $mock->method('isBot')->willReturn(false);
        $mock->method('getClient')->willReturn(['name' => 'Firefox', 'version' => '89.0']);
        $mock->method('getOs')->willReturn(['name' => 'Windows', 'short_name' => 'WIN']);
        $mock->method('getDeviceName')->willReturn('desktop');
        $mock->method('getBrandName')->willReturn('Dell');
        $mock->method('getModel')->willReturn('Inspiron');

        $plugin = $this->createPluginWithMockDetector($mock);
        $plugin->setMockedDetector($mock);

        $request = Request::create('/');
        $plugin->evaluate($request);

        $this->assertSame('Firefox', $plugin->getRequestValueWrapper($request, 'client.name'));
        $this->assertSame('Windows', $plugin->getRequestValueWrapper($request, 'os.name'));
        $this->assertSame('desktop', $plugin->getRequestValueWrapper($request, 'device.type'));
        $this->assertSame('Dell', $plugin->getRequestValueWrapper($request, 'brand'));
        $this->assertSame('Inspiron', $plugin->getRequestValueWrapper($request, 'model'));
    }

    /**
     * Tests getRequestValue returns null when nested key is not found.
     */
    public function testGetRequestValueWithMissingNestedKey(): void
    {
        $mock = $this->createMock(DeviceDetector::class);
        $mock->method('getClient')->willReturn(['name' => 'Chrome']);

        $plugin = $this->createPluginWithMockDetector($mock);
        $plugin->setMockedDetector($mock);

        $request = Request::create('/');
        $plugin->evaluate($request);

        $this->assertNull($plugin->getRequestValueWrapper($request, 'client.nonexistent'));
        $this->assertNull($plugin->getValueWrapper($request, ''));
    }

    /**
     * Tests that detectDevice parses user agent string and returns a valid DeviceDetector object.
     */
    public function testDetectDeviceParsesUserAgent(): void
    {
        $plugin = new class([], []) extends UserAgent {
            public function detectDeviceWrapper(string $ua): DeviceDetector
            {
                return $this->detectDevice($ua);
            }
        };

        $userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36';
        $deviceDetector = $plugin->detectDeviceWrapper($userAgent);

        $this->assertInstanceOf(DeviceDetector::class, $deviceDetector);
        $this->assertFalse($deviceDetector->isBot());
        $this->assertEquals('desktop', $deviceDetector->getDeviceName());
    }
}
