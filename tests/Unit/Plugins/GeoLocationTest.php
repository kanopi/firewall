<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use GeoIp2\Model\City;
use Kanopi\Firewall\Plugins\GeoLocation;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

class GeoLocationTest extends TestCase
{
    /**
     * Tests getName() returns the expected plugin name.
     */
    public function testGetName(): void
    {
        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => null]]) extends GeoLocation {
            protected function createService(string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return null;
            }
        };

        $this->assertEquals('GeoLocation', $plugin->getName());
    }

    /**
     * Tests getDescription() returns the expected description.
     */
    public function testGetDescription(): void
    {
        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => null]]) extends GeoLocation {
            protected function createService(string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return null;
            }
        };

        $this->assertEquals('Evaluate the GeoLocation Details', $plugin->getDescription());
    }

    /**
     * Tests evaluate() returns false when reader is null.
     */
    public function testEvaluateReturnsFalseIfReaderIsNull(): void
    {
        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => null]]) extends GeoLocation {
            protected function createService(string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return null;
            }
        };

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '8.8.8.8']);
        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * Tests evaluate() calls evaluateRequest().
     */
    public function testEvaluateCallsEvaluateRequest(): void
    {
        $reader = $this->createMock(\GeoIp2\Database\Reader::class);
        $reader->method('city')->willReturn($this->createMock(City::class));

        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => $reader]]) extends GeoLocation {
            public bool $wasCalled = false;

            protected function createService(string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return $config['instance'];
            }

            public function evaluateRequest(Request $request, array $config = []): bool {
                $this->wasCalled = true;
                return true;
            }
        };

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '8.8.8.8']);
        $this->assertTrue($plugin->evaluate($request));
        $this->assertTrue($plugin->wasCalled);
    }

    /**
     * Tests getRequestValue returns null on exception.
     */
    public function testGetRequestValueReturnsNullOnException(): void
    {
        $reader = $this->createMock(\GeoIp2\Database\Reader::class);
        $reader->method('city')->willThrowException(new \Exception());

        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => $reader]]) extends GeoLocation {
            protected function createService(string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return $config['instance'];
            }
        };

        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getRequestValue');
        $method->setAccessible(true);
        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '1.2.3.4']);

        $this->assertNull($method->invoke($plugin, $request, 'country'));
    }

    /**
     * Tests getRequestValue returns correct values from GeoIP City model.
     */
    public function testGetRequestValueReturnsGeoComponents(): void
    {
        $cityModel = new \GeoIp2\Model\City([
            'city' => ['names' => ['en' => 'New York']],
            'continent' => ['code' => 'NA'],
            'country' => ['iso_code' => 'US'],
            'location' => ['latitude' => 40.7128, 'longitude' => -74.0060],
            'postal' => ['code' => '10001'],
            'subdivisions' => [['iso_code' => 'NY']],
            'registered_country' => ['iso_code' => 'US'],
            'represented_country' => ['iso_code' => 'US'],
            'traits' => ['is_anonymous_proxy' => false],
            'maxmind' => [],
            'ip_address' => '1.2.3.4',
        ], ['en']);


        $reader = $this->createMock(\GeoIp2\Database\Reader::class);
        $reader->method('city')->willReturn($cityModel);

        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => $reader]]) extends GeoLocation {
            protected function createService(string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return $config['instance'];
            }
        };

        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getRequestValue');
        $method->setAccessible(true);
        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '1.2.3.4']);

        $this->assertEquals('US', $method->invoke($plugin, $request, 'country'));
        $this->assertEquals('NA', $method->invoke($plugin, $request, 'continent'));
        $this->assertEquals('New York', $method->invoke($plugin, $request, 'city'));
        $this->assertEquals(40.7128, $method->invoke($plugin, $request, 'location.latitude'));
        $this->assertEquals('10001', $method->invoke($plugin, $request, 'postal.code'));
    }

    /**
     * Tests getRequestValue returns null for unsupported keys.
     */
    public function testGetRequestValueReturnsNullForUnsupported(): void
    {
        $cityModel = new City([
            'city' => ['name' => 'New York'],
            'continent' => ['code' => 'NA'],
            'country' => ['iso_code' => 'US'],
            'location' => ['latitude' => 40.7128],
            'postal' => ['code' => '10001'],
            'subdivisions' => [['iso_code' => 'NY']],
            'registered_country' => ['iso_code' => 'US'],
            'represented_country' => ['iso_code' => 'US'],
            'traits' => ['is_anonymous_proxy' => false],
            'maxmind' => [],
            'ip_address' => '1.2.3.4',
        ], ['en']);

        $reader = $this->createMock(\GeoIp2\Database\Reader::class);
        $reader->method('city')->willReturn($cityModel);

        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => $reader]]) extends GeoLocation {
            protected function createService(string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return $config['instance'];
            }
        };

        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getRequestValue');
        $method->setAccessible(true);
        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '1.2.3.4']);

        $this->assertNull($method->invoke($plugin, $request, 'unsupported_key'));
    }

    /**
     * Tests getRequestValue returns false if the reader is null.
     */
    public function testGetRequestValueReturnsFalseIfReaderIsNull(): void
    {
        // Plugin with a null reader
        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => null]]) extends \Kanopi\Firewall\Plugins\GeoLocation {
            protected function createService(string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return null;
            }
        };

        // Use reflection to call the protected method
        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getRequestValue');
        $method->setAccessible(true);

        $request = new \Symfony\Component\HttpFoundation\Request([], [], [], [], [], ['REMOTE_ADDR' => '1.2.3.4']);

        $this->assertFalse($method->invoke($plugin, $request, 'country'), 'Expected false when reader is null');
    }

    /**
     * Tests getRequestValue returns false if the reader is null.
     */
    public function testGetRequestValueReturnsNullIfEmptyStringProvided(): void
    {
        $reader = $this->createMock(\GeoIp2\Database\Reader::class);

        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => $reader]]) extends \Kanopi\Firewall\Plugins\GeoLocation {
            protected function createService(string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return $config['instance'];
            }
        };

        // Use reflection to call the protected method
        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getValue');
        $method->setAccessible(true);

        $request = new \Symfony\Component\HttpFoundation\Request([], [], [], [], [], ['REMOTE_ADDR' => '1.2.3.4']);

        $this->assertNull($method->invoke($plugin, $request, ''), 'Expected null when empty string');
    }
}
