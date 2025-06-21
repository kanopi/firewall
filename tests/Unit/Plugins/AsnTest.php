<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use GeoIp2\Database\Reader;
use GeoIp2\Model\Asn as AsnModel;
use Kanopi\Firewall\Plugins\Asn;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Unit tests for the ASN plugin.
 */
class AsnTest extends TestCase
{
    /**
     * Returns a testable Asn plugin with a mocked GeoIP2 reader.
     */
    private function createPluginWithMockReader(?Reader $mockReader = null): Asn
    {
        if ($mockReader === null) {
            $model = new AsnModel([
                'autonomous_system_number' => 12345,
                'autonomous_system_organization' => 'MockOrg',
                'ip_address' => '127.0.0.1',
                'prefix_len' => 24,
            ]);

            $mockReader = $this->createMock(Reader::class);
            $mockReader->method('asn')->willReturn($model);
        }

        return new class(['reader' => ['type' => 'mock', 'instance' => $mockReader]]) extends Asn {
            protected function createService(string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return $config['instance'] ?? null;
            }
        };
    }

    /** Tests the plugin name string. */
    public function testGetName(): void
    {
        $plugin = $this->createPluginWithMockReader();
        $this->assertSame('Autonomous System Network', $plugin->getName());
    }

    /** Tests the plugin description string. */
    public function testGetDescription(): void
    {
        $plugin = $this->createPluginWithMockReader();
        $this->assertSame('Evaluate the GeoLocation Details', $plugin->getDescription());
    }

    /** Tests evaluate() returns false when reader is null. */
    public function testEvaluateReturnsFalseIfReaderIsNull(): void
    {
        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => null]]) extends Asn {
            protected function createService(string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return null;
            }
        };

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '1.1.1.1']);
        $this->assertFalse($plugin->evaluate($request));
    }

    /** Tests getRequestValue returns false if the reader is null. */
    public function testGetRequestValueReturnsFalseIfReaderIsNull(): void
    {
        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => null]]) extends Asn {
            protected function createService(string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return null;
            }
        };

        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getRequestValue');
        $method->setAccessible(true);

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '1.1.1.1']);
        $this->assertFalse($method->invoke($plugin, $request, 'asn'));
    }

    /** Tests getRequestValue returns null when reader throws exception. */
    public function testGetRequestValueReturnsNullOnException(): void
    {
        $reader = $this->createMock(Reader::class);
        $reader->method('asn')->willThrowException(new \RuntimeException("Simulated failure"));

        $plugin = $this->createPluginWithMockReader($reader);
        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getRequestValue');
        $method->setAccessible(true);

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '9.9.9.9']);
        $this->assertNull($method->invoke($plugin, $request, 'asn'));
    }

    /** Tests getRequestValue returns ASN and ASN Org from valid reader. */
    public function testGetRequestValueExtractsAsnData(): void
    {
        $asnModel = new AsnModel([
            'autonomous_system_number' => 15169,
            'autonomous_system_organization' => 'Google LLC',
            'ip_address' => '127.0.0.1',
            'prefix_len' => 24,
        ]);

        $reader = $this->createMock(Reader::class);
        $reader->method('asn')->willReturn($asnModel);

        $plugin = $this->createPluginWithMockReader($reader);
        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getRequestValue');
        $method->setAccessible(true);

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '127.0.0.1']);
        $this->assertSame(15169, $method->invoke($plugin, $request, 'asn'));
        $this->assertSame('Google LLC', $method->invoke($plugin, $request, 'asn_org'));
    }

    /** Tests getRequestValue returns null for unsupported variable keys. */
    public function testGetRequestValueReturnsNullForUnsupportedKeys(): void
    {
        $plugin = $this->createPluginWithMockReader();
        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getRequestValue');
        $method->setAccessible(true);

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '3.3.3.3']);
        $this->assertNull($method->invoke($plugin, $request, 'unsupported_key'));
    }

    /**
     * Tests that evaluateRequest() is called from evaluate().
     * We override evaluateRequest() and return true, while using a mock Reader.
     */
    public function testEvaluateUsesEvaluateRequest(): void
    {
        $reader = $this->createMock(\GeoIp2\Database\Reader::class);
        $reader->method('asn')->willReturn(new \GeoIp2\Model\Asn([
            'autonomous_system_number' => 1,
            'autonomous_system_organization' => 'MockOrg',
            'ip_address' => '127.0.0.1',
            'prefix_len' => 24,
        ]));

        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => $reader]]) extends Asn {
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
        $this->assertTrue($plugin->wasCalled, 'evaluateRequest() should be called');
    }

    /**
     * Tests getRequestValue returns false if reader does not have the asn() method.
     * This uses GeoIp2\WebService\Client which lacks an asn() method by design.
     */
    public function testGetRequestValueReturnsFalseIfMethodMissing(): void
    {
        $reader = $this->createMock(\GeoIp2\WebService\Client::class); // ✅ client has no `asn()`

        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => $reader]]) extends \Kanopi\Firewall\Plugins\Asn {
            protected function createService(string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return $config['instance'];
            }
        };

        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getRequestValue');
        $method->setAccessible(true);

        $request = new \Symfony\Component\HttpFoundation\Request([], [], [], [], [], ['REMOTE_ADDR' => '8.8.8.8']);
        $this->assertFalse($method->invoke($plugin, $request, 'asn'), 'Should return false when asn method is missing');
    }
}
