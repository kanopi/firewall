<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use GeoIp2\WebService\Client;
use Kanopi\Firewall\Plugins\GeoLocationTrait;
use PHPUnit\Framework\TestCase;

class GeoLocationTraitTest extends TestCase
{
    /**
     * Create a trait wrapper instance for testing.
     */
    protected function createTestInstance(): object
    {
        return new class {
            use GeoLocationTrait {
                createService as public;
                getReader as public;
                getClient as public;
            }
        };
    }

    /**
     * Tests createService() with type = reader and a valid file.
     */
    public function testCreateServiceWithReaderReturnsNullForMissingFile(): void
    {
        $trait = $this->createTestInstance();
        $result = $trait->createService('reader', ['db' => '/nonexistent/file.mmdb']);

        $this->assertNull($result, 'Expected null when DB file is missing');
    }

    /**
     * Tests createService() returns null for unknown type.
     */
    public function testCreateServiceWithUnknownType(): void
    {
        $trait = $this->createTestInstance();
        $result = $trait->createService('unknown');
        $this->assertNull($result, 'Expected null for unknown service type');
    }

    /**
     * Tests getReader() returns null when file does not exist.
     */
    public function testGetReaderReturnsNullForMissingFile(): void
    {
        $trait = $this->createTestInstance();
        $this->assertNull($trait->getReader('/path/to/nowhere.mmdb'));
    }

    /**
     * Tests getReader() returns null if exception thrown during reader creation.
     */
    public function testGetReaderReturnsNullOnInvalidDatabaseException(): void
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'geo');
        file_put_contents($tempFile, 'invalid content');

        $trait = $this->createTestInstance();
        $reader = $trait->getReader($tempFile);
        $this->assertNull($reader, 'Expected null when InvalidDatabaseException is thrown');

        unlink($tempFile);
    }

    /**
     * Tests getClient returns a GeoIp2 WebService Client object.
     */
    public function testGetClientReturnsInstance(): void
    {
        $trait = $this->createTestInstance();
        $client = $trait->getClient(123, 'license-key');

        $this->assertInstanceOf(Client::class, $client);
    }

    /**
     * Tests createService() with type = client returns Client object.
     */
    public function testCreateServiceWithClient(): void
    {
        $trait = $this->createTestInstance();
        $client = $trait->createService('client', [
            'accountId' => 123,
            'licenseKey' => 'abc123',
        ]);

        $this->assertInstanceOf(Client::class, $client);
    }
}
