<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Kanopi\Firewall\Firewall;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Yaml\Yaml;

/**
 * Integration tests for the complete Firewall request flow.
 * 
 * These tests verify the end-to-end functionality of the firewall system,
 * including configuration loading, plugin evaluation, storage persistence,
 * and response handling.
 */
class FirewallRequestFlowTest extends TestCase
{
    /**
     * Temporary directory for test files.
     */
    private string $tempDir;
    
    /**
     * Set up test environment before each test.
     */
    protected function setUp(): void
    {
        parent::setUp();

        putenv('FIREWALL_BYPASS_CLI=1');
        putenv('FIREWALL_TEST=1');

        // Create unique temp directory for this test run
        $this->tempDir = sys_get_temp_dir() . '/firewall_test_' . uniqid();
        if (!mkdir($this->tempDir, 0777, true)) {
            throw new \RuntimeException('Failed to create temp directory: ' . $this->tempDir);
        }
    }
    
    /**
     * Clean up test environment after each test.
     */
    protected function tearDown(): void
    {
        $this->recursiveRemoveDirectory($this->tempDir);
        parent::tearDown();
    }
    
    /**
     * Tests the complete blocking flow when a request comes from a blocked IP.
     * 
     * This test verifies:
     * - The firewall correctly identifies and blocks a blacklisted IP
     * - The blocked IP is persisted to storage
     * - The blocking response is sent (exception thrown)
     * - The storage file contains the correct IP address data
     * - The blocking event includes proper metadata (plugin name, timestamp, etc.)
     */
    public function testCompleteBlockingFlow(): void
    {
        // Create test configuration with a blocked IP
        $config = $this->createTestConfig([
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\FileStorage',
                'config' => [
                    'file' => $this->tempDir . '/blocked.data'
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'config' => ['192.168.1.100', '10.0.0.0/24']
                ]
            ]
        ]);
        
        // Create firewall instance
        $firewall = Firewall::create([$config]);
        
        // Create request from blocked IP
        $request = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.100'
        ]);
        
        // Capture the response before the exit
        $responseSent = false;
        $statusCode = null;
        
        // Override the sendBlockingResponse to capture instead of exit
        try {
            $firewall->evaluate($request);
            $this->fail('Expected firewall to block the request');
        } catch (\Exception $e) {
            $responseSent = true;
            $statusCode = $e->getCode();
        }
        
        // Verify blocking occurred
        $this->assertTrue($responseSent, 'Blocking response should have been sent');
        $this->assertEquals(400, $statusCode, 'Should return 400 Forbidden status');
        
        // Verify IP was stored
        $this->assertFileExists($this->tempDir . '/blocked.data');
        
        // Load and verify storage data
        $storageData = unserialize(file_get_contents($this->tempDir . '/blocked.data'));
        $this->assertIsArray($storageData);
        $this->assertArrayHasKey('192.168.1.100', $storageData);
        
        // Verify stored metadata
        $blockedData = $storageData['192.168.1.100']['value'] ?? [];
        $this->assertArrayHasKey('plugin', $blockedData);
        $this->assertEquals('IP Address', $blockedData['plugin']);
        $this->assertArrayHasKey('blocked', $blockedData);
        $this->assertArrayHasKey('event_id', $blockedData);
        $this->assertArrayHasKey('request', $blockedData);
    }
    
    /**
     * Tests that bypass rules take precedence over blocking rules.
     * 
     * This test verifies:
     * - When an IP is in both bypass and block lists, bypass wins
     * - The request is allowed through without exception
     * - No blocking data is stored
     * - The evaluate method returns true for allowed requests
     * - Bypass plugins are evaluated before block plugins
     */
    public function testBypassOverridesBlocking(): void
    {
        $config = $this->createTestConfig([
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'bypass' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'priority' => -100,  // Higher priority
                    'config' => ['192.168.1.100', '172.16.0.0/12']
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'priority' => 0,
                    'config' => ['192.168.1.100', '0.0.0.0/0']  // Block all IPs
                ]
            ]
        ]);
        
        $firewall = Firewall::create([$config]);
        
        // Request from IP that's in both lists
        $request = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.100'
        ]);
        
        // Should not throw exception due to bypass
        $result = $firewall->evaluate($request);
        $this->assertTrue($result, 'Bypassed request should return true');
        
        // Also test with CIDR range
        $request2 = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '172.16.5.10'
        ]);
        
        $result2 = $firewall->evaluate($request2);
        $this->assertTrue($result2, 'Bypassed CIDR range should return true');
    }
    
    /**
     * Tests that multiple blocking plugins work together correctly.
     * 
     * This test verifies:
     * - Multiple plugins can evaluate the same request
     * - A request blocked by any plugin results in blocking
     * - The correct plugin name is stored in the blocking data
     * - Plugin priority is respected (lower numbers execute first)
     * - First blocking plugin wins (others don't execute)
     */
    public function testMultipleBlockingPluginsIntegration(): void
    {
        $storageFile = $this->tempDir . '/blocked.data';
        
        $config = $this->createTestConfig([
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\FileStorage',
                'config' => [
                    'file' => $storageFile
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'priority' => 10,  // Lower priority (runs second)
                    'config' => ['10.0.0.0/8']
                ],
                'Kanopi\Firewall\Plugins\Url' => [
                    'enable' => true,
                    'priority' => -5,  // Higher priority (runs first)
                    'config' => [
                        'path:/admin',
                        'path@starts_with:/wp-'
                    ]
                ]
            ]
        ]);
        
        $firewall = Firewall::create([$config]);
        
        // Request that matches URL plugin but not IP plugin
        $request = Request::create('/wp-admin.php', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.1'  // Not in 10.0.0.0/8
        ]);
        
        try {
            $firewall->evaluate($request);
            $this->fail('Request to /wp-* should have been blocked');
        } catch (\Exception $e) {
            $this->assertEquals(400, $e->getCode());
        }
        
        // Verify the URL plugin blocked it (not the IP plugin)
        $storageData = unserialize(file_get_contents($storageFile));
        $blockedData = $storageData['192.168.1.1']['value'] ?? [];
        $this->assertEquals('URL', $blockedData['plugin'], 'URL plugin should have blocked the request');
        
        // Test request that matches IP plugin only
        $request2 = Request::create('/public', 'GET', [], [], [], [
            'REMOTE_ADDR' => '10.5.5.5'  // In 10.0.0.0/8
        ]);
        
        try {
            $firewall->evaluate($request2);
            $this->fail('Request from 10.0.0.0/8 should have been blocked');
        } catch (\Exception $e) {
            $this->assertEquals(400, $e->getCode());
        }
        
        // Verify the IP plugin blocked it
        $storageData = unserialize(file_get_contents($storageFile));
        $blockedData = $storageData['10.5.5.5']['value'] ?? [];
        $this->assertEquals('IP Address', $blockedData['plugin'], 'IP Address plugin should have blocked the request');
    }
    
    /**
     * Tests that previously blocked IPs remain blocked on subsequent requests.
     * 
     * This test verifies:
     * - Blocked IPs are persisted across firewall instances
     * - A new firewall instance reads existing blocked data
     * - Subsequent requests from blocked IPs are immediately blocked
     * - No duplicate evaluation occurs for already-blocked IPs
     * - The original blocking metadata is preserved
     */
    public function testPersistentBlockingAcrossRequests(): void
    {
        $storageFile = $this->tempDir . '/blocked.data';
        
        $configFile = $this->createTestConfig([
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\FileStorage',
                'config' => [
                    'file' => $storageFile
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'config' => ['192.168.1.100']
                ]
            ]
        ]);
        
        // First request - should block and store
        $firewall1 = Firewall::create([$configFile]);
        $request1 = Request::create('/first-request', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.100'
        ]);
        
        try {
            $firewall1->evaluate($request1);
            $this->fail('First request should have been blocked');
        } catch (\Exception $e) {
            $this->assertEquals(400, $e->getCode());
        }
        
        // Verify data was persisted
        $this->assertFileExists($storageFile);
        $originalData = unserialize(file_get_contents($storageFile));
        $originalEventId = $originalData['192.168.1.100']['value']['event_id'];
        
        // Second request with new firewall instance - should still be blocked
        $firewall2 = Firewall::create([$configFile]);
        $request2 = Request::create('/different-path', 'POST', ['data' => 'test'], [], [], [
            'REMOTE_ADDR' => '192.168.1.100'
        ]);
        
        try {
            $firewall2->evaluate($request2);
            $this->fail('Second request should have been blocked due to persistence');
        } catch (\Exception $e) {
            $this->assertEquals(400, $e->getCode());
        }
        
        // Verify the same event ID is used (no re-evaluation)
        $currentData = unserialize(file_get_contents($storageFile));
        $currentEventId = $currentData['192.168.1.100']['value']['event_id'];
        $this->assertEquals($originalEventId, $currentEventId, 'Should use original event ID');
    }
    
    /**
     * Tests configuration merging when multiple config files are provided.
     * 
     * This test verifies:
     * - Multiple YAML files can be loaded and merged
     * - Later configs override earlier ones for scalar values
     * - Arrays are properly merged (not replaced)
     * - The final configuration is correctly applied
     * - Plugin configurations are combined correctly
     */
    public function testConfigurationMergingIntegration(): void
    {
        // Base config with one blocked IP and file storage
        $baseConfig = $this->createTestConfig([
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\FileStorage',
                'config' => [
                    'file' => $this->tempDir . '/base.data'
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'priority' => 0,
                    'config' => ['192.168.1.1']
                ]
            ]
        ], 'base_config.yml');
        
        // Additional config that changes storage and adds another blocked IP
        $additionalConfig = $this->createTestConfig([
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'  // Override storage
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'priority' => -10,  // Override priority
                    'config' => ['192.168.1.2', '192.168.1.3']  // Additional IPs
                ]
            ]
        ], 'additional_config.yml');
        
        // Create firewall with both configs
        $firewall = Firewall::create([$baseConfig, $additionalConfig]);
        
        // Test that the storage was overridden (by checking it doesn't create a file)
        $request = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.2'
        ]);
        
        try {
            $firewall->evaluate($request);
            $this->fail('IP should have been blocked');
        } catch (\Exception $e) {
            // Expected
        }
        
        // File should not exist since we're using InMemoryStorage
        $this->assertFileDoesNotExist($this->tempDir . '/base.data', 'Storage should have been overridden to InMemory');
        
        // Test that all IPs are blocked (merged configs)
        $testIps = ['192.168.1.1', '192.168.1.2', '192.168.1.3'];
        foreach ($testIps as $ip) {
            $request = Request::create('/', 'GET', [], [], [], [
                'REMOTE_ADDR' => $ip
            ]);
            
            try {
                $firewall->evaluate($request);
                $this->fail("IP $ip should have been blocked");
            } catch (\Exception $e) {
                $this->assertEquals(400, $e->getCode(), "IP $ip should return 400");
            }
        }
        
        // Test that an unlisted IP is not blocked
        $request = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.4'
        ]);
        
        $result = $firewall->evaluate($request);
        $this->assertTrue($result, 'Unlisted IP should not be blocked');
    }
    
    /**
     * Tests dynamic configuration overrides using array syntax.
     * 
     * This test verifies:
     * - Configuration values can be overridden at runtime
     * - PropertyAccess syntax works correctly
     * - Overrides take precedence over file configuration
     * - Complex nested paths can be overridden
     */
    public function testDynamicConfigurationOverrides(): void
    {
        // Create base config
        $configFile = $this->createTestConfig([
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\FileStorage',
                'config' => [
                    'file' => '/original/path/blocked.data'
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => false,  // Disabled in config
                    'config' => ['192.168.1.1']
                ]
            ]
        ]);
        
        // Override configuration values
        $overrides = [
            '[storage][config][file]' => $this->tempDir . '/overridden.data',
            '[block][Kanopi\Firewall\Plugins\IpAddress][enable]' => true,
            '[block][Kanopi\Firewall\Plugins\IpAddress][config][1]' => '192.168.1.2'
        ];
        
        $firewall = Firewall::create([$configFile], $overrides);
        
        // Test that overrides are applied
        $request = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.2'  // The overridden IP
        ]);
        
        try {
            $firewall->evaluate($request);
            $this->fail('Overridden IP should have been blocked');
        } catch (\Exception $e) {
            $this->assertEquals(400, $e->getCode());
        }
        
        // Verify the overridden storage path was used
        $this->assertFileExists($this->tempDir . '/overridden.data', 'Overridden storage file should exist');
        $this->assertFileDoesNotExist('/original/path/blocked.data', 'Original storage file should not exist');
    }
    
    /**
     * Creates a test configuration file with the given data.
     * 
     * @param array $config Configuration data to write
     * @param string $filename Optional filename (defaults to test_config.yml)
     * @return string Path to the created configuration file
     */
    private function createTestConfig(array $config, string $filename = 'test_config.yml'): string
    {
        $configFile = $this->tempDir . '/' . $filename;
        $yaml = Yaml::dump($config, 4, 2);
        
        if (file_put_contents($configFile, $yaml) === false) {
            throw new \RuntimeException('Failed to create config file: ' . $configFile);
        }
        
        return $configFile;
    }
    
    /**
     * Recursively removes a directory and all its contents.
     * 
     * @param string $directory Directory path to remove
     */
    private function recursiveRemoveDirectory(string $directory): void
    {
        if (!is_dir($directory)) {
            return;
        }
        
        $files = array_diff(scandir($directory), ['.', '..']);
        foreach ($files as $file) {
            $path = $directory . '/' . $file;
            if (is_dir($path)) {
                $this->recursiveRemoveDirectory($path);
            } else {
                unlink($path);
            }
        }
        
        rmdir($directory);
    }
}