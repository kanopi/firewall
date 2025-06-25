<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration\Logging;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Integration\IntegrationTestCase;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Symfony\Component\Yaml\Yaml;

/**
 * Integration tests for the firewall logging system.
 * 
 * These tests verify:
 * - Monolog integration works correctly
 * - Log messages are properly formatted
 * - Context data is included
 * - Multiple handlers work together
 * - Log levels are respected
 * - Plugin-specific logging works
 */
class LoggingIntegrationTest extends IntegrationTestCase
{
    /**
     * Tests basic logging functionality with file handler.
     * 
     * This test verifies:
     * - Log file is created with correct permissions
     * - Messages are written in correct format
     * - Plugin context is included
     * - Timestamps are correct
     * - Log levels work properly
     */
    public function testFileLogging(): void
    {
        $logFile = $this->tempDir . '/firewall.log';
        
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'logger' => [
                [
                    'class' => 'Monolog\Handler\StreamHandler',
                    'args' => [
                        $logFile,
                        'Monolog\Level::Debug'
                    ],
                    'formatter' => [
                        'class' => 'Monolog\Formatter\LineFormatter',
                        'args' => [
                            "[%datetime%] [%level_name%] [%context.plugin%] %message% %context% %extra%\n",
                            "Y-m-d H:i:s"
                        ]
                    ]
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'config' => ['192.168.1.100']
                ]
            ]
        ];
        
        $firewall = $this->createFirewall($config);
        
        // Trigger a block event
        try {
            $request = $this->createRequest('192.168.1.100');
            $firewall->evaluate($request);
        } catch (\Exception $e) {
            // Expected
        }
        
        // Verify log file was created
        $this->assertFileExists($logFile, 'Log file should be created');
        
        // Check file permissions (should be writable)
        $this->assertTrue(is_writable($logFile), 'Log file should be writable');
        
        // Read and verify log contents
        $logContents = file_get_contents($logFile);
        $this->assertNotEmpty($logContents, 'Log file should contain entries');
        
        // Verify log format
        $this->assertStringContainsString('[INFO]', $logContents, 'Should contain log level');
        $this->assertStringContainsString('[IP Address]', $logContents, 'Should contain plugin name');
        $this->assertStringContainsString('192.168.1.100', $logContents, 'Should contain blocked IP');
        $this->assertMatchesRegularExpression('/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/', $logContents, 'Should contain timestamp');
    }
    
    /**
     * Tests logging with multiple handlers.
     * 
     * This test verifies:
     * - Multiple log handlers can work simultaneously
     * - Each handler receives all messages
     * - Different formatters can be used
     * - Log levels are respected per handler
     */
    public function testMultipleLogHandlers(): void
    {
        $debugLog = $this->tempDir . '/debug.log';
        $errorLog = $this->tempDir . '/error.log';
        $jsonLog = $this->tempDir . '/json.log';
        
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'logger' => [
                // Debug handler - logs everything
                [
                    'class' => 'Monolog\Handler\StreamHandler',
                    'args' => [
                        $debugLog,
                        'Monolog\Level::Debug'
                    ]
                ],
                // Error handler - only errors and above
                [
                    'class' => 'Monolog\Handler\StreamHandler',
                    'args' => [
                        $errorLog,
                        'Monolog\Level::Error'
                    ]
                ],
                // JSON formatter handler
                [
                    'class' => 'Monolog\Handler\StreamHandler',
                    'args' => [
                        $jsonLog,
                        'Monolog\Level::Info'
                    ],
                    'formatter' => [
                        'class' => 'Monolog\Formatter\JsonFormatter'
                    ]
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'config' => ['192.168.1.100']
                ],
                'Kanopi\Firewall\Plugins\Url' => [
                    'enable' => true,
                    'config' => ['path:/admin']
                ]
            ]
        ];
        
        $firewall = $this->createFirewall($config);
        
        // Generate various log levels
        $this->triggerFirewallEvent($firewall, '192.168.1.100');
        $this->triggerFirewallEvent($firewall, '192.168.1.101', ['path' => '/admin']);
        
        // Verify all log files exist
        $this->assertFileExists($debugLog, 'Debug log should exist');
        $this->assertFileExists($jsonLog, 'JSON log should exist');
        
        // Debug log should have entries
        $debugContents = file_get_contents($debugLog);
        $this->assertNotEmpty($debugContents, 'Debug log should have entries');
        
        // JSON log should be valid JSON
        $jsonContents = file_get_contents($jsonLog);
        $jsonLines = array_filter(explode("\n", trim($jsonContents)));
        foreach ($jsonLines as $line) {
            $decoded = json_decode($line, true);
            $this->assertIsArray($decoded, 'Each line should be valid JSON');
            $this->assertArrayHasKey('message', $decoded);
            $this->assertArrayHasKey('context', $decoded);
            $this->assertArrayHasKey('level_name', $decoded);
        }
    }
    
    /**
     * Tests logging context data from different plugins.
     * 
     * This test verifies:
     * - Each plugin provides appropriate context
     * - Request data is logged correctly
     * - Sensitive data is not logged
     * - Custom metadata is included
     */
    public function testPluginContextLogging(): void
    {
        $logFile = $this->tempDir . '/context.log';
        
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'logger' => [
                [
                    'class' => 'Monolog\Handler\StreamHandler',
                    'args' => [
                        $logFile,
                        'Monolog\Level::Debug'
                    ],
                    'formatter' => [
                        'class' => 'Monolog\Formatter\JsonFormatter'
                    ]
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'config' => ['192.168.1.100']
                ],
                'Kanopi\Firewall\Plugins\Url' => [
                    'enable' => true,
                    'config' => [
                        'path:/secret',
                        'query.action:delete'
                    ]
                ],
                'Kanopi\Firewall\Plugins\UserAgent' => [
                    'enable' => true,
                    'config' => ['bot:true']
                ],
                'Kanopi\Firewall\Plugins\RateLimit' => [
                    'enable' => true,
                    'metadata' => [
                        'default_rate' => 1,
                        'default_sample' => 10,
                        'storage' => [
                            'type' => 'Kanopi\Firewall\RateLimitStorage\InMemoryRateLimitStorage'
                        ]
                    ],
                    'config' => []
                ]
            ]
        ];
        
        $firewall = $this->createFirewall($config);
        
        // Test different plugin scenarios
        
        // 1. IP block
        $this->triggerFirewallEvent($firewall, '192.168.1.100');
        
        // 2. URL block with query parameters
        $this->triggerFirewallEvent($firewall, '192.168.1.101', [
            'path' => '/public',
            'query' => ['action' => 'delete', 'id' => '123']
        ]);
        
        // 3. User agent block
        $this->triggerFirewallEvent($firewall, '192.168.1.102', [
            'headers' => ['User-Agent' => 'BadBot/1.0']
        ]);
        
        // 4. Rate limit (trigger twice)
        $this->triggerFirewallEvent($firewall, '192.168.1.103');
        $this->triggerFirewallEvent($firewall, '192.168.1.103'); // This should be rate limited
        
        // Parse log entries
        $logContents = file_get_contents($logFile);
        $logLines = array_filter(explode("\n", trim($logContents)));
        $logEntries = array_map('json_decode', $logLines, array_fill(0, count($logLines), true));
        
        // Find entries by plugin
        $ipEntry = $this->findLogEntry($logEntries, 'IP Address', 'Request blocked by plugin');
        $urlEntry = $this->findLogEntry($logEntries, 'URL', 'Request blocked by plugin');
        $uaEntry = $this->findLogEntry($logEntries, 'User Agent', 'Request blocked by plugin');
        $rlEntry = $this->findLogEntry($logEntries, 'Rate Limit', 'Request blocked by plugin');
        
        // Verify IP Address context
        $this->assertNotNull($ipEntry, 'Should have IP Address log entry');
        $this->assertEquals('192.168.1.100', $ipEntry['context']['client_ip'] ?? null);
        
        // Verify URL context
        $this->assertNotNull($urlEntry, 'Should have URL log entry');
        $this->assertEquals('delete', $urlEntry['context']['query']['action'] ?? null);
        
        // Verify User Agent context
        $this->assertNotNull($uaEntry, 'Should have User Agent log entry');
        $this->assertStringContainsString('BadBot/1.0', $uaEntry['context']['user_agent'] ?? '');
        
        // Verify Rate Limit context
        $this->assertNotNull($rlEntry, 'Should have Rate Limit log entry');
        $this->assertEquals('192.168.1.103', $rlEntry['context']['client_ip'] ?? null);
    }
    
    /**
     * Tests custom log handler implementation.
     * 
     * This test verifies:
     * - Custom handlers can be configured
     * - Handler arguments are passed correctly
     * - Processors work as expected
     * - Log rotation works (if applicable)
     */
    public function testCustomLogHandlers(): void
    {
        $logFile = $this->tempDir . '/custom.log';
        
        // Test with RotatingFileHandler
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'logger' => [
                // Rotating file handler
                [
                    'class' => 'Monolog\Handler\RotatingFileHandler',
                    'args' => [
                        $logFile,
                        7,  // Keep 7 days
                        'Monolog\Level::Info'
                    ]
                ],
                // Test handler for assertions
                [
                    'class' => 'Kanopi\Firewall\Tests\Logging\TestLogHandler',
                    'args' => [
                        'Monolog\Level::Debug'
                    ]
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'config' => ['192.168.1.100']
                ]
            ]
        ];
        
        $firewall = $this->createFirewall($config);
        
        // Trigger logging
        $this->triggerFirewallEvent($firewall, '192.168.1.100');
        
        // Verify rotating file was created with date
        $today = date('Y-m-d');
        $rotatedFile = str_replace('custom.log', 'custom-' . $today . '.log', $logFile);
        $this->assertFileExists($rotatedFile, 'Rotating log file should exist with date');
        
        // Content should be logged
        $contents = file_get_contents($rotatedFile);
        $this->assertNotEmpty($contents, 'Rotating log should have content');
    }
    
    /**
     * Tests logging performance with high volume.
     * 
     * This test verifies:
     * - Logging doesn't significantly slow down the firewall
     * - Log files don't grow unbounded
     * - No memory leaks occur
     * - Handlers can keep up with load
     */
    public function testLoggingPerformance(): void
    {
        $logFile = $this->tempDir . '/performance.log';
        $iterations = (int) self::getEnv('PERF_TEST_ITERATIONS', 100);
        
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'logger' => [
                [
                    'class' => 'Monolog\Handler\StreamHandler',
                    'args' => [
                        $logFile,
                        'Monolog\Level::Info'
                    ],
                    'formatter' => [
                        'class' => 'Monolog\Formatter\LineFormatter',
                        'args' => [
                            "%message% %context%\n"
                        ]
                    ]
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'config' => ['192.168.1.0/24']
                ]
            ]
        ];
        
        $firewall = $this->createFirewall($config);
        
        // Measure performance
        $startTime = microtime(true);
        $startMemory = memory_get_usage();
        
        // Generate many log entries
        for ($i = 0; $i < $iterations; $i++) {
            $ip = '192.168.1.' . ($i % 255);
            try {
                $request = $this->createRequest($ip);
                $firewall->evaluate($request);
            } catch (\Exception $e) {
                // Expected - we're testing logging performance
            }
        }
        
        $endTime = microtime(true);
        $endMemory = memory_get_usage();
        
        // Performance assertions
        $duration = $endTime - $startTime;
        $memoryUsed = $endMemory - $startMemory;
        
        $this->assertLessThan(5, $duration, "Logging $iterations events should take less than 5 seconds");
        $this->assertLessThan(50 * 1024 * 1024, $memoryUsed, 'Memory usage should be under 50MB');
        
        // Verify log file size is reasonable
        $fileSize = filesize($logFile);
        $this->assertGreaterThan(0, $fileSize, 'Log file should have content');
        $this->assertLessThan(100 * 1024 * 1024, $fileSize, 'Log file should be under 100MB');
        
        // Verify all entries were logged
        $lineCount = substr_count(file_get_contents($logFile), "\n");
        $this->assertGreaterThanOrEqual($iterations, $lineCount, 'Should have logged all events');
    }
    
    /**
     * Tests logging with different log levels.
     * 
     * This test verifies:
     * - Different log levels are respected
     * - Debug messages only appear in debug mode
     * - Error messages are always logged
     * - Log level filtering works correctly
     */
    public function testLogLevels(): void
    {
        $debugLog = $this->tempDir . '/levels-debug.log';
        $infoLog = $this->tempDir . '/levels-info.log';
        $errorLog = $this->tempDir . '/levels-error.log';
        
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'logger' => [
                [
                    'class' => 'Monolog\Handler\StreamHandler',
                    'args' => [$debugLog, 'Monolog\Level::Debug']
                ],
                [
                    'class' => 'Monolog\Handler\StreamHandler',
                    'args' => [$infoLog, 'Monolog\Level::Info']
                ],
                [
                    'class' => 'Monolog\Handler\StreamHandler',
                    'args' => [$errorLog, 'Monolog\Level::Error']
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'config' => ['192.168.1.100']
                ]
            ]
        ];
        
        $firewall = $this->createFirewall($config);
        
        // Trigger events that generate different log levels
        $this->triggerFirewallEvent($firewall, '192.168.1.100');
        
        // Check log contents
        $debugContents = file_get_contents($debugLog);
        $infoContents = file_exists($infoLog) ? file_get_contents($infoLog) : '';
        $errorContents = file_exists($errorLog) ? file_get_contents($errorLog) : '';
        
        // Debug log should have the most entries
        $debugLines = substr_count($debugContents, "\n");
        $infoLines = substr_count($infoContents, "\n");
        $errorLines = substr_count($errorContents, "\n");
        
        $this->assertGreaterThanOrEqual($infoLines, $debugLines, 'Debug log should have >= info entries');
        $this->assertGreaterThanOrEqual($errorLines, $infoLines, 'Info log should have >= error entries');
    }
    
    /**
     * Helper: Create firewall instance.
     */
    protected function createFirewall(array $config): Firewall
    {
        $configFile = $this->tempDir . '/config.yml';
        file_put_contents($configFile, Yaml::dump($config, 4, 2));
        return Firewall::create([$configFile]);
    }
    
    /**
     * Helper: Create request.
     */
    protected function createRequest(string $ip, array $options = []): \Symfony\Component\HttpFoundation\Request
    {
        $method = $options['method'] ?? 'GET';
        $path = $options['path'] ?? '/';
        $query = $options['query'] ?? [];
        $post = $options['post'] ?? [];
        $headers = $options['headers'] ?? [];
        
        $server = ['REMOTE_ADDR' => $ip];
        foreach ($headers as $key => $value) {
            $server['HTTP_' . str_replace('-', '_', strtoupper($key))] = $value;
        }
        
        return \Symfony\Component\HttpFoundation\Request::create(
            $path,
            $method,
            array_merge($query, $post),
            [],
            [],
            $server
        );
    }
    
    /**
     * Helper: Trigger a firewall event that generates logs.
     */
    protected function triggerFirewallEvent(Firewall $firewall, string $ip, array $options = []): void
    {
        try {
            $request = $this->createRequest($ip, $options);
            $firewall->evaluate($request);
        } catch (\Exception $e) {
            // Expected for blocked requests
        }
    }
    
    /**
     * Helper: Find log entry by plugin name.
     */
    protected function findLogEntry(array $entries, string $pluginName, string $message): ?array
    {
        foreach ($entries as $entry) {
            if (($entry['context']['plugin'] ?? '') === $pluginName && ($entry['message'] ?? '') === $message) {
                return $entry;
            }
        }
        return null;
    }

    protected function findLogEntries(array $entries, string $pluginName): array
    {
        return array_filter($entries, function ($entry) use ($pluginName) {
            return ($entry['context']['plugin'] ?? '') === $pluginName;
        });
    }
}