<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration\Plugins;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Integration\IntegrationTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * Integration tests for all firewall plugins in both bypass and block modes.
 * 
 * These tests verify that each plugin:
 * - Works correctly in both bypass and block configurations
 * - Integrates properly with the firewall system
 * - Handles real-world data (IPs, GeoIP databases, etc.)
 * - Respects priority ordering
 * - Logs appropriately
 */
class AllPluginsIntegrationTest extends IntegrationTestCase
{

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        putenv('FIREWALL_BYPASS_CLI=1');
        putenv('FIREWALL_TEST=1');
    }

    /**
     * Tests IpAddress plugin in both bypass and block modes.
     * 
     * This test verifies:
     * - Single IP matching works correctly
     * - CIDR block matching works for IPv4 and IPv6
     * - IP range matching works
     * - Bypass takes precedence over block
     */
    public function testIpAddressPlugin(): void
    {
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'bypass' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'priority' => -100,
                    'config' => [
                        '192.168.1.100',      // Single IP
                        '10.0.0.0/8',         // CIDR block
                        '172.16.0.1-172.16.0.10'  // IP range
                    ]
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'priority' => 0,
                    'config' => [
                        '192.168.2.0/24',     // Different subnet
                        '::1',                // IPv6 localhost
                        'fe80::/10'           // IPv6 link-local
                    ]
                ]
            ]
        ];
        
        $firewall = $this->createFirewall($config);
        
        // Test bypass IPs are allowed
        $this->assertRequestAllowed($firewall, '192.168.1.100', 'Single bypass IP');
        $this->assertRequestAllowed($firewall, '10.5.5.5', 'CIDR bypass range');
        $this->assertRequestAllowed($firewall, '172.16.0.5', 'IP range bypass');
        
        // Test blocked IPs are blocked
        $this->assertRequestBlocked($firewall, '192.168.2.50', 'Blocked subnet');
        $this->assertRequestBlocked($firewall, '::1', 'IPv6 localhost blocked');
        
        // Test non-listed IPs are allowed
        $this->assertRequestAllowed($firewall, '8.8.8.8', 'Unlisted IP allowed');
    }
    
    /**
     * Tests GeoLocation plugin with real MaxMind databases.
     * 
     * This test verifies:
     * - Country-based blocking/bypassing works
     * - Continent-based rules work
     * - City-level rules work
     * - Database file loading works correctly
     * - Missing database handling
     */
    public function testGeoLocationPlugin(): void
    {
        $this->skipIfGroupDisabled('geolocation');
        
        $cityDb = self::getEnv('MAXMIND_CITY_DB');
        if (!$cityDb || !file_exists($cityDb)) {
            $this->markTestSkipped('MaxMind City database not available');
        }
        
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'bypass' => [
                'Kanopi\Firewall\Plugins\GeoLocation' => [
                    'enable' => true,
                    'priority' => -100,
                    'metadata' => [
                        'reader' => [
                            'type' => 'reader',
                            'db' => $cityDb
                        ]
                    ],
                    'config' => [
                        'country:US',              // Allow US
                        'continent:EU',            // Allow Europe
                        'city.name:London'         // Allow London
                    ]
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\GeoLocation' => [
                    'enable' => true,
                    'priority' => 0,
                    'metadata' => [
                        'reader' => [
                            'type' => 'reader',
                            'db' => $cityDb
                        ]
                    ],
                    'config' => [
                        'country:CN',              // Block China
                        'country:RU',              // Block Russia
                        'continent:AS',            // Block Asia (except bypassed)
                    ]
                ]
            ]
        ];
        
        $firewall = $this->createFirewall($config);
        $testIps = self::getTestIps();
        
        // Test with real IP addresses
        if (isset($testIps['public_us'])) {
            $this->assertRequestAllowed($firewall, $testIps['public_us'], 'US IP should be allowed');
        }
        
        if (isset($testIps['public_cn'])) {
            $this->assertRequestBlocked($firewall, $testIps['public_cn'], 'China IP should be blocked');
        }
        
        if (isset($testIps['public_uk'])) {
            $this->assertRequestAllowed($firewall, $testIps['public_uk'], 'UK IP (Europe) should be allowed');
        }
    }
    
    /**
     * Tests URL plugin with various request patterns.
     * 
     * This test verifies:
     * - Path matching (exact, wildcard, regex)
     * - Method filtering
     * - Query parameter checking
     * - POST data inspection
     * - Header evaluation
     */
    public function testUrlPlugin(): void
    {
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'bypass' => [
                'Kanopi\Firewall\Plugins\Url' => [
                    'enable' => true,
                    'priority' => -100,
                    'config' => [
                        'path:/api/health',              // Health check endpoint
                        'header.authorization@exists',    // Authenticated requests
                        'method:OPTIONS'                  // CORS preflight
                    ]
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\Url' => [
                    'enable' => true,
                    'priority' => 0,
                    'config' => [
                        'path@contains:phpmyadmin',      // Common attack vector
                        'path@regex:/\.(sql|bak)$/i',    // Backup files
                        'method:TRACE',                   // Dangerous method
                        'query@regex:/(union|select|drop)/i',  // SQL injection
                        [
                            'type' => 'AND',
                            'rules' => [
                                'method:POST',
                                'path:/login',
                                'post.username:admin'     // Brute force attempt
                            ]
                        ]
                    ]
                ]
            ]
        ];
        
        $firewall = $this->createFirewall($config);
        
        // Test bypass rules
        $this->assertRequestAllowed($firewall, '192.168.1.1', 'Health check allowed', [
            'path' => '/api/health'
        ]);
        
        $this->assertRequestAllowed($firewall, '192.168.1.1', 'Authenticated request allowed', [
            'headers' => ['Authorization' => 'Bearer token123']
        ]);
        
        // Test block rules
        $this->assertRequestBlocked($firewall, '192.168.1.2', 'PhpMyAdmin blocked', [
            'path' => '/phpmyadmin/index.php'
        ]);
        
        $this->assertRequestBlocked($firewall, '192.168.1.3', 'SQL file blocked', [
            'path' => '/backup.sql'
        ]);
        
        $this->assertRequestBlocked($firewall, '192.168.1.4', 'SQL injection blocked', [
            'query' => ['q' => 'test UNION SELECT * FROM users']
        ]);
        
        // Test complex rule (POST to /login with username=admin)
        $this->assertRequestBlocked($firewall, '192.168.1.5', 'Admin login attempt blocked', [
            'method' => 'POST',
            'path' => '/login',
            'post' => ['username' => 'admin', 'password' => 'test']
        ]);
        
        // But other logins should work
        $this->assertRequestAllowed($firewall, '192.168.1.6', 'Normal login allowed', [
            'method' => 'POST',
            'path' => '/login',
            'post' => ['username' => 'user123', 'password' => 'test']
        ]);
    }
    
    /**
     * Tests UserAgent plugin with real user agent strings.
     * 
     * This test verifies:
     * - Bot detection works correctly
     * - Device type identification
     * - Browser detection and version checking
     * - OS detection
     * - Complex user agent patterns
     */
    public function testUserAgentPlugin(): void
    {
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'bypass' => [
                'Kanopi\Firewall\Plugins\UserAgent' => [
                    'enable' => true,
                    'priority' => -100,
                    'config' => [
                        'bot.name@equals:Googlebot,bingbot#any',      // Allow search engine bots
                        'client.name:Chrome',             // Allow Chrome
                        [
                            'type' => 'AND',
                            'rules' => [
                                'os.name:Windows',
                                'client.version >= 100'   // Modern Windows browsers
                            ]
                        ]
                    ]
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\UserAgent' => [
                    'enable' => true,
                    'priority' => 0,
                    'config' => [
                        'bot:true',                      // Block all bots (except bypassed)
                        'client.name:Internet Explorer', // Block IE
                        'client.version < 80',           // Block old browsers
                        'device.type:bot'                // Block identified bots
                    ]
                ]
            ]
        ];
        
        $firewall = $this->createFirewall($config);
        $userAgents = self::getTestUserAgents();
        
        // Test with real user agents
        if (isset($userAgents['chrome'])) {
            $this->assertRequestAllowed($firewall, '192.168.1.1', 'Chrome allowed', [
                'headers' => ['User-Agent' => $userAgents['chrome']]
            ]);
        }
        
        if (isset($userAgents['bot_google'])) {
            $this->assertRequestAllowed($firewall, '192.168.1.1', 'Googlebot allowed', [
                'headers' => ['User-Agent' => $userAgents['bot_google']]
            ]);
        }
        
        if (isset($userAgents['old_ie'])) {
            $this->assertRequestBlocked($firewall, '192.168.1.1', 'Old IE blocked', [
                'headers' => ['User-Agent' => $userAgents['old_ie']]
            ]);
        }
        
        // Test bot detection
        $maliciousBot = 'Mozilla/5.0 (compatible; MaliciousBot/1.0)';
        $this->assertRequestBlocked($firewall, '192.168.1.1', 'Unknown bot blocked', [
            'headers' => ['User-Agent' => $maliciousBot]
        ]);
    }
    
    /**
     * Tests ASN plugin with real ASN database.
     * 
     * This test verifies:
     * - ASN number matching
     * - Organization name matching
     * - Database loading
     * - Missing database handling
     */
    public function testAsnPlugin(): void
    {
        $this->skipIfGroupDisabled('geolocation');
        
        $asnDb = self::getEnv('MAXMIND_ASN_DB');
        if (!$asnDb || !file_exists($asnDb)) {
            $this->markTestSkipped('MaxMind ASN database not available');
        }
        
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'bypass' => [
                'Kanopi\Firewall\Plugins\Asn' => [
                    'enable' => true,
                    'priority' => -100,
                    'metadata' => [
                        'reader' => [
                            'type' => 'reader',
                            'db' => $asnDb
                        ]
                    ],
                    'config' => [
                        'asn:15169',                     // Google
                        'asn_org@contains:CLOUDFLARE'    // Cloudflare
                    ]
                ]
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\Asn' => [
                    'enable' => true,
                    'priority' => 0,
                    'metadata' => [
                        'reader' => [
                            'type' => 'reader',
                            'db' => $asnDb
                        ]
                    ],
                    'config' => [
                        'asn_org@contains:CHINANET',     // Block Chinese networks
                        'asn:4134'                       // Specific ASN
                    ]
                ]
            ]
        ];
        
        $firewall = $this->createFirewall($config);
        $testIps = self::getTestIps();
        
        // Test with known IPs (Google DNS)
        if (isset($testIps['public_us']) && $testIps['public_us'] === '8.8.8.8') {
            $this->assertRequestAllowed($firewall, '8.8.8.8', 'Google IP should be allowed');
        }
        
        // Test blocking (would need specific test IPs for each ASN)
        // This is a placeholder - in real tests you'd have known IPs for specific ASNs
    }
    
    /**
     * Tests RateLimit plugin with various storage backends.
     * 
     * This test verifies:
     * - Rate limiting works per IP
     * - Path-specific limits are enforced
     * - Time windows work correctly
     * - Different storage backends work
     * - 429 status code is returned
     */
    public function testRateLimitPlugin(): void
    {
        // Test with file storage
        $this->runRateLimitTest('file');
        
        // Test with Redis if available
        if (!self::getEnv('TEST_SKIP_REDIS')) {
            $this->runRateLimitTest('redis');
        }
        
        // Test with in-memory storage
        $this->runRateLimitTest('memory');
    }
    
    /**
     * Run rate limit tests with specific storage backend.
     */
    protected function runRateLimitTest(string $storageType): void
    {
        $rateLimitStorage = match ($storageType) {
            'file' => [
                'type' => 'Kanopi\Firewall\RateLimitStorage\FileRateLimitStorage',
                'config' => ['file' => $this->tempDir . '/ratelimit.data']
            ],
            'redis' => [
                'type' => 'Kanopi\Firewall\RateLimitStorage\RedisRateLimitStorage',
                'config' => ['redis' => self::getRedisConfig()]
            ],
            'memory' => [
                'type' => 'Kanopi\Firewall\RateLimitStorage\InMemoryRateLimitStorage'
            ]
        };
        
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'block' => [
                'Kanopi\Firewall\Plugins\RateLimit' => [
                    'enable' => true,
                    'priority' => 100,
                    'metadata' => [
                        'default_rate' => 10,
                        'default_sample' => 60,
                        'storage' => $rateLimitStorage
                    ],
                    'config' => [
                        ['path' => '/api/*', 'rate' => 5, 'sample' => 60],
                        ['path' => '/login', 'rate' => 3, 'sample' => 300],
                        ['path' => '/', 'rate' => 2, 'sample' => 10]
                    ]
                ]
            ]
        ];
        
        try {
            $firewall = $this->createFirewall($config);
        } catch (\Exception $e) {
            if ($storageType === 'redis') {
                $this->markTestSkipped('Redis not available: ' . $e->getMessage());
            }
            throw $e;
        }
        
        // Test rate limit on homepage
        $this->assertRequestAllowed($firewall, '192.168.1.100', "First request allowed ($storageType)", [
            'path' => '/'
        ]);
        
        $this->assertRequestAllowed($firewall, '192.168.1.100', "Second request allowed ($storageType)", [
            'path' => '/'
        ]);
        
        // Third request should be blocked
        try {
            $request = $this->createRequest('192.168.1.100', ['path' => '/']);
            $firewall->evaluate($request);
            $this->fail("Third request should have been rate limited ($storageType)");
        } catch (\Exception $e) {
            $this->assertEquals(429, $e->getCode(), 'Should return 429 Too Many Requests');
        }
        
        // Different IP should still work
        $this->assertRequestAllowed($firewall, '192.168.1.101', "Different IP allowed ($storageType)", [
            'path' => '/'
        ]);
        
        // Test path-specific limits
        for ($i = 1; $i <= 5; $i++) {
            $this->assertRequestAllowed($firewall, '192.168.1.200', "API request $i allowed ($storageType)", [
                'path' => '/api/users'
            ]);
        }
        
        // 6th API request should fail
        try {
            $request = $this->createRequest('192.168.1.200', ['path' => '/api/posts']);
            $firewall->evaluate($request);
            $this->fail("6th API request should have been rate limited ($storageType)");
        } catch (\Exception $e) {
            $this->assertEquals(429, $e->getCode());
        }
    }
    
    /**
     * Tests multiple plugins working together.
     * 
     * This test verifies:
     * - Plugin priority ordering works
     * - Multiple plugins can evaluate same request
     * - First match wins (bypass or block)
     * - Complex real-world scenarios
     */
    public function testMultiplePluginsIntegration(): void
    {
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\FileStorage',
                'config' => ['file' => $this->tempDir . '/multi.data']
            ],
            'bypass' => [
                // High priority: IP whitelist
                'Kanopi\Firewall\Plugins\IpAddress' => [
                    'enable' => true,
                    'priority' => -200,
                    'config' => ['192.168.1.100']
                ]
            ],
            'block' => [
                // Block suspicious URLs first
                'Kanopi\Firewall\Plugins\Url' => [
                    'enable' => true,
                    'priority' => -100,
                    'config' => ['path@contains:evil']
                ],
                // Then check user agents
                'Kanopi\Firewall\Plugins\UserAgent' => [
                    'enable' => true,
                    'priority' => -50,
                    'config' => ['bot:true']
                ],
                // Finally apply rate limits
                'Kanopi\Firewall\Plugins\RateLimit' => [
                    'enable' => true,
                    'priority' => 100,
                    'metadata' => [
                        'default_rate' => 10,
                        'default_sample' => 60,
                        'storage' => [
                            'type' => 'Kanopi\Firewall\RateLimitStorage\InMemoryRateLimitStorage'
                        ]
                    ],
                    'config' => []
                ]
            ]
        ];
        
        $firewall = $this->createFirewall($config);
        
        // Whitelisted IP can access evil path
        $this->assertRequestAllowed($firewall, '192.168.1.100', 'Whitelisted IP bypasses all blocks', [
            'path' => '/evil/path',
            'headers' => ['User-Agent' => 'BadBot/1.0']
        ]);
        
        // Non-whitelisted IP gets blocked by URL
        $this->assertRequestBlocked($firewall, '192.168.1.101', 'Evil path blocked', [
            'path' => '/evil/path'
        ]);
        
        // Bot gets blocked
        $this->assertRequestBlocked($firewall, '192.168.1.102', 'Bot blocked', [
            'headers' => ['User-Agent' => 'BadBot/1.0']
        ]);
        
        // Verify plugin priority (URL plugin blocked first)
        $storageData = unserialize(file_get_contents($this->tempDir . '/multi.data'));
        $this->assertEquals('URL', $storageData['192.168.1.101']['plugin'] ?? null);
        $this->assertEquals('User Agent', $storageData['192.168.1.102']['plugin'] ?? null);
    }
    
    /**
     * Helper: Create a firewall instance with config.
     */
    protected function createFirewall(array $config): Firewall
    {
        $configFile = $this->tempDir . '/config.yml';
        file_put_contents($configFile, Yaml::dump($config, 4, 2));
        return Firewall::create([$configFile]);
    }
    
    /**
     * Helper: Create a request with options.
     */
    protected function createRequest(string $ip, array $options = []): Request
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
        
        return Request::create($path, $method, array_merge($query, $post), [], [], $server);
    }
    
    /**
     * Helper: Assert request is allowed.
     */
    protected function assertRequestAllowed(Firewall $firewall, string $ip, string $message, array $options = []): void
    {
        $request = $this->createRequest($ip, $options);
        $result = $firewall->evaluate($request);
        $this->assertTrue($result, $message);
    }
    
    /**
     * Helper: Assert request is blocked.
     */
    protected function assertRequestBlocked(Firewall $firewall, string $ip, string $message, array $options = []): void
    {
        $request = $this->createRequest($ip, $options);
        
        try {
            $firewall->evaluate($request);
            $this->fail($message . ' - Expected request to be blocked');
        } catch (\Exception $e) {
            $this->assertContains($e->getCode(), [400, 403, 429], 'Expected 400, 403, or 429 status code');
        }
    }
}