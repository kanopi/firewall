<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Dotenv\Dotenv;

/**
 * Base class for integration tests with environment configuration support.
 */
abstract class IntegrationTestCase extends TestCase
{
    /**
     * Environment configuration values.
     */
    protected static array $env = [];
    
    /**
     * Temporary directory for test files.
     */
    protected string $tempDir;
    
    /**
     * Load environment variables once for all tests.
     */
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        
        // Load .env file if it exists
        $envFile = dirname(__DIR__, 2) . '/.env';
        if (file_exists($envFile)) {
            $dotenv = new Dotenv();
            $dotenv->loadEnv($envFile);
        }
        
        // Store environment variables
        self::$env = $_ENV;
    }
    
    /**
     * Set up test environment before each test.
     */
    protected function setUp(): void
    {
        parent::setUp();
        
        // Create unique temp directory for this test
        $baseDir = self::getEnv('TEST_TEMP_DIR', sys_get_temp_dir() . '/firewall_tests');
        if (!is_dir($baseDir)) {
            mkdir($baseDir, 0777, true);
        }
        
        $this->tempDir = $baseDir . '/' . uniqid('test_');
        if (!mkdir($this->tempDir, 0777, true)) {
            throw new \RuntimeException('Failed to create temp directory: ' . $this->tempDir);
        }

        putenv('FIREWALL_BYPASS_CLI=1');
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
     * Get environment variable with fallback.
     */
    protected static function getEnv(string $key, mixed $default = null): mixed
    {
        return self::$env[$key] ?? $_ENV[$key] ?? getenv($key) ?: $default;
    }
    
    /**
     * Is this run collecting code coverage?
     *
     * Wall-clock assertions cannot be trusted when it is: Xdebug's
     * line-by-line tracing multiplies execution time several-fold, so a
     * timing threshold ends up measuring the profiler rather than the code
     * under test. Callers use this to record timings without asserting on
     * them, keeping the work itself running so it still counts toward
     * coverage.
     *
     * Both engines are checked because either can be the active driver:
     * Xdebug is what this project uses, PCOV is the common alternative.
     */
    protected static function coverageIsActive(): bool
    {
        $xdebugMode = (string) (getenv('XDEBUG_MODE') ?: ini_get('xdebug.mode'));
        if (str_contains($xdebugMode, 'coverage')) {
            return true;
        }

        return extension_loaded('pcov') && (bool) ini_get('pcov.enabled');
    }

    /**
     * Check if a test group should be skipped.
     */
    protected function skipIfGroupDisabled(string $group): void
    {
        $skipKey = 'TEST_SKIP_' . strtoupper($group);
        if (self::getEnv($skipKey) === 'true') {
            $this->markTestSkipped("Test group '$group' is disabled in environment configuration");
        }
    }
    
    /**
     * Check if required environment variables are set.
     */
    protected function requireEnvVars(array $vars): void
    {
        $missing = [];
        foreach ($vars as $var) {
            if (empty(self::getEnv($var))) {
                $missing[] = $var;
            }
        }
        
        if (!empty($missing)) {
            $this->markTestSkipped('Required environment variables not set: ' . implode(', ', $missing));
        }
    }
    
    /**
     * Get database DSN from environment.
     */
    protected static function getDatabaseDsn(string $type = 'mysql'): ?string
    {
        return match ($type) {
            'mysql' => self::getEnv('DB_MYSQL_DSN'),
            'pgsql' => self::getEnv('DB_PGSQL_DSN'),
            'sqlite' => 'sqlite:///' . self::getEnv('DB_SQLITE_PATH', ':memory:'),
            default => null
        };
    }
    
    /**
     * Get Redis configuration from environment.
     */
    protected static function getRedisConfig(): array
    {
        $config = [
            'host' => self::getEnv('REDIS_HOST', '127.0.0.1'),
            'port' => (int) self::getEnv('REDIS_PORT', 6379),
        ];
        
        $password = self::getEnv('REDIS_PASSWORD');
        $username = self::getEnv('REDIS_USERNAME');
        
        if ($username && $password) {
            $config['auth'] = [$username, $password];
        } elseif ($password) {
            $config['auth'] = $password;
        }
        
        return $config;
    }
    
    /**
     * Get MaxMind database paths from environment.
     */
    protected static function getMaxMindDatabases(): array
    {
        return [
            'city' => self::getEnv('MAXMIND_CITY_DB'),
            'country' => self::getEnv('MAXMIND_COUNTRY_DB'),
            'asn' => self::getEnv('MAXMIND_ASN_DB'),
        ];
    }
    
    /**
     * Get test IP addresses from environment.
     */
    protected static function getTestIps(): array
    {
        return [
            'local' => self::getEnv('TEST_IP_LOCAL', '127.0.0.1'),
            'private' => self::getEnv('TEST_IP_PRIVATE', '192.168.1.100'),
            'public_us' => self::getEnv('TEST_IP_PUBLIC_US', '8.8.8.8'),
            'public_cn' => self::getEnv('TEST_IP_PUBLIC_CN', '223.5.5.5'),
            'public_ru' => self::getEnv('TEST_IP_PUBLIC_RU', '77.88.8.8'),
            'public_uk' => self::getEnv('TEST_IP_PUBLIC_UK', '81.2.69.142'),
        ];
    }
    
    /**
     * Get test user agents from environment.
     */
    protected static function getTestUserAgents(): array
    {
        return [
            'chrome' => self::getEnv('TEST_UA_CHROME'),
            'firefox' => self::getEnv('TEST_UA_FIREFOX'),
            'safari' => self::getEnv('TEST_UA_SAFARI'),
            'bot_google' => self::getEnv('TEST_UA_BOT_GOOGLE'),
            'bot_bing' => self::getEnv('TEST_UA_BOT_BING'),
            'old_ie' => self::getEnv('TEST_UA_OLD_IE'),
        ];
    }
    
    /**
     * Recursively removes a directory and all its contents.
     */
    protected function recursiveRemoveDirectory(string $directory): void
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