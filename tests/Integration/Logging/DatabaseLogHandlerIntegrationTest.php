<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration\Logging;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Logging\Handler\DatabaseHandler;
use Kanopi\Firewall\Tests\Integration\IntegrationTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * The database log handler, driven end to end from YAML.
 *
 * The unit tests exercise the handler directly. What is left to prove is the
 * part an operator actually does: declare it under `logger:` in a config file
 * and have real blocked traffic show up in a table they can query.
 */
class DatabaseLogHandlerIntegrationTest extends IntegrationTestCase
{
    /**
     * Path of the SQLite file the current test logs into.
     */
    private string $databasePath;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->databasePath = $this->tempDir . '/firewall.sqlite';
        DatabaseHandler::setDefaultConnection(null);
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        DatabaseHandler::setDefaultConnection(null);

        parent::tearDown();
    }

    /**
     * A blocked request becomes a queryable row.
     */
    public function testBlockedTrafficIsQueryableFromTheTable(): void
    {
        $firewall = $this->createFirewall([
            'logger' => [
                [
                    'class' => DatabaseHandler::class,
                    'args' => [
                        [
                            'table' => 'firewall_log',
                            'connection' => ['driver' => 'pdo_sqlite', 'path' => $this->databasePath],
                            'level' => 'Monolog\Level::Warning',
                            'buffer' => false,
                        ],
                    ],
                ],
            ],
        ]);

        $this->evaluate($firewall, '192.0.2.55', '/wp-login.php');

        $rows = $this->rows();

        self::assertCount(1, $rows, 'The blocked request should have produced exactly one row');
        self::assertSame('192.0.2.55', $rows[0]['client_ip']);
        self::assertSame('IP Address', $rows[0]['plugin_name']);
        self::assertSame('Kanopi\Firewall\Plugins\IpAddress', $rows[0]['plugin_type']);
        self::assertSame('/wp-login.php', $rows[0]['path']);
        self::assertSame('GET', $rows[0]['method']);
        self::assertNotSame('', $rows[0]['request_id'], 'The request id ties a request\'s lines together');

        // The question the issue opens with, asked in SQL.
        self::assertSame(
            1,
            (int) $this->connection()->fetchOne(
                'SELECT COUNT(DISTINCT client_ip) FROM firewall_log WHERE plugin_type = ? AND logged_at >= ?',
                ['Kanopi\Firewall\Plugins\IpAddress', time() - 604800]
            )
        );
    }

    /**
     * With no `connection`, the handler reuses the storage one.
     */
    public function testTheStorageConnectionIsReusedWhenTheHandlerDeclaresNone(): void
    {
        $firewall = $this->createFirewall([
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\DatabaseStorage',
                'config' => [
                    'connection' => ['driver' => 'pdo_sqlite', 'path' => $this->databasePath],
                ],
            ],
            'logger' => [
                [
                    'class' => DatabaseHandler::class,
                    'args' => [
                        [
                            'table' => 'firewall_log',
                            'level' => 'Monolog\Level::Warning',
                            'buffer' => false,
                        ],
                    ],
                ],
            ],
        ]);

        $this->evaluate($firewall, '192.0.2.55');

        self::assertCount(1, $this->rows());

        // Both subsystems in one database, which is the point of the fallback.
        $tables = $this->connection()->fetchFirstColumn(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        );

        self::assertContains('firewall_log', $tables);
        self::assertContains('firewall_storage', $tables);
    }

    /**
     * A log database that is unreachable does not stop the firewall.
     *
     * The handler is built during `Firewall::create()`. If it connected there,
     * an unreachable log database would take the whole firewall down — failing
     * closed over a diagnostic destination.
     */
    public function testAnUnreachableLogDatabaseDoesNotStopTheFirewall(): void
    {
        $firewall = $this->createFirewall([
            'logger' => [
                [
                    'class' => DatabaseHandler::class,
                    'args' => [
                        [
                            'table' => 'firewall_log',
                            'connection' => ['driver' => 'pdo_sqlite', 'path' => '/nonexistent/dir/firewall.sqlite'],
                            'buffer' => false,
                        ],
                    ],
                ],
            ],
        ]);

        $blocked = $this->evaluate($firewall, '192.0.2.55');

        self::assertTrue($blocked, 'The rule should still have blocked the request');
        self::assertTrue($this->evaluate($firewall, '192.0.2.55'), 'And on the request after that');
    }

    /**
     * Buffered records reach the table when the handler is closed.
     */
    public function testBufferedRecordsReachTheTableAtShutdown(): void
    {
        $firewall = $this->createFirewall([
            'logger' => [
                [
                    'class' => DatabaseHandler::class,
                    'args' => [
                        [
                            'table' => 'firewall_log',
                            'connection' => ['driver' => 'pdo_sqlite', 'path' => $this->databasePath],
                            'level' => 'Monolog\Level::Warning',
                        ],
                    ],
                ],
            ],
        ]);

        $this->evaluate($firewall, '192.0.2.55');

        self::assertSame([], $this->rows(), 'Buffered by default, so nothing yet');

        \Kanopi\Firewall\Logging\LoggingFactory::logger()->close();

        self::assertCount(1, $this->rows());
    }

    /**
     * `bin/firewall-log-prune` deletes what the retention window excludes.
     */
    public function testThePruneScriptDeletesExpiredRows(): void
    {
        $configFile = $this->writeConfig([
            'logger' => [
                [
                    'class' => DatabaseHandler::class,
                    'args' => [
                        [
                            'table' => 'firewall_log',
                            'connection' => ['driver' => 'pdo_sqlite', 'path' => $this->databasePath],
                            'retention_days' => 30,
                            'prune_probability' => 0,
                            'buffer' => false,
                        ],
                    ],
                ],
            ],
        ]);

        $firewall = Firewall::create([$configFile]);
        $this->evaluate($firewall, '192.0.2.55');

        $this->connection()->insert('firewall_log', [
            'logged_at' => time() - (90 * 86400),
            'level' => 'WARNING',
            'level_value' => 300,
            'channel' => 'firewall',
            'message' => 'Long forgotten',
            'request_id' => '',
            'client_ip' => '198.51.100.1',
            'plugin_name' => '',
            'plugin_type' => '',
            'method' => '',
            'path' => '',
            'host' => '',
            'user_agent' => '',
            'context' => '{}',
        ]);

        self::assertCount(2, $this->rows());

        $dryRun = $this->runPruneScript([$configFile, '--dry-run']);

        self::assertSame(0, $dryRun['status'], $dryRun['output']);
        self::assertStringContainsString('1 row older than 30 days', $dryRun['output']);
        self::assertCount(2, $this->rows(), 'A dry run deletes nothing');

        $prune = $this->runPruneScript([$configFile]);

        self::assertSame(0, $prune['status'], $prune['output']);
        self::assertStringContainsString('1 row deleted', $prune['output']);

        $remaining = $this->rows();

        self::assertCount(1, $remaining);
        self::assertSame('192.0.2.55', $remaining[0]['client_ip']);
    }

    /**
     * The prune script says so when a config declares no log table.
     */
    public function testThePruneScriptRejectsAConfigWithNoDatabaseHandler(): void
    {
        $configFile = $this->writeConfig([
            'logger' => [
                ['class' => 'Monolog\Handler\StreamHandler', 'args' => [$this->tempDir . '/firewall.log']],
            ],
        ]);

        $result = $this->runPruneScript([$configFile]);

        self::assertSame(2, $result['status']);
        self::assertStringContainsString('declares no DatabaseHandler', $result['output']);
    }

    /**
     * Write the config and build a firewall from it.
     *
     * @param array<string, mixed> $config
     *   Config to merge over the blocking rule every test here shares.
     */
    private function createFirewall(array $config): Firewall
    {
        return Firewall::create([$this->writeConfig($config)]);
    }

    /**
     * Write a config file, with a rule that blocks one address.
     *
     * @param array<string, mixed> $config
     *   Config to merge over the defaults.
     *
     * @return string
     *   Path of the written file.
     */
    private function writeConfig(array $config): string
    {
        $config += [
            'global' => ['mode' => 'exception', 'behind_proxy' => false],
            'storage' => ['type' => 'Kanopi\Firewall\Storage\InMemoryStorage'],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'block',
                    'enable' => true,
                    'config' => ['192.0.2.55'],
                ],
            ],
        ];

        $configFile = $this->tempDir . '/' . uniqid('config-') . '.yml';
        file_put_contents($configFile, Yaml::dump($config, 6, 2));

        return $configFile;
    }

    /**
     * Evaluate a request and report whether it was blocked.
     */
    private function evaluate(Firewall $firewall, string $ip, string $path = '/'): bool
    {
        try {
            $firewall->evaluate(Request::create($path, 'GET', [], [], [], ['REMOTE_ADDR' => $ip]));
        } catch (FirewallBlockedException) {
            return true;
        }

        return false;
    }

    /**
     * Run `bin/firewall-log-prune` in its own process.
     *
     * @param array<int, string> $arguments
     *   Arguments to pass.
     *
     * @return array{status: int, output: string}
     *   Exit status and combined output.
     */
    private function runPruneScript(array $arguments): array
    {
        $command = escapeshellarg(PHP_BINARY)
            . ' ' . escapeshellarg(dirname(__DIR__, 3) . '/bin/firewall-log-prune')
            . ' ' . implode(' ', array_map(escapeshellarg(...), $arguments))
            . ' 2>&1';

        $output = [];
        $status = 0;
        exec($command, $output, $status);

        return ['status' => $status, 'output' => implode("\n", $output)];
    }

    /**
     * Open a connection to this test's SQLite file.
     */
    private function connection(): Connection
    {
        return DriverManager::getConnection(['driver' => 'pdo_sqlite', 'path' => $this->databasePath]);
    }

    /**
     * Return every log row, oldest first.
     *
     * @return array<int, array<string, mixed>>
     *   Rows, or an empty list when the table does not exist yet.
     */
    private function rows(): array
    {
        if (!is_file($this->databasePath)) {
            return [];
        }

        try {
            return $this->connection()->fetchAllAssociative('SELECT * FROM firewall_log ORDER BY id');
        } catch (\Throwable) {
            return [];
        }
    }
}
