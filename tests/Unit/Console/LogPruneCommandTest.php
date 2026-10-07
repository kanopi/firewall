<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Console;

use Kanopi\Firewall\Tests\Console\RunsFirewallCommands;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * `firewall log-prune` (#289).
 *
 * The same rows the handler prunes on a fraction of flushes, deleted when the operator says
 * so, against a SQLite log table with rows backdated past the window.
 */
final class LogPruneCommandTest extends AbstractTestCase
{
    use RunsFirewallCommands;

    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-log-prune-' . uniqid('', true);
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            unlink($file);
        }

        rmdir($this->dir);
        parent::tearDown();
    }

    /**
     * A config with one SQLite log handler, and whatever else the test adds.
     */
    private function config(string $handler = 'retention_days: 30', string $extra = ''): string
    {
        $path = $this->dir . '/config-' . uniqid('', true) . '.yml';
        file_put_contents($path, <<<YAML
        logger:
          - class: "Kanopi\\\\Firewall\\\\Logging\\\\Handler\\\\DatabaseHandler"
            args:
              - table: firewall_log
                connection: { driver: pdo_sqlite, path: "{$this->dir}/log.sqlite" }
                {$handler}
        {$extra}
        YAML);

        return $path;
    }

    /**
     * Create the table, and put rows in it this many days old.
     *
     * @param array<int, int> $ages
     */
    private function rows(string $config, array $ages): void
    {
        $this->assertSame(0, $this->runFirewall('migrate', [$config])['code']);

        $pdo = new \PDO('sqlite:' . $this->dir . '/log.sqlite');
        $insert = $pdo->prepare('INSERT INTO firewall_log (logged_at, message) VALUES (?, ?)');

        foreach ($ages as $days) {
            $insert->execute([time() - $days * 86400, $days . ' days old']);
        }
    }

    public function testItDeletesRowsOlderThanTheWindow(): void
    {
        $config = $this->config();
        $this->rows($config, [40, 50, 1]);

        $result = $this->runFirewall('log-prune', [$config]);

        $this->assertSame(0, $result['code']);
        $this->assertMatchesRegularExpression('/✓ firewall_log +2 rows deleted/', $result['stdout']);

        $this->assertMatchesRegularExpression('/✓ firewall_log +0 rows deleted/', $this->runFirewall('log-prune', [$config])['stdout']);
    }

    public function testOneRowIsARow(): void
    {
        $config = $this->config();
        $this->rows($config, [40]);

        $this->assertMatchesRegularExpression('/1 row deleted/', $this->runFirewall('log-prune', [$config])['stdout']);
    }

    public function testADryRunCountsAndDeletesNothing(): void
    {
        $config = $this->config();
        $this->rows($config, [40, 50, 1]);

        $result = $this->runFirewall('log-prune', [$config, '--dry-run']);

        $this->assertSame(0, $result['code']);
        $this->assertMatchesRegularExpression('/firewall_log +2 rows older than 30 days/', $result['stdout']);
        $this->assertMatchesRegularExpression('/1 row older than 45 days/', $this->runFirewall('log-prune', [$config, '--dry-run', '--days=45'])['stdout']);
    }

    /**
     * --days replaces each handler's retention_days for this run.
     */
    public function testDaysOverridesTheRetentionWindow(): void
    {
        $config = $this->config();
        $this->rows($config, [5, 10, 1]);

        $result = $this->runFirewall('log-prune', [$config, '--days=3']);

        $this->assertSame(0, $result['code']);
        $this->assertMatchesRegularExpression('/2 rows deleted/', $result['stdout']);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function badDays(): array
    {
        return [
            'zero' => ['0'],
            'negative' => ['-1'],
            'not a number' => ['week'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('badDays')]
    public function testDaysMustBeAPositiveWholeNumber(string $days): void
    {
        $result = $this->runFirewall('log-prune', [$this->config(), '--days=' . $days]);

        $this->assertSame(2, $result['code']);
        $this->assertStringContainsString('--days must be a positive whole number', $result['stderr']);
    }

    /**
     * --quiet: nothing on a clean run, which is what a cron entry wants.
     */
    public function testQuietSaysNothingOnSuccess(): void
    {
        $config = $this->config();
        $this->rows($config, [40]);

        $this->assertSame('', $this->runFirewall('log-prune', [$config, '--quiet'])['stdout']);
        $this->assertSame('', $this->runFirewall('log-prune', [$config, '--quiet', '--dry-run'])['stdout']);
    }

    public function testAHandlerWithNoRetentionHasNothingToPrune(): void
    {
        $config = $this->config('retention_days: 0');

        $result = $this->runFirewall('log-prune', [$config]);

        $this->assertSame(0, $result['code']);
        $this->assertStringContainsString('no retention_days configured', $result['stdout']);
        $this->assertSame('', $this->runFirewall('log-prune', [$config, '--quiet'])['stdout']);
    }

    /**
     * A table that cannot be reached fails the run, in both modes.
     */
    public function testAnUnreachableTableFails(): void
    {
        $path = $this->dir . '/unreachable.yml';
        file_put_contents($path, <<<'YAML'
        logger:
          - class: "Kanopi\\Firewall\\Logging\\Handler\\DatabaseHandler"
            args:
              - table: firewall_log
                connection: { driver: pdo_sqlite, path: /nonexistent/dir/log.sqlite }
                retention_days: 30
        YAML);

        $pruned = $this->runFirewall('log-prune', [$path]);
        $counted = $this->runFirewall('log-prune', [$path, '--dry-run']);

        $this->assertSame(1, $pruned['code']);
        $this->assertStringContainsString('could not be pruned', $pruned['stderr']);
        $this->assertStringContainsString('1 of 1 log tables failed.', $pruned['stderr']);

        $this->assertSame(1, $counted['code']);
        $this->assertStringContainsString('could not be read', $counted['stderr']);
    }

    /**
     * Only DatabaseHandlers are pruned; any other logger entry is passed over.
     */
    public function testOtherLoggerEntriesArePassedOver(): void
    {
        $path = $this->dir . '/mixed.yml';
        file_put_contents($path, <<<YAML
        logger:
          - not a handler
          - class: 5
          - class: "Monolog\\\\Handler\\\\NullHandler"
          - class: "Kanopi\\\\Firewall\\\\Logging\\\\Handler\\\\DatabaseHandler"
            args: ["not a map"]
        YAML);

        $result = $this->runFirewall('log-prune', [$path]);

        // Only the DatabaseHandler is built, and with args that are not a map
        // it has no settings: no retention, so nothing to prune.
        $this->assertSame(0, $result['code']);
        $this->assertSame(1, substr_count($result['stdout'], 'no retention_days configured'));
    }

    public function testAConfigWithNoLogHandlerIsAUsageError(): void
    {
        $path = $this->dir . '/none.yml';
        file_put_contents($path, "global:\n  mode: log\n");

        $result = $this->runFirewall('log-prune', [$path]);

        $this->assertSame(2, $result['code']);
        $this->assertStringContainsString('declares no DatabaseHandler', $result['stderr']);
    }

    /**
     * A named connection that is not declared is the configuration's error.
     */
    public function testAnUndeclaredConnectionIsAUsageError(): void
    {
        $path = $this->dir . '/undeclared.yml';
        file_put_contents($path, <<<'YAML'
        logger:
          - class: "Kanopi\\Firewall\\Logging\\Handler\\DatabaseHandler"
            args:
              - table: firewall_log
                connection: "%connection(nope)%"
        YAML);

        $result = $this->runFirewall('log-prune', [$path]);

        $this->assertSame(2, $result['code']);
        $this->assertStringContainsString('nope', $result['stderr']);
    }

    public function testAnIncludeThatCannotBeLoadedIsReported(): void
    {
        $result = $this->runFirewall('log-prune', [$this->config('retention_days: 30', "configs:\n  - {$this->dir}/missing.yml")]);

        $this->assertStringContainsString('Could not load', $result['stderr']);
    }

    public function testNoConfigurationIsAUsageError(): void
    {
        $this->assertSame(2, $this->runFirewall('log-prune', [])['code']);
        $this->assertSame(2, $this->runFirewall('log-prune', [$this->dir . '/missing.yml'])['code']);
    }
}
