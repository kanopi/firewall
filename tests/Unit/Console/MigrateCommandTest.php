<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Console;

use Kanopi\Firewall\Tests\Console\RunsFirewallCommands;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * `firewall migrate` (#217, #289).
 *
 * Against a SQLite log table, which is the consumer this needs the least of to stand up:
 * one file, and DatabaseHandler creates its own table.
 */
final class MigrateCommandTest extends AbstractTestCase
{
    use RunsFirewallCommands;

    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-migrate-' . uniqid('', true);
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
     * A config whose logger writes to a SQLite log table in this test's directory.
     */
    private function config(string $extra = ''): string
    {
        $path = $this->dir . '/config-' . uniqid('', true) . '.yml';
        file_put_contents($path, <<<YAML
        logger:
          - class: "Kanopi\\\\Firewall\\\\Logging\\\\Handler\\\\DatabaseHandler"
            args:
              - table: firewall_log
                connection: { driver: pdo_sqlite, path: "{$this->dir}/log.sqlite" }
        {$extra}
        YAML);

        return $path;
    }

    private function pdo(): \PDO
    {
        return new \PDO('sqlite:' . $this->dir . '/log.sqlite');
    }

    /**
     * A table that exists and is current.
     */
    public function testATableThatIsCurrentIsUpToDate(): void
    {
        $config = $this->config();
        $this->runFirewall('migrate', [$config]);

        $result = $this->runFirewall('migrate', [$config]);

        $this->assertSame(0, $result['code']);
        $this->assertMatchesRegularExpression('/✓ logger \(handler 0\) +up to date/', $result['stdout']);
        $this->assertSame('', $this->runFirewall('migrate', [$config, '--quiet'])['stdout'], '--quiet says nothing when nothing changed');
    }

    /**
     * A missing index is pending under --dry-run, which exits 3 so a deploy can gate on
     * it, and added by a real run.
     */
    public function testAMissingIndexIsReportedThenAdded(): void
    {
        $config = $this->config();
        $this->runFirewall('migrate', [$config]);
        $this->pdo()->exec('DROP INDEX firewall_log_plugin_name_logged_at_idx');

        $dryRun = $this->runFirewall('migrate', [$config, '--dry-run']);

        $this->assertSame(3, $dryRun['code']);
        $this->assertStringContainsString('+ logger (handler 0)', $dryRun['stdout']);
        $this->assertStringContainsString('firewall_log_plugin_name_logged_at_idx', $dryRun['stdout']);
        $this->assertStringContainsString('CREATE INDEX', $dryRun['stdout']);
        $this->assertStringContainsString('1 change pending.', $dryRun['stdout']);

        $applied = $this->runFirewall('migrate', [$config]);

        $this->assertSame(0, $applied['code']);
        $this->assertStringContainsString('added', $applied['stdout']);
        $this->assertStringContainsString('1 change applied.', $applied['stdout']);

        $this->assertMatchesRegularExpression('/up to date/', $this->runFirewall('migrate', [$config])['stdout']);
    }

    /**
     * A change that fails to apply is refused, by name, and the run exits 1.
     *
     * SQLite keeps tables and indexes in one namespace, so a table named after the
     * missing index makes CREATE INDEX fail.
     */
    public function testAChangeThatCannotBeAppliedIsRefused(): void
    {
        $config = $this->config();
        $this->runFirewall('migrate', [$config]);
        $this->pdo()->exec('DROP INDEX firewall_log_plugin_name_logged_at_idx');
        $this->pdo()->exec('CREATE TABLE firewall_log_plugin_name_logged_at_idx (x INTEGER)');

        $result = $this->runFirewall('migrate', [$config]);

        $this->assertSame(1, $result['code']);
        $this->assertStringContainsString('refused:', $result['stderr']);
        $this->assertStringContainsString('1 change could not be applied.', $result['stderr']);
    }

    /**
     * A consumer that cannot be built is a failure, alongside the ones that can.
     */
    public function testAConsumerThatCannotBeBuiltFails(): void
    {
        $result = $this->runFirewall('migrate', [$this->config(<<<'YAML'
        storage:
          type: "Kanopi\\Firewall\\Storage\\DatabaseStorage"
          config:
            connection: { driver: pdo_sqlite, path: /nonexistent/dir/storage.sqlite }
        YAML)]);

        $this->assertSame(1, $result['code']);
        $this->assertStringContainsString('✗ storage:', $result['stderr']);
        $this->assertStringContainsString('1 change could not be applied.', $result['stderr']);
    }

    /**
     * Nothing it could build, and one it could not: exit 1, without a second message.
     */
    public function testOnlyAFailedConsumerFails(): void
    {
        $path = $this->dir . '/only-storage.yml';
        file_put_contents($path, <<<'YAML'
        storage:
          type: "Kanopi\\Firewall\\Storage\\DatabaseStorage"
          config:
            connection: { driver: pdo_sqlite, path: /nonexistent/dir/storage.sqlite }
        YAML);

        $result = $this->runFirewall('migrate', [$path]);

        $this->assertSame(1, $result['code']);
        $this->assertStringContainsString('✗ storage:', $result['stderr']);
        $this->assertStringNotContainsString('declares no database', $result['stderr']);
    }

    public function testAConfigWithNoDatabaseTablesIsAUsageError(): void
    {
        $path = $this->dir . '/no-tables.yml';
        file_put_contents($path, "global:\n  mode: log\n");

        $result = $this->runFirewall('migrate', [$path]);

        $this->assertSame(2, $result['code']);
        $this->assertStringContainsString('declares no database-backed storage', $result['stderr']);
    }

    public function testAnIncludeThatCannotBeLoadedIsReported(): void
    {
        $result = $this->runFirewall('migrate', [$this->config("configs:\n  - {$this->dir}/missing.yml")]);

        $this->assertStringContainsString('Could not load', $result['stderr']);
    }

    public function testNoConfigurationIsAUsageError(): void
    {
        $result = $this->runFirewall('migrate', []);

        $this->assertSame(2, $result['code']);
        $this->assertStringContainsString('No configuration files given', $result['stderr']);
    }

    public function testAMissingConfigurationIsAUsageError(): void
    {
        $result = $this->runFirewall('migrate', [$this->dir . '/missing.yml']);

        $this->assertSame(2, $result['code']);
        $this->assertStringContainsString('Configuration file not found', $result['stderr']);
    }
}
