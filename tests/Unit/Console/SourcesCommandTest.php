<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Console;

use Kanopi\Firewall\Tests\Console\RunsFirewallCommands;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * `firewall sources` (#289).
 *
 * Every `metadata.sources` list a config declares, refreshed out of band so a visitor's
 * request never waits on a fetch. Local files, so nothing here touches the network.
 */
final class SourcesCommandTest extends AbstractTestCase
{
    use RunsFirewallCommands;

    private string $dir;

    private string $cache;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-sources-' . uniqid('', true);
        $this->cache = $this->dir . '/cache';
        mkdir($this->cache, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->remove($this->dir);
        parent::tearDown();
    }

    private function remove(string $path): void
    {
        foreach (glob($path . '/{,.}[!.,!..]*', GLOB_BRACE) ?: [] as $entry) {
            is_dir($entry) ? $this->remove($entry) : unlink($entry);
        }

        rmdir($path);
    }

    /**
     * A config whose plugins declare these sources.
     */
    private function config(string $sources): string
    {
        file_put_contents($this->dir . '/bad.txt', "203.0.113.5\n198.51.100.0/24\n");
        file_put_contents($this->dir . '/one.txt', "192.0.2.1\n");

        $path = $this->dir . '/config-' . uniqid('', true) . '.yml';
        file_put_contents($path, <<<YAML
        plugins:
          - plugin: "Kanopi\\\\Firewall\\\\Plugins\\\\IpAddress"
            response: block
            metadata:
              name: from-a-list
              sources:
        {$sources}
        YAML);

        return $path;
    }

    /**
     * @param array<int, string> $args
     *
     * @return array{stdout: string, stderr: string, code: int}
     */
    private function sources(string $config, array $args = []): array
    {
        return $this->runFirewall('sources', [$config, '--cache-dir=' . $this->cache, ...$args]);
    }

    public function testItRefreshesEverySource(): void
    {
        $config = $this->config(<<<YAML
                - {$this->dir}/bad.txt
                - upstream: {$this->dir}/one.txt
                  name: one
        YAML);

        $result = $this->sources($config);

        $this->assertSame(0, $result['code']);
        $this->assertStringContainsString('Cache directory: ' . $this->cache, $result['stdout']);
        $this->assertMatchesRegularExpression('/✓ .* 2 entries in \d+ms/', $result['stdout']);
        $this->assertMatchesRegularExpression('/✓ one +1 entry in \d+ms/', $result['stdout']);
        $this->assertStringContainsString('2 sources refreshed.', $result['stdout']);
    }

    /**
     * The same list declared twice is fetched once.
     */
    public function testASharedListIsFetchedOnce(): void
    {
        $config = $this->config(<<<YAML
                - {$this->dir}/one.txt
                - {$this->dir}/one.txt
        YAML);

        $this->assertStringContainsString('1 source refreshed.', $this->sources($config)['stdout']);
    }

    /**
     * --dry-run says what is cached and how fresh, and fetches nothing.
     */
    public function testADryRunReportsTheCache(): void
    {
        $config = $this->config(<<<YAML
                - {$this->dir}/one.txt
        YAML);

        $this->assertStringContainsString('(not cached)', $this->sources($config, ['--dry-run'])['stdout']);

        $this->sources($config, ['--force']);
        $result = $this->sources($config, ['--dry-run']);

        $this->assertSame(0, $result['code']);
        $this->assertStringContainsString('(1 entry, fresh)', $result['stdout']);
        $this->assertStringNotContainsString('refreshed', $result['stdout']);
    }

    public function testDryRunCountsSeveralEntries(): void
    {
        $config = $this->config(<<<YAML
                - {$this->dir}/bad.txt
        YAML);
        $this->sources($config);

        $this->assertStringContainsString('(2 entries, fresh)', $this->sources($config, ['--dry-run'])['stdout']);
    }

    public function testASourceThatCannotBeReadFails(): void
    {
        $config = $this->config(<<<YAML
                - {$this->dir}/one.txt
                - {$this->dir}/missing.txt
        YAML);

        $result = $this->sources($config);

        $this->assertSame(1, $result['code']);
        $this->assertStringContainsString('cannot read', $result['stderr']);
        $this->assertStringContainsString('1 of 2 sources failed.', $result['stderr']);
    }

    public function testQuietSaysNothingOnSuccess(): void
    {
        $config = $this->config(<<<YAML
                - {$this->dir}/one.txt
        YAML);

        $this->assertSame('', $this->sources($config, ['--quiet'])['stdout']);
    }

    public function testAnInvalidSourceIsAUsageError(): void
    {
        $result = $this->sources($this->config(<<<'YAML'
                - name: no-upstream
        YAML));

        $this->assertSame(2, $result['code']);
        $this->assertStringContainsString('Invalid source', $result['stderr']);
    }

    /**
     * Plugins without sources, and declarations that are not one, are passed over.
     */
    public function testNoSourcesDeclared(): void
    {
        $path = $this->dir . '/no-sources.yml';
        file_put_contents($path, <<<'YAML'
        plugins:
          - 5
          - plugin: "Kanopi\\Firewall\\Plugins\\Url"
            response: block
            config: ["path:/admin"]
          - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
            response: block
            metadata:
              sources: [5]
        YAML);

        $result = $this->sources($path);

        $this->assertSame(0, $result['code']);
        $this->assertStringContainsString('No sources declared.', $result['stdout']);
        $this->assertSame('', $this->sources($path, ['--quiet'])['stdout']);
    }

    public function testAConfigWithNoPluginsIsAUsageError(): void
    {
        $path = $this->dir . '/no-plugins.yml';
        file_put_contents($path, "global:\n  mode: log\n");

        $result = $this->sources($path);

        $this->assertSame(2, $result['code']);
        $this->assertStringContainsString('declares no plugins', $result['stderr']);
    }

    public function testAnIncludeThatCannotBeLoadedIsReported(): void
    {
        $path = $this->dir . '/include.yml';
        file_put_contents($path, "configs:\n  - {$this->dir}/missing.yml\n");

        $this->assertStringContainsString('Could not load', $this->sources($path)['stderr']);
    }

    public function testNoConfigurationIsAUsageError(): void
    {
        $this->assertSame(2, $this->runFirewall('sources', [])['code']);
        $this->assertSame(2, $this->runFirewall('sources', [$this->dir . '/missing.yml'])['code']);
    }
}
