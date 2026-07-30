<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;

/**
 * `bin/firewall-check` (#105).
 *
 * Driven as a real subprocess rather than by including the script. The exit
 * code is part of the contract — it is how the tool composes in CI — and so is
 * the stdout/stderr split that keeps `--json` parseable. Neither can be
 * asserted honestly from inside the same process.
 */
final class FirewallCheckCommandTest extends AbstractTestCase
{
    private const EXIT_ALLOWED = 0;
    private const EXIT_BLOCKED = 1;
    private const EXIT_CHALLENGED = 2;
    private const EXIT_USAGE = 64;

    /**
     * @var array<int, string>
     */
    private array $tempFiles = [];

    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $file) {
            @unlink($file);
        }

        $this->tempFiles = [];

        parent::tearDown();
    }

    private function script(): string
    {
        return dirname(__DIR__, 2) . '/bin/firewall-check';
    }

    private function writeConfig(string $yaml): string
    {
        $path = sys_get_temp_dir() . '/fw-check-' . uniqid('', true) . '.yml';
        file_put_contents($path, $yaml);
        $this->tempFiles[] = $path;

        return $path;
    }

    /**
     * Run the script and capture stdout, stderr and the exit code separately.
     *
     * @param array<int, string> $args
     *
     * @return array{stdout: string, stderr: string, code: int}
     */
    private function runCheck(array $args): array
    {
        // -d display_errors=stderr isolates the subprocess from the host's
        // own PHP startup diagnostics, which the CLI SAPI otherwise prints to
        // STDOUT. CI installs pdo_mysql/mysqli/pdo_pgsql over an image that
        // already has them, so every run emits 'Module "..." is already
        // loaded' — which would land ahead of the JSON document and make these
        // assertions measure the environment rather than the tool.
        $command = array_merge(
            [PHP_BINARY, '-d', 'display_errors=stderr', $this->script()],
            $args,
        );
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open($command, $descriptors, $pipes);

        $this->assertIsResource($process, 'Could not start bin/firewall-check');

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return ['stdout' => $stdout, 'stderr' => $stderr, 'code' => proc_close($process)];
    }

    /**
     * A config with one plugin per bucket so attribution can be told apart.
     */
    private function standardConfig(): string
    {
        return $this->writeConfig(<<<'YML'
        global:
          mode: block
          banning_message: "blocked"
        storage:
          type: 'Kanopi\Firewall\Storage\InMemoryStorage'
        plugins:
          - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
            response: block
            weight: -100
            enable: true
            config:
              - 203.0.113.0/24
          - plugin: "Kanopi\\Firewall\\Plugins\\Url"
            response: block
            weight: -10
            enable: true
            config:
              - "path@starts_with:/wp-admin"
        YML);
    }

    // -----------------------------------------------------------------------
    // Verdicts and exit codes
    // -----------------------------------------------------------------------

    public function testAllowedRequestExitsZero(): void
    {
        $result = $this->runCheck(['--config=' . $this->standardConfig(), '--ip=1.1.1.1', '--url=/']);

        $this->assertSame(self::EXIT_ALLOWED, $result['code']);
        $this->assertStringContainsString('ALLOWED', $result['stdout']);
    }

    /**
     * The regression that matters most. `Firewall::evaluate()` returns TRUE
     * immediately in CLI unless the mode is `exception`, so a tool that fails
     * to force it reports "allowed" for everything — including this request,
     * which is squarely inside a blocked CIDR.
     */
    public function testBlockedRequestIsNotSilentlyAllowedInCli(): void
    {
        $result = $this->runCheck(['--config=' . $this->standardConfig(), '--ip=203.0.113.5', '--url=/']);

        $this->assertSame(self::EXIT_BLOCKED, $result['code']);
        $this->assertStringContainsString('BLOCKED', $result['stdout']);
    }

    public function testBlockedRequestNamesTheResponsiblePlugin(): void
    {
        $result = $this->runCheck(['--config=' . $this->standardConfig(), '--ip=1.1.1.1', '--url=/wp-admin/']);

        $this->assertSame(self::EXIT_BLOCKED, $result['code']);
        $this->assertStringContainsString('blocked by', $result['stdout']);
        $this->assertStringContainsString('URL', $result['stdout']);
    }

    /**
     * Attribution must come from the firewall's decision, not from any plugin
     * that happened to log. An allowed request has no responsible plugin, and
     * claiming one sends the reader hunting for a rule that did not fire.
     */
    public function testAllowedRequestReportsNoResponsiblePlugin(): void
    {
        $result = $this->runCheck(['--config=' . $this->standardConfig(), '--ip=1.1.1.1', '--url=/']);

        $this->assertStringNotContainsString('blocked by', $result['stdout']);
        $this->assertStringNotContainsString('matched plugin', $result['stdout']);
    }

    public function testChallengedRequestExitsTwo(): void
    {
        $config = $this->writeConfig(<<<'YML'
        global:
          mode: block
        storage:
          type: 'Kanopi\Firewall\Storage\InMemoryStorage'
        challenge:
          provider: math
          secret: 'test-secret-for-the-cli-check'
        plugins:
          - plugin: "Kanopi\\Firewall\\Plugins\\Url"
            response: challenge
            enable: true
            config:
              - "path@starts_with:/secure"
        YML);

        $result = $this->runCheck(['--config=' . $config, '--ip=1.1.1.1', '--url=/secure']);

        $this->assertSame(self::EXIT_CHALLENGED, $result['code']);
        $this->assertStringContainsString('CHALLENGED', $result['stdout']);
    }

    // -----------------------------------------------------------------------
    // Request construction
    // -----------------------------------------------------------------------

    public function testHeadersReachThePlugins(): void
    {
        $config = $this->writeConfig(<<<'YML'
        global:
          mode: block
        storage:
          type: 'Kanopi\Firewall\Storage\InMemoryStorage'
        plugins:
          - plugin: "Kanopi\\Firewall\\Plugins\\UserAgent"
            response: block
            enable: true
            config:
              - "client.name@contains:sqlmap"
        YML);

        $blocked = $this->runCheck(['--config=' . $config, '--header=User-Agent: sqlmap/1.8.3']);
        $allowed = $this->runCheck(['--config=' . $config, '--header=User-Agent: Mozilla/5.0 (Macintosh) Safari/605']);

        $this->assertSame(self::EXIT_BLOCKED, $blocked['code']);
        $this->assertSame(self::EXIT_ALLOWED, $allowed['code']);
    }

    /**
     * Later configs merge over earlier ones, exactly as Firewall::create()
     * treats them, so a base ruleset plus an overlay can be checked together.
     */
    public function testMultipleConfigsAreMerged(): void
    {
        $base = $this->writeConfig(<<<'YML'
        global:
          mode: block
        storage:
          type: 'Kanopi\Firewall\Storage\InMemoryStorage'
        plugins:
          - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
            response: block
            enable: true
            config:
              - 10.0.0.0/8
        YML);

        $overlay = $this->writeConfig(<<<'YML'
        plugins:
          - plugin: "Kanopi\\Firewall\\Plugins\\Url"
            response: block
            enable: true
            config:
              - "path@starts_with:/admin"
        YML);

        $baseOnly = $this->runCheck(['--config=' . $base, '--ip=1.1.1.1', '--url=/admin']);
        $merged = $this->runCheck(['--config=' . $base, '--config=' . $overlay, '--ip=1.1.1.1', '--url=/admin']);

        $this->assertSame(self::EXIT_ALLOWED, $baseOnly['code'], 'The overlay rule should not apply yet.');
        $this->assertSame(self::EXIT_BLOCKED, $merged['code'], 'The overlay rule should apply once merged.');
    }

    /**
     * getopt() returns a string for one occurrence and an array for several —
     * a reliable source of "works with two headers, breaks with one".
     */
    public function testASingleHeaderIsHandledLikeSeveral(): void
    {
        $config = $this->standardConfig();

        $one = $this->runCheck(['--config=' . $config, '--header=X-One: 1']);
        $two = $this->runCheck(['--config=' . $config, '--header=X-One: 1', '--header=X-Two: 2']);

        $this->assertSame(self::EXIT_ALLOWED, $one['code']);
        $this->assertSame(self::EXIT_ALLOWED, $two['code']);
    }

    // -----------------------------------------------------------------------
    // Safety
    // -----------------------------------------------------------------------

    /**
     * A check must not be able to ban anyone. The block path writes to
     * storage, records an offense and applies `blocking_escalation`, so
     * without the throwaway default a "check" against production config would
     * ban the address it was asked about.
     */
    public function testCheckingABlockedAddressDoesNotWriteToConfiguredStorage(): void
    {
        $storageFile = sys_get_temp_dir() . '/fw-check-must-not-exist-' . uniqid('', true) . '.json';
        $this->tempFiles[] = $storageFile;

        $config = $this->writeConfig(sprintf(
            <<<'YML'
            global:
              mode: block
            storage:
              type: 'Kanopi\Firewall\Storage\FileStorage'
              config:
                storage_file: %s
            plugins:
              - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
                response: block
                enable: true
                config:
                  - 203.0.113.0/24
            YML,
            $storageFile,
        ));

        $result = $this->runCheck(['--config=' . $config, '--ip=203.0.113.5']);

        $this->assertSame(self::EXIT_BLOCKED, $result['code']);
        $this->assertFileDoesNotExist($storageFile, 'A check must never write to the configured storage backend.');
        $this->assertStringContainsString('throwaway', $result['stdout']);
    }

    /**
     * The warning must go to stderr, or it would corrupt --json on stdout.
     */
    public function testLiveStorageWarnsOnStderrOnly(): void
    {
        $result = $this->runCheck([
            '--config=' . $this->standardConfig(),
            '--ip=203.0.113.5',
            '--live-storage',
            '--json',
        ]);

        $this->assertStringContainsString('Warning', $result['stderr']);
        // stdout must be the JSON document and nothing else, or `| jq` breaks.
        $this->assertStringStartsWith('{', ltrim($result['stdout']));
        $this->assertIsArray(json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR));
    }

    // -----------------------------------------------------------------------
    // Output modes
    // -----------------------------------------------------------------------

    public function testJsonOutputIsParseable(): void
    {
        $result = $this->runCheck([
            '--config=' . $this->standardConfig(),
            '--ip=203.0.113.5',
            '--url=/search?q=test',
            '--json',
        ]);

        // Assert the whole of stdout parses, not merely that it contains JSON
        // somewhere — anything printed alongside would break a `| jq` pipeline.
        $this->assertStringStartsWith('{', ltrim($result['stdout']));
        $decoded = json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame('blocked', $decoded['verdict']);
        $this->assertSame('203.0.113.5', $decoded['request']['ip']);
        $this->assertSame('/search', $decoded['request']['path']);
    }

    /**
     * `--explain` must show the plugins that ran AND the ones an earlier match
     * short-circuited past. "Why wasn't this caught?" is usually answered by
     * the second list.
     */
    public function testExplainListsEvaluatedAndUnreachedPlugins(): void
    {
        $result = $this->runCheck([
            '--config=' . $this->standardConfig(),
            '--ip=203.0.113.5',
            '--url=/wp-admin/',
            '--explain',
        ]);

        $this->assertStringContainsString('Plugins evaluated', $result['stdout']);
        $this->assertStringContainsString('MATCH', $result['stdout']);
        // IpAddress matches first, so the URL plugin never runs.
        $this->assertStringContainsString('not reached', $result['stdout']);
        $this->assertStringContainsString('Url', $result['stdout']);
    }

    /**
     * When nothing short-circuits, every configured plugin runs and there is
     * no unreached list to print.
     */
    public function testExplainOmitsUnreachedSectionWhenEverythingRan(): void
    {
        $result = $this->runCheck([
            '--config=' . $this->standardConfig(),
            '--ip=1.1.1.1',
            '--url=/',
            '--explain',
        ]);

        $this->assertStringContainsString('IP Address', $result['stdout']);
        $this->assertStringContainsString('URL', $result['stdout']);
        $this->assertStringNotContainsString('not reached', $result['stdout']);
    }

    // -----------------------------------------------------------------------
    // Usage errors
    // -----------------------------------------------------------------------

    /**
     * @param array<int, string> $args
     */
    #[DataProvider('provideUsageErrors')]
    public function testUsageErrorsExitSixtyFour(array $args, string $expected): void
    {
        $result = $this->runCheck($args);

        $this->assertSame(self::EXIT_USAGE, $result['code']);
        $this->assertStringContainsString($expected, $result['stderr']);
    }

    /**
     * @return array<string, array{0: array<int, string>, 1: string}>
     */
    public static function provideUsageErrors(): array
    {
        return [
            'no config' => [['--ip=1.1.1.1'], '--config'],
            'unreadable config' => [['--config=/nonexistent/nope.yml'], 'not readable'],
        ];
    }

    public function testInvalidIpIsRejected(): void
    {
        $result = $this->runCheck(['--config=' . $this->standardConfig(), '--ip=999.999.999.999']);

        $this->assertSame(self::EXIT_USAGE, $result['code']);
        $this->assertStringContainsString('not a valid address', $result['stderr']);
    }

    public function testMalformedHeaderIsRejected(): void
    {
        $result = $this->runCheck(['--config=' . $this->standardConfig(), '--header=NoColonHere']);

        $this->assertSame(self::EXIT_USAGE, $result['code']);
        $this->assertStringContainsString('NAME:VALUE', $result['stderr']);
    }

    public function testHelpExitsZeroAndDescribesTheOptions(): void
    {
        $result = $this->runCheck(['--help']);

        $this->assertSame(self::EXIT_ALLOWED, $result['code']);
        $this->assertStringContainsString('--config', $result['stdout']);
        $this->assertStringContainsString('--explain', $result['stdout']);
        $this->assertStringContainsString('EXIT CODES', $result['stdout']);
    }
}
