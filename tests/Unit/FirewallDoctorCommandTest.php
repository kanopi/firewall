<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

/**
 * `bin/firewall-doctor` (#211).
 *
 * Driven as a real subprocess, for the same reasons `FirewallCheckCommandTest`
 * is: the exit code is the contract that lets this gate a deploy, and the
 * stdout/stderr split is what keeps `--json` parseable while errors still reach
 * a CI log. Neither can be asserted honestly from inside the same process.
 */
final class FirewallDoctorCommandTest extends AbstractTestCase
{
    private const EXIT_OK = 0;
    private const EXIT_ERRORS = 1;
    private const EXIT_USAGE = 2;

    /** @var array<int, string> */
    private array $temporary = [];

    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-doctor-cmd-' . uniqid();
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach ($this->temporary as $file) {
            @unlink($file);
        }

        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->dir);
        $this->temporary = [];
        parent::tearDown();
    }

    private function script(): string
    {
        return dirname(__DIR__, 2) . '/bin/firewall-doctor';
    }

    private function writeConfig(string $yaml): string
    {
        $path = $this->dir . '/config-' . uniqid('', true) . '.yml';
        file_put_contents($path, $yaml);
        $this->temporary[] = $path;

        return $path;
    }

    /**
     * @param array<int, string> $args
     *
     * @return array{stdout: string, stderr: string, code: int}
     */
    private function runDoctor(array $args): array
    {
        // display_errors=stderr for the reason FirewallCheckCommandTest gives:
        // CI installs extensions over an image that has them, so every run
        // prints 'Module "..." is already loaded' — which would land ahead of
        // the JSON and make these assertions measure the environment.
        $command = array_merge([PHP_BINARY, '-d', 'display_errors=stderr', $this->script()], $args);
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open($command, $descriptors, $pipes);

        $this->assertIsResource($process, 'Could not start bin/firewall-doctor');

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return ['stdout' => $stdout, 'stderr' => $stderr, 'code' => proc_close($process)];
    }

    private function workingConfig(): string
    {
        return $this->writeConfig(
            "global:\n  mode: block\n"
            . "storage:\n  type: 'Kanopi\\Firewall\\Storage\\FileStorage'\n"
            . "  config:\n    storage_file: '" . $this->dir . "/blocked.data'\n"
            . "plugins:\n  - plugin: 'Kanopi\\Firewall\\Plugins\\IpAddress'\n"
            . "    response: block\n    enable: true\n    config: ['203.0.113.5']\n"
        );
    }

    /**
     * A healthy installation exits 0, warnings and all.
     *
     * A warning must not fail the command, or a stale GeoIP database blocks a
     * deploy — and the CLI always warns about trusted proxies, which it cannot
     * verify from a terminal.
     */
    public function testAHealthyInstallationExitsZero(): void
    {
        $result = $this->runDoctor([$this->workingConfig()]);

        $this->assertSame(self::EXIT_OK, $result['code'], $result['stdout'] . $result['stderr']);
        $this->assertStringContainsString('Config loads', $result['stdout']);
        $this->assertStringContainsString('0 errors', $result['stdout']);
    }

    /**
     * Something configured that is not happening exits 1.
     */
    public function testAnErrorExitsOne(): void
    {
        $config = $this->writeConfig(
            "global:\n  mode: block\n"
            . "storage:\n  type: 'Kanopi\\Firewall\\Storage\\FileStorage'\n"
            . "  config:\n    storage_file: '/nonexistent/dir/blocked.data'\n"
            . "plugins: []\n"
        );

        $result = $this->runDoctor([$config]);

        $this->assertSame(self::EXIT_ERRORS, $result['code']);
        $this->assertStringContainsString('does not exist', $result['stderr'], 'Errors go to stderr');
    }

    /**
     * `--json` puts a parseable document on stdout and nothing else.
     */
    public function testJsonOutputIsParseableOnStdout(): void
    {
        $result = $this->runDoctor([$this->workingConfig(), '--json']);

        $decoded = json_decode($result['stdout'], true);

        $this->assertIsArray($decoded, 'stdout must be JSON and nothing else: ' . $result['stdout']);
        $this->assertArrayHasKey('findings', $decoded);
        $this->assertArrayHasKey('summary', $decoded);
        $this->assertSame(0, $decoded['summary']['error']);

        foreach ($decoded['findings'] as $finding) {
            $this->assertArrayHasKey('status', $finding);
            $this->assertArrayHasKey('title', $finding);
        }
    }

    /**
     * `--quiet` drops the passing checks and keeps the rest.
     */
    public function testQuietDropsPassingChecks(): void
    {
        $config = $this->workingConfig();

        $loud = $this->runDoctor([$config]);
        $quiet = $this->runDoctor([$config, '--quiet']);

        $this->assertStringContainsString('Config loads', $loud['stdout']);
        $this->assertStringNotContainsString('Config loads', $quiet['stdout']);
        $this->assertStringContainsString('Trusted proxies', $quiet['stdout'], 'A warning survives --quiet');
        $this->assertSame(self::EXIT_OK, $quiet['code']);
    }

    /**
     * Usage problems are their own exit code, distinct from findings.
     */
    public function testUsageProblemsExitTwo(): void
    {
        $this->assertSame(self::EXIT_USAGE, $this->runDoctor([])['code'], 'No config files');
        $this->assertSame(self::EXIT_USAGE, $this->runDoctor(['/nope.yml'])['code'], 'Missing file');
    }

    /**
     * `--help` explains itself and exits 0.
     */
    public function testHelpExitsZero(): void
    {
        $result = $this->runDoctor(['--help']);

        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertStringContainsString('firewall-doctor', $result['stdout']);
    }
}
