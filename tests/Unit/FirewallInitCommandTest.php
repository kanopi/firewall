<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

/**
 * `bin/firewall-init` (#210).
 *
 * A subprocess, like the other command tests: the exit codes and the refusal to
 * overwrite are the contract, and whether it prompts depends on having a
 * terminal — which cannot be arranged from inside the same process.
 */
final class FirewallInitCommandTest extends AbstractTestCase
{
    private const EXIT_OK = 0;
    private const EXIT_REFUSED = 1;
    private const EXIT_USAGE = 2;

    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-init-cmd-' . uniqid();
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        foreach (glob($this->dir . '/*/*') ?: [] as $file) {
            @unlink($file);
        }

        foreach (glob($this->dir . '/*', GLOB_ONLYDIR) ?: [] as $sub) {
            @rmdir($sub);
        }

        @rmdir($this->dir);
        parent::tearDown();
    }

    /**
     * @param array<int, string> $args
     *
     * @return array{stdout: string, stderr: string, code: int}
     */
    private function runInit(array $args, string $stdin = ''): array
    {
        $command = array_merge(
            [PHP_BINARY, '-d', 'display_errors=stderr', dirname(__DIR__, 2) . '/bin/firewall-init'],
            $args
        );
        $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open($command, $descriptors, $pipes);

        $this->assertIsResource($process, 'Could not start bin/firewall-init');

        fwrite($pipes[0], $stdin);
        fclose($pipes[0]);

        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return ['stdout' => $stdout, 'stderr' => $stderr, 'code' => proc_close($process)];
    }

    /**
     * It writes a file, and says what to run next.
     */
    public function testItWritesAConfigAndPointsAtTheNextStep(): void
    {
        $output = $this->dir . '/firewall.yml';

        $result = $this->runInit(['--platform=drupal', '--storage=file', '--mode=log', '--output=' . $output]);

        $this->assertSame(self::EXIT_OK, $result['code'], $result['stderr']);
        $this->assertFileExists($output);
        $this->assertStringContainsString('drupal.yml', (string) file_get_contents($output));
        $this->assertStringContainsString('firewall-doctor', $result['stdout'], 'It says what to run next');
    }

    /**
     * It creates the directory it was asked to write into.
     */
    public function testItCreatesAMissingDirectory(): void
    {
        $output = $this->dir . '/nested/firewall.yml';

        $this->assertSame(self::EXIT_OK, $this->runInit(['--output=' . $output])['code']);
        $this->assertFileExists($output);
    }

    /**
     * It will not quietly replace an existing config.
     */
    public function testItRefusesToOverwriteWithoutForce(): void
    {
        $output = $this->dir . '/firewall.yml';
        file_put_contents($output, "# hand written\n");

        $result = $this->runInit(['--output=' . $output]);

        $this->assertSame(self::EXIT_REFUSED, $result['code']);
        $this->assertSame("# hand written\n", file_get_contents($output), 'The existing file is untouched');
        $this->assertStringContainsString('--force', $result['stderr'], 'It says how to proceed');
    }

    /**
     * `--force` replaces it.
     */
    public function testForceOverwrites(): void
    {
        $output = $this->dir . '/firewall.yml';
        file_put_contents($output, "# hand written\n");

        $this->assertSame(self::EXIT_OK, $this->runInit(['--output=' . $output, '--force'])['code']);
        $this->assertStringNotContainsString('hand written', (string) file_get_contents($output));
    }

    /**
     * `--print` writes nothing to disk.
     */
    public function testPrintCreatesNothing(): void
    {
        $output = $this->dir . '/firewall.yml';

        $result = $this->runInit(['--print', '--output=' . $output]);

        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertFileDoesNotExist($output);
        $this->assertStringContainsString('configs:', $result['stdout']);
    }

    /**
     * An unrecognised choice is refused, and says what is accepted.
     */
    public function testAnUnknownChoiceIsAUsageError(): void
    {
        $result = $this->runInit(['--platform=joomla', '--print']);

        $this->assertSame(self::EXIT_USAGE, $result['code']);
        $this->assertStringContainsString('wordpress', $result['stderr'], 'It lists what it accepts');
    }

    /**
     * With no terminal and no flags it takes the defaults rather than hanging.
     *
     * The case that matters for a scaffolding script or a container build: a
     * prompt nobody can see is a build that never finishes.
     */
    public function testItDoesNotPromptWithoutATerminal(): void
    {
        $result = $this->runInit(['--print']);

        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertStringContainsString('mode: log', $result['stdout'], 'It took the observing default');
        $this->assertStringNotContainsString('Platform?', $result['stdout'], 'And asked nothing');
    }

    /**
     * `--help` explains itself and exits 0.
     */
    public function testHelpExitsZero(): void
    {
        $result = $this->runInit(['--help']);

        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertStringContainsString('firewall-init', $result['stdout']);
    }
}
