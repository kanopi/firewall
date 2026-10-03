<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Tests\Console\RunsFirewallCommands;

/**
 * `bin/firewall init` (#210).
 *
 * A subprocess, like the other command tests: the exit codes and the refusal to
 * overwrite are the contract, and whether it prompts depends on having a
 * terminal — which cannot be arranged from inside the same process.
 */
final class FirewallInitCommandTest extends AbstractTestCase
{
    use RunsFirewallCommands;

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
        return $this->runFirewall('init', $args, $stdin);
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
        $this->assertStringContainsString('firewall doctor', $result['stdout'], 'It says what to run next');
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
    /**
     * Run init as if at a terminal, answering its four questions from $answers.
     *
     * @param array<int, string> $args
     *
     * @return array{stdout: string, stderr: string, code: int}
     */
    private function runInitAtATerminal(array $args, string $answers): array
    {
        putenv('SHELL_INTERACTIVE=1');

        try {
            return $this->runInit($args, $answers);
        } finally {
            putenv('SHELL_INTERACTIVE');
        }
    }

    /**
     * At a terminal it asks, takes an answer, takes enter as the default, and asks again
     * after an answer it does not accept.
     */
    public function testAtATerminalItAsks(): void
    {
        $result = $this->runInitAtATerminal(['--print'], "drupal\n\nnot-a-store\nredis\nblock\n");

        $this->assertSame(0, $result['code']);
        $this->assertStringContainsString('Press enter to take the CAPITALISED default.', $result['stdout']);
        $this->assertStringContainsString('Platform?', $result['stdout']);
        $this->assertStringContainsString('Not one of: file, database, redis', $result['stdout']);
        $this->assertStringContainsString('{presets_dir}/drupal.yml', $result['stdout']);
        $this->assertStringContainsString('mode: block', $result['stdout']);
    }

    /**
     * Input that ends mid-question takes the defaults rather than failing.
     */
    public function testInputThatEndsTakesTheDefaults(): void
    {
        $result = $this->runInitAtATerminal(['--print'], '');

        $this->assertSame(0, $result['code']);
        $this->assertStringContainsString('mode: log', $result['stdout']);
    }

    /**
     * --no-interaction asks nothing, even at a terminal.
     */
    public function testNoInteractionAsksNothing(): void
    {
        $result = $this->runInitAtATerminal(['--print', '--no-interaction'], "drupal\n");

        $this->assertSame(0, $result['code']);
        $this->assertStringNotContainsString('Platform?', $result['stdout']);
    }

    public function testADirectoryThatCannotBeCreatedFails(): void
    {
        $result = $this->runInit(['--output=/nonexistent-root-' . uniqid() . '/config/firewall.yml']);

        $this->assertSame(1, $result['code']);
        $this->assertStringContainsString('could not create', $result['stderr']);
    }

    public function testAFileThatCannotBeWrittenFails(): void
    {
        $directory = sys_get_temp_dir() . '/fw-init-dir-' . uniqid('', true);
        mkdir($directory . '/firewall.yml', 0777, true);

        try {
            $result = $this->runInit(['--output=' . $directory . '/firewall.yml']);
        } finally {
            rmdir($directory . '/firewall.yml');
            rmdir($directory);
        }

        $this->assertSame(1, $result['code']);
        $this->assertStringContainsString('could not write', $result['stderr']);
    }

    public function testHelpExitsZero(): void
    {
        $result = $this->runInit(['--help']);

        $this->assertSame(self::EXIT_OK, $result['code']);
        $this->assertStringContainsString('Usage:', $result['stdout']);
        $this->assertStringContainsString('Exit codes:', $result['stdout']);
    }
}
