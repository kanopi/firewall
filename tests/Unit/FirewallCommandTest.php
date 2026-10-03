<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;

/**
 * `bin/firewall`, and the deprecated scripts that wrap it (#289).
 *
 * Nine scripts became one command with nine subcommands. These tests hold the
 * entry point to its listing and dispatch, and each old name to running exactly
 * what its subcommand runs -- a deploy hook or a cron entry calling one must not
 * notice the change until 3.0 removes it.
 */
final class FirewallCommandTest extends AbstractTestCase
{
    private const COMMANDS = ['block', 'challenge', 'check', 'doctor', 'init', 'log-prune', 'migrate', 'rule', 'sources'];

    /**
     * Run a script under bin/ in its own process.
     *
     * @param array<int, string> $arguments
     *
     * @return array{stdout: string, stderr: string, code: int}
     */
    private function execute(string $script, array $arguments = []): array
    {
        $process = proc_open(
            [PHP_BINARY, '-d', 'display_errors=stderr', dirname(__DIR__, 2) . '/bin/' . $script, ...$arguments],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );

        $this->assertIsResource($process, 'Could not start bin/' . $script);

        fclose($pipes[0]);
        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return ['stdout' => $stdout, 'stderr' => $stderr, 'code' => proc_close($process)];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function commands(): array
    {
        return array_combine(self::COMMANDS, array_map(static fn(string $command): array => [$command], self::COMMANDS));
    }

    /**
     * With nothing after it, or `help`, it lists every command.
     *
     * @return array<string, array{array<int, string>}>
     */
    public static function listings(): array
    {
        return [
            'nothing' => [[]],
            'help' => [['help']],
            '--help' => [['--help']],
            '-h' => [['-h']],
            'list' => [['list']],
        ];
    }

    /**
     * @param array<int, string> $arguments
     */
    #[DataProvider('listings')]
    public function testItListsEveryCommand(array $arguments): void
    {
        $result = $this->execute('firewall', $arguments);

        $this->assertSame(0, $result['code']);
        $this->assertSame('', $result['stderr']);

        foreach (self::COMMANDS as $command) {
            $this->assertMatchesRegularExpression('/^  ' . preg_quote($command, '/') . ' +\S/m', $result['stdout']);
        }
    }

    /**
     * Every command it lists has a file, and every command file is listed.
     */
    public function testTheListAndTheCommandFilesAgree(): void
    {
        $files = array_map(
            static fn(string $path): string => basename($path, '.php'),
            glob(dirname(__DIR__, 2) . '/bin/commands/*.php') ?: []
        );

        $this->assertEqualsCanonicalizing([...self::COMMANDS, 'bootstrap'], $files);
    }

    public function testAnUnknownCommandExitsTwo(): void
    {
        $result = $this->execute('firewall', ['nope']);

        $this->assertSame(2, $result['code']);
        $this->assertSame('', $result['stdout']);
        $this->assertStringContainsString('Unknown command "nope"', $result['stderr']);
    }

    /**
     * `help <command>` is `<command> --help`.
     */
    #[DataProvider('commands')]
    public function testHelpForACommandIsItsOwnHelp(string $command): void
    {
        $this->assertSame($this->execute('firewall', [$command, '--help']), $this->execute('firewall', ['help', $command]));
    }

    /**
     * Each deprecated script runs what its subcommand runs: the same output, on the same
     * streams, with the same exit code.
     */
    #[DataProvider('commands')]
    public function testADeprecatedScriptRunsItsSubcommand(string $command): void
    {
        $this->assertSame($this->execute('firewall', [$command, '--help']), $this->execute('firewall-' . $command, ['--help']));
    }

    /**
     * A failing run too: arguments reach the command, and its exit code comes back.
     */
    public function testADeprecatedScriptPassesArgumentsAndExitCodes(): void
    {
        $missing = sys_get_temp_dir() . '/fw-missing-' . uniqid('', true) . '.yml';

        $new = $this->execute('firewall', ['doctor', $missing]);
        $old = $this->execute('firewall-doctor', [$missing]);

        $this->assertNotSame(0, $new['code']);
        $this->assertSame($new, $old);
    }

    /**
     * Off a terminal -- cron, CI, a deploy hook -- a deprecated script says nothing about
     * being deprecated, so a job that mails its output does not start mailing.
     *
     * Covered by testADeprecatedScriptRunsItsSubcommand, whose stderr must match; this
     * says it outright, and checks each script still carries the notice for a terminal.
     */
    #[DataProvider('commands')]
    public function testADeprecatedScriptIsQuietOffATerminal(string $command): void
    {
        $this->assertStringNotContainsString('deprecated', $this->execute('firewall-' . $command, ['--help'])['stderr']);

        $source = (string) file_get_contents(dirname(__DIR__, 2) . '/bin/firewall-' . $command);
        $this->assertStringContainsString('if (stream_isatty(STDERR))', $source);
        $this->assertStringContainsString('Use `firewall ' . $command . '` instead.', $source);
    }

    /**
     * Composer installs the new command and keeps every old name until 3.0.
     */
    public function testComposerInstallsAllOfThem(): void
    {
        $composer = json_decode((string) file_get_contents(dirname(__DIR__, 2) . '/composer.json'), true);
        $this->assertIsArray($composer);

        $this->assertEqualsCanonicalizing(
            ['bin/firewall', ...array_map(static fn(string $command): string => 'bin/firewall-' . $command, self::COMMANDS)],
            $composer['bin'] ?? null
        );
    }
}
