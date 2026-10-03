<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Console;

use Kanopi\Firewall\Console\Application;
use Kanopi\Firewall\Utility\DegradedBackends;
use Symfony\Component\Console\Input\ArgvInput;

/**
 * Run a `firewall` subcommand in this process (#289).
 *
 * The command tests ran each command as a process, which measured nothing towards coverage.
 * Run here, through the same Application `bin/firewall` runs, they do -- and the result is
 * the same three things: stdout, stderr and the exit code. FirewallCommandTest still runs
 * `bin/firewall` and the deprecated scripts as processes, for what only a process shows.
 */
trait RunsFirewallCommands
{
    /**
     * @param array<int, string> $args
     *   What follows the command on the command line.
     * @param string $stdin
     *   What the command reads, for one that asks.
     *
     * @return array{stdout: string, stderr: string, code: int}
     */
    private function runFirewall(string $command, array $args, string $stdin = ''): array
    {
        $application = new Application();
        $application->setAutoExit(false);

        $input = new ArgvInput(['firewall', $command, ...$args]);
        $stream = fopen('php://memory', 'w+');
        assert(is_resource($stream));
        fwrite($stream, $stdin);
        rewind($stream);
        $input->setStream($stream);

        $output = new SplitOutput();

        // What a process forgets when it exits, forgotten here: a backend one
        // command found unreachable is not unreachable for the next (#289).
        DegradedBackends::reset();

        try {
            $code = $application->run($input, $output);
        } finally {
            DegradedBackends::reset();
        }

        return ['stdout' => $output->stdout(), 'stderr' => $output->stderr(), 'code' => $code];
    }
}
