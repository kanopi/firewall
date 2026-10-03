<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Console\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Exception\InvalidArgumentException;
use Symfony\Component\Console\Exception\InvalidOptionException;
use Symfony\Component\Console\Exception\RuntimeException;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\StreamableInputInterface;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * What every `firewall` subcommand has in common (#289).
 *
 * The commands were scripts before they were classes, and three things about
 * them are public, because deploy hooks, CI steps and cron entries depend on
 * them. This keeps all three:
 *
 * - **Exit codes.** Each command keeps the ones it documents, including the
 *   one it uses for arguments it cannot use: `2` for most, `64` for `check`,
 *   where `1` means "would be blocked". Console's own is `1` for every input
 *   error, so a typo would have read as a verdict.
 * - **Streams.** stdout carries what a caller parses -- `--json` output above
 *   all -- and stderr everything else. Output is written raw, so a `<` in a
 *   path or a rule is not read as one of Console's formatting tags.
 * - **Early exits.** A command can stop anywhere with stop(), which is what
 *   its script's exit() was.
 */
abstract class FirewallCommand extends Command
{
    /**
     * The exit code for arguments the command cannot use.
     */
    protected const EXIT_USAGE = 2;

    private OutputInterface $stdout;

    private OutputInterface $stderr;

    /**
     * @var resource
     */
    private $stdin;

    /**
     * The exit code for arguments the command cannot use.
     */
    public function usageExitCode(): int
    {
        return static::EXIT_USAGE;
    }

    /**
     * Run the command, answering arguments it cannot use with its own exit code.
     *
     * Here rather than in the application, so a command run on its own -- by a test, or
     * by a host's console -- answers the same way.
     */
    public function run(InputInterface $input, OutputInterface $output): int
    {
        try {
            return parent::run($input, $output);
        } catch (InvalidArgumentException | InvalidOptionException | RuntimeException $exception) {
            // Console's input errors -- an option that does not exist, one
            // missing its value, an argument too many. Not LogicException, which
            // is a mistake in the command's own definition and must surface.
            $stderr = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
            $stderr->writeln(
                sprintf('%s Run `firewall %s --help` for its arguments.', $exception->getMessage(), $this->getName() ?? ''),
                OutputInterface::OUTPUT_RAW
            );

            return $this->usageExitCode();
        }
    }

    final protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->stdout = $output;
        $this->stderr = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;

        $stream = $input instanceof StreamableInputInterface ? $input->getStream() : null;
        $this->stdin = is_resource($stream) ? $stream : STDIN;

        try {
            return $this->handle($input);
        } catch (CommandExit $commandExit) {
            return $commandExit->getCode();
        }
    }

    /**
     * What the command does.
     *
     * @return int
     *   The exit code.
     */
    abstract protected function handle(InputInterface $input): int;

    /**
     * Write to stdout, as it is.
     */
    protected function out(string $text): void
    {
        $this->stdout->write($text, false, OutputInterface::OUTPUT_RAW);
    }

    /**
     * Write to stderr, as it is.
     */
    protected function err(string $text): void
    {
        $this->stderr->write($text, false, OutputInterface::OUTPUT_RAW);
    }

    /**
     * Where the command reads answers from: the terminal, or a test's input.
     *
     * @return resource
     */
    protected function stdin()
    {
        return $this->stdin;
    }

    /**
     * Stop here, with this exit code.
     */
    protected function stop(int $code): CommandExit
    {
        return new CommandExit($code);
    }
}
