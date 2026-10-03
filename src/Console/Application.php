<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Console;

use Composer\InstalledVersions;
use Kanopi\Firewall\Console\Command\BlockCommand;
use Kanopi\Firewall\Console\Command\ChallengeCommand;
use Kanopi\Firewall\Console\Command\CheckCommand;
use Kanopi\Firewall\Console\Command\DoctorCommand;
use Kanopi\Firewall\Console\Command\InitCommand;
use Kanopi\Firewall\Console\Command\LogPruneCommand;
use Kanopi\Firewall\Console\Command\MigrateCommand;
use Kanopi\Firewall\Console\Command\RuleCommand;
use Kanopi\Firewall\Console\Command\SourcesCommand;
use Symfony\Component\Console\Application as ConsoleApplication;
use Symfony\Component\Console\Exception\CommandNotFoundException;
use Symfony\Component\Console\Input\InputDefinition;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `vendor/bin/firewall`: one command, a subcommand per job (#289).
 *
 * Symfony Console, so every command declares its arguments once and gets help,
 * validation and completion from that. Two of Console's defaults are changed,
 * because the commands were scripts first and deploy hooks depend on them:
 *
 * - **`--quiet` is the command's.** `doctor`, `log-prune`, `migrate` and
 *   `sources` each had one meaning "only warnings and failures", and
 *   `firewall log-prune --quiet` is the documented cron line. Console's global
 *   one silences everything, so it is left out and each command's own applies.
 * - **An unknown command exits 2,** as the dispatcher it replaced did, not 1.
 */
final class Application extends ConsoleApplication
{
    public function __construct()
    {
        parent::__construct('firewall', $this->installedVersion());

        $this->addCommands([
            new CheckCommand(),
            new DoctorCommand(),
            new InitCommand(),
            new RuleCommand(),
            new BlockCommand(),
            new ChallengeCommand(),
            new SourcesCommand(),
            new MigrateCommand(),
            new LogPruneCommand(),
        ]);
    }

    /**
     * Console's global options, without `--quiet`.
     */
    protected function getDefaultInputDefinition(): InputDefinition
    {
        $inputDefinition = parent::getDefaultInputDefinition();

        return new InputDefinition([
            ...array_values($inputDefinition->getArguments()),
            ...array_values(array_filter(
                $inputDefinition->getOptions(),
                static fn(\Symfony\Component\Console\Input\InputOption $inputOption): bool => $inputOption->getName() !== 'quiet'
            )),
        ]);
    }

    /**
     * Console's input and output set-up, without its `--quiet`.
     *
     * Console reads `--quiet` straight off the arguments here, whatever the definition
     * says, and silences the output and the prompts. A command's own `--quiet` asks for
     * neither, so both are put back.
     */
    protected function configureIO(InputInterface $input, OutputInterface $output): void
    {
        $interactive = $input->isInteractive();

        parent::configureIO($input, $output);

        if (!$input->hasParameterOption(['--quiet', '-q'], true) || $input->hasParameterOption(['--silent'], true)) {
            return;
        }

        $output->setVerbosity(OutputInterface::VERBOSITY_NORMAL);

        if ($output instanceof ConsoleOutputInterface) {
            $output->getErrorOutput()->setVerbosity(OutputInterface::VERBOSITY_NORMAL);
        }

        $input->setInteractive($interactive && !$input->hasParameterOption(['--no-interaction', '-n'], true));

        if (\function_exists('putenv')) {
            @putenv('SHELL_VERBOSITY=0');
        }

        $_ENV['SHELL_VERBOSITY'] = 0;
        $_SERVER['SHELL_VERBOSITY'] = 0;
    }

    /**
     * Run, and answer an unknown command with 2.
     */
    public function doRun(InputInterface $input, OutputInterface $output): int
    {
        try {
            return parent::doRun($input, $output);
        } catch (CommandNotFoundException $commandNotFoundException) {
            $this->renderThrowable($commandNotFoundException, $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output);

            return 2;
        }
    }

    /**
     * This package's version, as Composer installed it.
     */
    private function installedVersion(): string
    {
        // Composer's runtime API is always there under Composer 2, and this
        // package is always installed where this runs -- as the root package
        // here, as a dependency anywhere else. The fallback is for neither.
        return InstalledVersions::isInstalled('kanopi/firewall')
            ? InstalledVersions::getPrettyVersion('kanopi/firewall') ?? 'dev'
            : 'dev';
    }
}
