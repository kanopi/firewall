<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Console\Command;

use Kanopi\Firewall\Logging\Handler\DatabaseHandler;
use Kanopi\Firewall\Utility\Config;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * `firewall log-prune`: delete log rows older than the retention window, out of band.
 *
 * `DatabaseHandler` can prune itself on a fraction of flushes, which needs no scheduling.
 * This is the same job when you say so: it deletes the same rows and says how many. Set
 * `prune_probability: 0` on the handler and pruning happens only here.
 */
final class LogPruneCommand extends FirewallCommand
{
    protected function configure(): void
    {
        $this
            ->setName('log-prune')
            ->setDescription('Delete firewall log rows older than the retention window')
            ->addArgument('config', InputArgument::IS_ARRAY, 'Configuration files, merged in order')
            ->addOption('days', null, InputOption::VALUE_REQUIRED, "Prune to N days instead of each handler's retention_days")
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Report what would be deleted without deleting it')
            ->addOption('quiet', null, InputOption::VALUE_NONE, 'Only report failures')
            ->setHelp(<<<'TEXT'
            Deletes firewall log rows older than each database log handler's
            retention_days, in batches, and reports how many went.

            Exit codes:
              0  every handler pruned
              1  at least one handler failed
              2  the configuration could not be read, or declared no log table
            TEXT);
    }

    protected function handle(InputInterface $input): int
    {
        /** @var array<int, string> $files */
        $files = $input->getArgument('config');

        $dryRun = $input->getOption('dry-run') === true;
        $quiet = $input->getOption('quiet') === true;
        $days = null;
        $given = $input->getOption('days');

        if ($given !== null) {
            $given = (string) $given;

            if (!ctype_digit($given) || (int) $given < 1) {
                $this->err("--days must be a positive whole number of days.\n");

                return 2;
            }

            $days = (int) $given;
        }

        if ($files === []) {
            $this->err("No configuration files given. Try --help.\n");
            return 2;
        }

        foreach ($files as $file) {
            if (!is_file($file)) {
                $this->err(sprintf("Configuration file not found: %s\n", $file));
                return 2;
            }
        }

        Config::clearLoadErrors();

        try {
            // A handler may name its connection (#395).
            $config = \Kanopi\Firewall\Utility\Connections::resolveIn(Config::load($files));
        } catch (\Kanopi\Firewall\Exception\ConfigurationException $configurationException) {
            $this->err($configurationException->getMessage() . "\n");
            return 2;
        }

        foreach (Config::getLoadErrors() as $error) {
            $this->err(sprintf("Could not load %s: %s\n", $error['file'], $error['message']));
        }

        $loggerConfig = is_array($config['logger'] ?? null) ? $config['logger'] : [];
        $handlers = [];

        foreach ($loggerConfig as $handlerConfig) {
            if (!is_array($handlerConfig)) {
                continue;
            }

            $class = $handlerConfig['class'] ?? '';
            if (!is_string($class)) {
                continue;
            }

            if (!is_a(ltrim($class, '\\'), DatabaseHandler::class, true)) {
                continue;
            }

            $args = $handlerConfig['args'][0] ?? [];

            if (!is_array($args)) {
                $args = [];
            }

            if ($days !== null) {
                $args['retention_days'] = $days;
            }

            // Pruning is this script's whole job, so a handler that would otherwise
            // also prune itself on write must not do so during this run.
            $args['prune_probability'] = 0;

            $handlers[] = new DatabaseHandler($args);
        }

        if ($handlers === []) {
            $this->err("Configuration declares no DatabaseHandler under `logger:`.\n");
            return 2;
        }

        $failed = 0;

        foreach ($handlers as $handler) {
            $table = $handler->getTable();
            $retention = $handler->getRetentionDays();

            if ($retention <= 0) {
                if (!$quiet) {
                    $this->out(sprintf(
                        "  - %-28s no retention_days configured, nothing to prune\n",
                        $table
                    ));
                }

                continue;
            }

            if ($dryRun) {
                $countable = $handler->countPrunable();

                if ($countable === null) {
                    $failed++;
                    $this->err(sprintf("  ✗ %-28s could not be read\n", $table));
                    continue;
                }

                if (!$quiet) {
                    $this->out(sprintf(
                        "  %-28s %d %s older than %d days\n",
                        $table,
                        $countable,
                        $countable === 1 ? 'row' : 'rows',
                        $retention
                    ));
                }

                continue;
            }

            $deleted = $handler->prune();

            if ($deleted === null) {
                $failed++;
                $this->err(sprintf("  ✗ %-28s could not be pruned\n", $table));
                continue;
            }

            if (!$quiet) {
                $this->out(sprintf(
                    "  ✓ %-28s %d %s deleted\n",
                    $table,
                    $deleted,
                    $deleted === 1 ? 'row' : 'rows'
                ));
            }
        }

        if ($failed > 0) {
            $this->err(sprintf("\n%d of %d log tables failed.\n", $failed, count($handlers)));
            return 1;
        }

        return 0;
    }
}
