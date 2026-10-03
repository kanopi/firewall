<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Console\Command;

use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\DatabaseConsumers;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * `firewall migrate`: bring existing tables up to the schema this release declares (#217).
 *
 * Tables are created on first write and were then never touched again, so a release that
 * added a column or an index reached only installations created after it. This is that
 * instruction, executable. Only ever additive: it adds what is missing and never drops,
 * renames or rewrites, so no sequence of runs can lose a row.
 */
final class MigrateCommand extends FirewallCommand
{
    protected function configure(): void
    {
        $this
            ->setName('migrate')
            ->setDescription('Bring existing firewall tables up to the schema this release declares')
            ->addArgument('config', InputArgument::IS_ARRAY, 'Configuration files, merged in order')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Report what is missing, and the statements, without running them')
            ->addOption('quiet', null, InputOption::VALUE_NONE, 'Only report changes and failures')
            ->setHelp(<<<'TEXT'
            Adds the columns and indexes existing firewall tables are missing. Only ever
            adds: nothing is dropped, renamed or rewritten.

            Exit codes:
              0  every table matches the declared schema, or was brought up to it
              1  at least one change could not be applied
              2  the configuration could not be read, or declared no database tables
              3  changes are pending (--dry-run only), so this can gate a deploy
            TEXT);
    }

    protected function handle(InputInterface $input): int
    {
        /** @var array<int, string> $files */
        $files = $input->getArgument('config');

        $dryRun = $input->getOption('dry-run') === true;
        $quiet = $input->getOption('quiet') === true;

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
        $config = Config::load($files);

        foreach (Config::getLoadErrors() as $error) {
            $this->err(sprintf("Could not load %s: %s\n", $error['file'], $error['message']));
        }

        /*
         * Every consumer of DatabaseTrait the configuration reaches.
         *
         * Constructed rather than described, because the declared schema lives on the
         * class -- `getStorageTables()` is where a column is added when a release adds
         * one, and a second list here would be a second place to forget.
         *
         * Construction also creates a table that does not exist yet, which is the
         * right outcome for a script whose job is making the schema current.
         */
        $built = DatabaseConsumers::fromConfig($config);
        $consumers = $built['consumers'];
        $failures = array_map(
            static fn(array $failure): string => sprintf('%s: %s', $failure['label'], $failure['error']),
            $built['failures']
        );

        foreach ($failures as $failure) {
            $this->err(sprintf("  ✗ %s\n", $failure));
        }

        if ($consumers === []) {
            if ($failures !== []) {
                return 1;
            }

            $this->err("Configuration declares no database-backed storage, rate limit storage or log handler.\n");
            return 2;
        }

        $pending = 0;
        $applied = 0;
        $refused = 0;

        foreach ($consumers as $label => $consumer) {
            $changes = $dryRun ? $consumer->pendingSchemaChanges() : $consumer->migrateSchema();

            if ($changes === []) {
                if (!$quiet) {
                    $this->out(sprintf("  ✓ %-28s up to date\n", $label));
                }

                continue;
            }

            foreach ($changes as $change) {
                $what = sprintf('%s.%s %s', $change['table'], $change['name'], $change['kind']);

                if (!$change['safe']) {
                    $refused++;
                    $this->err(sprintf("  ✗ %-28s %s\n      refused: %s\n", $label, $what, $change['reason']));
                    continue;
                }

                if ($dryRun) {
                    $pending++;
                    $this->out(sprintf("  + %-28s %s\n", $label, $what));

                    foreach ($change['sql'] as $statement) {
                        $this->out(sprintf("      %s\n", $statement));
                    }

                    continue;
                }

                $applied++;
                $this->out(sprintf("  ✓ %-28s %s added\n", $label, $what));
            }
        }

        if ($failures !== [] || $refused > 0) {
            $this->err(sprintf(
                "\n%d change%s could not be applied.\n",
                $refused + count($failures),
                $refused + count($failures) === 1 ? '' : 's'
            ));

            return 1;
        }

        if ($dryRun && $pending > 0) {
            // Distinct from success, so this can gate a deploy without parsing output.
            $this->out(sprintf("\n%d change%s pending.\n", $pending, $pending === 1 ? '' : 's'));
            return 3;
        }

        if (!$quiet && $applied > 0) {
            $this->out(sprintf("\n%d change%s applied.\n", $applied, $applied === 1 ? '' : 's'));
        }

        return 0;
    }
}
