<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Console\Command;

use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Diagnostics\Doctor;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * `firewall doctor`: diagnose a live firewall installation (#211).
 *
 * Runs against the environment it is in rather than reading the config in the
 * abstract: it opens the storage file, reaches the database, reads the GeoIP
 * database's mtime, and builds every rule to find out whether it can be built.
 * The same configuration diagnoses differently on a laptop and in production,
 * which is the point.
 *
 * A warning does not fail the command, so this can gate a deploy without a
 * stale GeoIP database blocking one.
 */
final class DoctorCommand extends FirewallCommand
{
    protected function configure(): void
    {
        $this
            ->setName('doctor')
            ->setDescription('Diagnose a live firewall installation')
            ->addArgument('config', InputArgument::IS_ARRAY, 'Configuration files, merged in order')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Machine-readable output on stdout')
            ->addOption('quiet', null, InputOption::VALUE_NONE, 'Only warnings and errors')
            ->setHelp(<<<'TEXT'
            Runs against the environment it is in: it opens the storage, reaches the
            database, reads the GeoIP database, and builds every rule.

            Exit codes:
              0  nothing wrong, or warnings only
              1  at least one error: something configured is not happening
              2  the configuration itself could not be read

            A warning does not fail the command.
            TEXT);
    }

    protected function handle(InputInterface $input): int
    {
        /** @var array<int, string> $files */
        $files = $input->getArgument('config');
        $json = $input->getOption('json') === true;
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

        $findings = (new Doctor($files))->run();
        $tally = Doctor::tally($findings);

        if ($json) {
            // stdout stays parseable: nothing else is written there in this mode.
            $this->out(json_encode([
                'findings' => array_map(static fn(Diagnosis $diagnosis): array => $diagnosis->toArray(), $findings),
                'summary' => $tally,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");

            return $tally[Diagnosis::ERROR] > 0 ? 1 : 0;
        }

        $marks = [
            Diagnosis::OK => '  ✓ ',
            Diagnosis::WARNING => '  ! ',
            Diagnosis::ERROR => '  ✗ ',
        ];

        $this->out("\n");

        foreach ($findings as $finding) {
            if ($quiet && $finding->status === Diagnosis::OK) {
                continue;
            }

            // Errors to stderr so a CI log shows them even when stdout is captured.
            $write = $finding->status === Diagnosis::ERROR ? $this->err(...) : $this->out(...);

            $write($marks[$finding->status] . $finding->title . "\n");

            if ($finding->detail !== null) {
                $write('      ' . $finding->detail . "\n");
            }

            if ($finding->reference !== null) {
                $write('      See docs/' . $finding->reference . "\n");
            }
        }

        $plural = static fn(int $n, string $word): string => sprintf('%d %s%s', $n, $word, $n === 1 ? '' : 's');

        $this->out(sprintf(
            "\n  %s, %s, %s\n",
            $plural($tally[Diagnosis::ERROR], 'error'),
            $plural($tally[Diagnosis::WARNING], 'warning'),
            $plural($tally[Diagnosis::OK], 'check') . ' passed'
        ));

        return $tally[Diagnosis::ERROR] > 0 ? 1 : 0;
    }
}
