<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Console\Command;

use Kanopi\Firewall\Utility\BlockList;
use Kanopi\Firewall\Utility\Config;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * `firewall block`: see who is blocked and why, and lift a block (#291).
 *
 * Reads and writes the real block list -- that is the point of it -- so the backend is
 * named in the output.
 */
final class BlockCommand extends FirewallCommand
{
    protected function configure(): void
    {
        $this
            ->setName('block')
            ->setDescription('See who is blocked, and lift a block')
            ->addArgument('config', InputArgument::IS_ARRAY, 'Configuration files, merged in order')
            ->addOption('list', null, InputOption::VALUE_NONE, 'Every blocked client')
            ->addOption('find', null, InputOption::VALUE_REQUIRED, 'Blocked clients in an address or CIDR')
            ->addOption('show', null, InputOption::VALUE_REQUIRED, 'One client: why it is blocked, and what it did')
            ->addOption('lift', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Lift the blocks in an address or CIDR. Repeatable')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'With --lift: say what would be lifted, and lift nothing')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Machine-readable output')
            ->setHelp(<<<'TEXT'
            Reads and writes the real block list, so the backend is named in the output.

            Exit codes:
              0  the question was answered, or the blocks lifted
              1  something could not be read or lifted
              2  the configuration could not be read, or the arguments made no sense
            TEXT);
    }

    protected function handle(InputInterface $input): int
    {
        /** @var array<int, string> $files */
        $files = $input->getArgument('config');

        /** @var array<int, string> $lifts */
        $lifts = $input->getOption('lift');
        $find = is_string($input->getOption('find')) ? $input->getOption('find') : null;
        $show = is_string($input->getOption('show')) ? $input->getOption('show') : null;
        $list = $input->getOption('list') === true;
        $dryRun = $input->getOption('dry-run') === true;
        $json = $input->getOption('json') === true;

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

        // One action at a time. Combining --lift with --find reads as "lift what this
        // finds", which is not what it would do, and guessing on the operator's behalf
        // is the wrong instinct for a command that deletes things.
        $chosen = array_filter([$list, $find !== null, $show !== null, $lifts !== []]);

        if (count($chosen) > 1) {
            $this->err("Choose one of --list, --find, --show or --lift. Try --help.\n");
            return 2;
        }

        if ($dryRun && $lifts === []) {
            $this->err("--dry-run only means something with --lift.\n");
            return 2;
        }

        Config::clearLoadErrors();
        $blockList = new BlockList($files);

        try {
            $backend = $blockList->backend();
        } catch (\Throwable $throwable) {
            $this->err(sprintf("Could not build the configured storage: %s\n", $throwable->getMessage()));
            return 2;
        }

        foreach (Config::getLoadErrors() as $error) {
            $this->err(sprintf("Could not load %s: %s\n", $error['file'], $error['message']));
        }

        if (!$backend['queryable']) {
            $this->err(sprintf(
                "%s cannot enumerate its own keys, so it cannot answer this.\n"
                . "Enumeration is a capability rather than a requirement — see docs/configuration/storage.md.\n",
                $backend['class']
            ));

            return 1;
        }

        // A store that dies with the process answers every question truthfully and
        // uselessly: nothing is blocked, because nothing was ever written here. Saying
        // so is the difference between "your customer is not blocked" and "I looked in
        // the wrong place".
        $warning = $backend['durable']
            ? null
            : sprintf(
                '%s does not outlive the process, so nothing written by your site is visible here.',
                $backend['class']
            );

        // A store that enumerates from an index it can lose answers truthfully and
        // incompletely. "Not in this range" then means "not in the part of the index
        // that survived", which is a different sentence (#392).
        if ($warning === null && $backend['gap'] !== null) {
            $warning = sprintf('Results may be incomplete: %s.', $backend['gap']);
        }

        if ($lifts !== []) {
            $matched = [];

            foreach ($lifts as $lift) {
                foreach ($blockList->find($lift) as $address => $record) {
                    $matched[$address] = $record;
                }
            }

            // Counted before, because deleteMatching() also removes records that have
            // already lapsed — find() hides those, so the two numbers legitimately
            // differ and reporting only one of them invites the wrong conclusion.
            $removed = $dryRun ? 0 : $blockList->lift($lifts);

            if ($json) {
                $this->out(json_encode([
                    'action' => $dryRun ? 'dry-run' : 'lift',
                    'patterns' => $lifts,
                    'in_force' => array_keys($matched),
                    'removed' => $removed,
                    'backend' => $backend,
                    'warning' => $warning,
                ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");

                return 0;
            }

            if ($warning !== null) {
                $this->err('  ! ' . $warning . "\n");
            }

            foreach ($matched as $address => $record) {
                $this->out($this->describeRecord((string) $address, $record) . "\n");
            }

            if ($dryRun) {
                $this->out(sprintf(
                    "\n  %d block%s in force would be lifted. Nothing was removed.\n",
                    count($matched),
                    count($matched) === 1 ? '' : 's'
                ));

                return 0;
            }

            $this->out(sprintf("\n  %d record%s removed.\n", $removed, $removed === 1 ? '' : 's'));

            if ($removed > count($matched)) {
                // Not a discrepancy worth hiding: it means expired rows were cleared
                // too, which is the documented behaviour and usually welcome.
                $this->out(sprintf(
                    "  %d of those had already expired and were not in force.\n",
                    $removed - count($matched)
                ));
            }

            return 0;
        }

        if ($show !== null) {
            $records = $blockList->find($show);
            $offenses = $blockList->offenses($show);

            if ($json) {
                $this->out(json_encode([
                    'address' => $show,
                    'blocked' => $records !== [],
                    'records' => $records,
                    'offenses' => $offenses,
                    'backend' => $backend,
                    'warning' => $warning,
                ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");

                return 0;
            }

            if ($warning !== null) {
                $this->err('  ! ' . $warning . "\n");
            }

            if ($records === []) {
                $this->out(sprintf("\n  %s is not blocked.\n", $show));
            }

            foreach ($records as $address => $record) {
                $this->out("\n" . $this->describeRecord((string) $address, $record) . "\n");
            }

            if ($offenses !== []) {
                $this->out(sprintf("\n  Offended %d time%s, most recent first:\n", count($offenses), count($offenses) === 1 ? '' : 's'));

                foreach ($offenses as $offense) {
                    $this->out(sprintf("    %s\n", date('Y-m-d H:i:s', $offense)));
                }
            }

            return 0;
        }

        $records = $find !== null ? $blockList->find($find) : $blockList->all();

        if ($json) {
            $this->out(json_encode([
                'action' => $find !== null ? 'find' : 'list',
                'pattern' => $find,
                'count' => count($records),
                'records' => $records,
                'backend' => $backend,
                'warning' => $warning,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");

            return 0;
        }

        if ($warning !== null) {
            $this->err('  ! ' . $warning . "\n");
        }

        $this->out("\n");

        foreach ($records as $address => $record) {
            $this->out($this->describeRecord((string) $address, $record) . "\n");
        }

        $this->out(sprintf(
            "\n  %d block%s in force%s (%s)\n",
            count($records),
            count($records) === 1 ? '' : 's',
            $find !== null ? ' matching ' . $find : '',
            $backend['class']
        ));

        return 0;
    }

    /**
     * Describe a record for a human.
     *
     * @param array<string, mixed> $record
     *   A stored block.
     */
    private function describeRecord(string $address, array $record): string
    {
        $expire = $record['expire'] ?? 0;
        $expires = is_numeric($expire) && (int) $expire > 0
            ? sprintf('expires %s', date('Y-m-d H:i:s', (int) $expire))
            : 'no expiry';

        $offenses = is_numeric($record['offenses'] ?? null) ? (int) $record['offenses'] : 0;

        return sprintf(
            '  %-42s %-32s %d offense%s',
            $address,
            $expires,
            $offenses,
            $offenses === 1 ? '' : 's'
        );
    }
}
