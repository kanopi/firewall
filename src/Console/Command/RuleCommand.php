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
use Kanopi\Firewall\Utility\ManagedRules;
use Kanopi\Firewall\Utility\PluginConfigNormalizer;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * `firewall rule`: add and remove rules without hand-editing YAML (#290).
 *
 * Owns one file of its own and includes it, rather than rewriting the operator's -- see
 * `ManagedRules`. Rules it wrote can be added, removed, enabled and disabled; rules you
 * wrote are listed, and asking to change one is refused by name.
 */
final class RuleCommand extends FirewallCommand
{
    private const EXIT_OK = 0;

    private const EXIT_REFUSED = 1;

    protected const EXIT_USAGE = 2;

    private const HELP = <<<TEXT
    Add and remove firewall rules without hand-editing YAML.

      bin/firewall rule ACTION config.yml [more.yml ...] [options]

    Actions:
      init                 Create the managed file, and say how to include it
      list                 Every rule the firewall will evaluate, and where it came from
      add                  Append a rule to the managed file
      remove NAME          Delete a managed rule
      disable NAME         Keep a managed rule, stop evaluating it
      enable NAME          Evaluate it again

    For `add`:
      --plugin=NAME        ip | url | agent | asn | geo, or a class name. Default ip
      --response=NAME      block | allow | challenge. Default block
      --rule=VALUE         A `config:` entry. Repeatable. Required
      --ip=VALUE           Shorthand for --plugin=ip --rule=VALUE. Repeatable
      --path=VALUE         Shorthand for --plugin=url --rule=path:VALUE. Repeatable
      --name=NAME          What the log will call it. Default is generated
      --weight=N           Evaluation order, lower first. Default 0

      --managed=PATH       The file this owns. Default firewall-managed.yml beside
                           the first config given
      --dry-run            Report what would change and write nothing
      --json               Machine-readable output

    This writes only its own file. Rules you wrote by hand are listed and never
    changed -- rewriting them would destroy their comments, which is why there are
    two files.
    TEXT;

    protected function configure(): void
    {
        $this
            ->setName('rule')
            ->setDescription('Add and remove rules without hand-editing YAML')
            ->addArgument('action', InputArgument::OPTIONAL, 'init, list, add, remove, disable or enable')
            ->addArgument('args', InputArgument::IS_ARRAY, 'The rule name, for remove, disable and enable; then configuration files')
            ->addOption('plugin', null, InputOption::VALUE_REQUIRED, 'ip | url | agent | asn | geo, or a class name. Default ip')
            ->addOption('response', null, InputOption::VALUE_REQUIRED, 'block | allow | challenge', 'block')
            ->addOption('rule', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'A `config:` entry. Repeatable')
            ->addOption('ip', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Shorthand for --plugin=ip --rule=VALUE. Repeatable')
            ->addOption('path', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Shorthand for --plugin=url --rule=path:VALUE. Repeatable')
            ->addOption('name', null, InputOption::VALUE_REQUIRED, 'What the log will call it. Default is generated')
            ->addOption('weight', null, InputOption::VALUE_REQUIRED, 'Evaluation order, lower first', '0')
            ->addOption('managed', null, InputOption::VALUE_REQUIRED, 'The file this owns. Default firewall-managed.yml beside the first config')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Report what would change and write nothing')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Machine-readable output')
            ->setHelp(self::HELP);
    }

    protected function handle(InputInterface $input): int
    {
        $action = $input->getArgument('action');

        if ($action === null || $action === 'help') {
            $this->out(self::HELP . "\n");

            return self::EXIT_OK;
        }

        if (!in_array($action, ['init', 'list', 'add', 'remove', 'disable', 'enable'], true)) {
            $this->err(sprintf("Unknown action: %s. Try --help.\n", $action));

            return self::EXIT_USAGE;
        }

        /** @var array<int, string> $ips */
        $ips = $input->getOption('ip');
        /** @var array<int, string> $paths */
        $paths = $input->getOption('path');
        /** @var array<int, string> $explicit */
        $explicit = $input->getOption('rule');

        // `path:` and not `path@starts_with:`, because the shorthand should mean the
        // least surprising thing. Anything else is --rule=, which takes the plugin's
        // full syntax.
        $rules = [...$explicit, ...$ips, ...array_map(static fn(string $path): string => 'path:' . $path, $paths)];
        $plugin = is_string($input->getOption('plugin'))
            ? $input->getOption('plugin')
            : ($ips !== [] ? 'ip' : ($paths !== [] ? 'url' : null));
        $response = (string) $input->getOption('response');
        $name = is_string($input->getOption('name')) ? $input->getOption('name') : null;
        $weight = (int) $input->getOption('weight');
        $managedPath = is_string($input->getOption('managed')) ? $input->getOption('managed') : null;
        $dryRun = $input->getOption('dry-run') === true;
        $json = $input->getOption('json') === true;
        $files = [];
        $target = null;

        /** @var array<int, string> $arguments */
        $arguments = $input->getArgument('args');

        foreach ($arguments as $argument) {
            // A bare word is the rule name for the actions that take one, and a config
            // file for everything else. Ordering matters: `remove office prod.yml`
            // reads the way it is written.
            if ($target === null && in_array($action, ['remove', 'disable', 'enable'], true)) {
                $target = $argument;
                continue;
            }

            $files[] = $argument;
        }

        foreach ($files as $file) {
            if (!is_file($file)) {
                $this->err(sprintf("Configuration file not found: %s\n", $file));
                return self::EXIT_USAGE;
            }
        }

        // `remove prod.yml` is the shape of the mistake: the first bare word is taken
        // as the rule name, so the config is consumed and the command would otherwise
        // report "no managed rule is named prod.yml" -- true, and no help at all.
        if ($files === [] && $target !== null && is_file($target)) {
            $this->err(sprintf(
                "`%s` takes a rule name before the configuration file:\n  firewall rule %s NAME %s\n",
                $action,
                $action,
                $target
            ));
            return self::EXIT_USAGE;
        }

        if ($files === []) {
            $this->err("Name at least one configuration file. Try --help.\n");
            return self::EXIT_USAGE;
        }

        // Beside the first config given, which is where an include written as a bare
        // relative path will look for it.
        $managedPath ??= dirname($files[0]) . '/firewall-managed.yml';

        $managed = ManagedRules::read($managedPath);

        if ($managed['problem'] !== null) {
            $this->err(sprintf("%s %s\n", $managedPath, $managed['problem']));
            return self::EXIT_REFUSED;
        }

        $before = $managed['rules'];

        /**
         * Load the merged configuration, and say so when it did not load.
         *
         * `Config::load()` collects failures instead of raising them and returns
         * whatever it managed -- which for a dangling `configs:` include is an empty
         * array. Reported as "no rules are configured", that reads as a working
         * firewall with nothing in it, which is the most misleading thing this command
         * could say.
         *
         * @param array<int, string> $files
         *   The configuration files named on the command line.
         *
         * @return array<string, mixed>
         *   The merged, normalized configuration.
         */
        $loadConfig = function (array $files): array {
            Config::clearLoadErrors();
            $merged = PluginConfigNormalizer::normalize(Config::load($files));
            $errors = Config::getLoadErrors();

            if ($errors !== []) {
                $this->err("That configuration did not load cleanly:\n");

                foreach ($errors as $error) {
                    $this->err(sprintf("  %s\n", $error['message']));
                }

                $this->err("\nA `configs:` include naming a file that does not exist yet\n"
                    . "empties the whole document -- it is a load failure, not a skipped line.\n"
                    . "`firewall rule init` writes the managed file first, which is the order\n"
                    . "that avoids this.\n");
            }

            return $merged;
        };

        $finish = function (array $result, array $lines, int $code) use ($json): never {
            $this->finish($json, $result, $lines, $code);
        };

        // -----------------------------------------------------------------------
        // init
        // -----------------------------------------------------------------------

        if ($action === 'init') {
            $existed = is_file($managedPath);

            if (!$existed && !$dryRun && !ManagedRules::write($managedPath, [])) {
                $this->err(sprintf("Could not write %s\n", $managedPath));
                return self::EXIT_REFUSED;
            }

            // The ordering is the reason this action exists. A `configs:` entry naming
            // a file that is not there yet does not degrade -- `Config::load()`
            // records the failure and returns an empty document, so every rule in the
            // config stops being configured. File first, include second.
            $finish(
                [
                    'action' => 'init',
                    'managed_file' => $managedPath,
                    'created' => !$existed,
                    'dry_run' => $dryRun,
                ],
                [
                    $existed
                        ? sprintf('%s already exists', $managedPath)
                        : sprintf('%s %s', $dryRun ? 'Would create' : 'Created', $managedPath),
                    '',
                    'Include it from your configuration, now that the file exists:',
                    '',
                    '  configs:',
                    sprintf('    - "%s"', basename($managedPath)),
                    '',
                    'Naming it before it exists empties the whole document -- a missing include is',
                    'a load failure, not a skipped line.',
                ],
                self::EXIT_OK
            );
        }

        // -----------------------------------------------------------------------
        // list
        // -----------------------------------------------------------------------

        if ($action === 'list') {
            // Config::load() reports a file it cannot read rather than throwing, and
            // $loadConfig says so on stderr; the listing goes on with what loaded.
            $merged = $loadConfig($files);

            $inventory = ManagedRules::inventory(
                is_array($merged['plugins'] ?? null) ? $merged['plugins'] : [],
                $before
            );

            $lines = [];

            if ($inventory === []) {
                $lines[] = 'No rules are configured.';
            }

            foreach ($inventory as $row) {
                $lines[] = sprintf(
                    '%-9s %-7s %-5s %-6d %s%s',
                    $row['managed'] ? 'managed' : 'yours',
                    $row['response'],
                    $row['enabled'] ? 'on' : 'off',
                    $row['weight'],
                    $row['name'],
                    $row['managed'] ? '' : '   (declared in your own configuration)'
                );
            }

            if ($inventory !== []) {
                $lines[] = '';
                $lines[] = sprintf(
                    '%d rule%s. `managed` ones live in %s and can be changed from here.',
                    count($inventory),
                    count($inventory) === 1 ? '' : 's',
                    $managedPath
                );
            }

            $finish(['managed_file' => $managedPath, 'rules' => $inventory], $lines, self::EXIT_OK);
        }

        // -----------------------------------------------------------------------
        // add
        // -----------------------------------------------------------------------

        if ($action === 'add') {
            if ($rules === []) {
                $this->err("`add` needs at least one --rule=, --ip= or --path=. Try --help.\n");
                return self::EXIT_USAGE;
            }

            if (!in_array($response, ManagedRules::RESPONSES, true)) {
                $this->err(sprintf(
                    "Unknown --response=%s. Use one of: %s\n",
                    $response,
                    implode(', ', ManagedRules::RESPONSES)
                ));
                return self::EXIT_USAGE;
            }

            $class = ManagedRules::resolvePlugin($plugin ?? 'ip');

            if ($class === null) {
                $this->err(sprintf(
                    "Unknown --plugin=%s. Use one of: %s, or a class name.\n",
                    $plugin,
                    implode(', ', array_keys(ManagedRules::ALIASES))
                ));
                return self::EXIT_USAGE;
            }

            // A generated name is still a name, because an unnamed rule is one the log
            // cannot tell from every other rule of the same class (#182) -- and one
            // this command could never find again to remove.
            $name ??= sprintf('%s-%s', strtolower(substr((string) strrchr('\\' . $class, '\\'), 1)), substr(bin2hex(random_bytes(3)), 0, 6));

            $added = ManagedRules::add($before, ManagedRules::rule($class, $response, $rules, $name, $weight));

            if ($added['problem'] !== null) {
                $this->err(sprintf("Refused: %s.\n", $added['problem']));
                return self::EXIT_REFUSED;
            }

            if (!$dryRun && !ManagedRules::write($managedPath, $added['rules'])) {
                $this->err(sprintf("Could not write %s\n", $managedPath));
                return self::EXIT_REFUSED;
            }

            $lines = [
                sprintf('%s %s %s (%s)', $dryRun ? 'Would add' : 'Added', $response, $name, $class),
                sprintf('  %s', implode(', ', $rules)),
                sprintf('  %s %s', $dryRun ? 'in' : 'written to', $managedPath),
            ];

            // Writing the file is not the same as the firewall reading it. Everything
            // below is the difference between "the command worked" and "the rule is in
            // force", and it is checked rather than assumed: a missing `configs:`
            // entry, a typo in the path, a file written beside the wrong config -- all
            // of them look exactly like success from here.
            if (!$dryRun) {
                $reachable = false;

                $reloaded = PluginConfigNormalizer::normalize(Config::load($files));
                Config::clearLoadErrors();

                foreach (is_array($reloaded['plugins'] ?? null) ? $reloaded['plugins'] : [] as $candidate) {
                    if (is_array($candidate) && ManagedRules::nameOf($candidate) === $name) {
                        $reachable = true;
                        break;
                    }
                }

                if (!$reachable) {
                    $lines[] = '';
                    $lines[] = 'The rule was written but the firewall will not see it: nothing in your';
                    $lines[] = 'configuration includes that file. Add it -- the file exists now, which is';
                    $lines[] = 'the order that matters, since naming a missing include empties the whole';
                    $lines[] = 'document rather than skipping a line:';
                    $lines[] = '';
                    $lines[] = '  configs:';
                    $lines[] = sprintf('    - "%s"', basename($managedPath));
                }

                $finish(
                    [
                        'action' => 'add',
                        'name' => $name,
                        'plugin' => $class,
                        'response' => $response,
                        'config' => $rules,
                        'managed_file' => $managedPath,
                        'in_force' => $reachable,
                    ],
                    $lines,
                    $reachable ? self::EXIT_OK : self::EXIT_REFUSED
                );
            }

            $finish(
                [
                    'action' => 'add',
                    'dry_run' => true,
                    'name' => $name,
                    'plugin' => $class,
                    'response' => $response,
                    'config' => $rules,
                    'managed_file' => $managedPath,
                ],
                $lines,
                self::EXIT_OK
            );
        }

        // -----------------------------------------------------------------------
        // remove / disable / enable
        // -----------------------------------------------------------------------

        $changed = match ($action) {
            'remove' => ManagedRules::remove($before, (string) $target),
            'disable' => ManagedRules::setEnabled($before, (string) $target, false),
            default => ManagedRules::setEnabled($before, (string) $target, true),
        };

        if ($changed['problem'] !== null) {
            // "No managed rule of that name" is true and, on its own, unhelpful: by far
            // the likeliest reason is that the rule exists and the operator wrote it.
            // Leading with the pedantic answer would send them looking for a command
            // that does not exist, so the config is consulted before anything is said.
            $yours = false;

            Config::clearLoadErrors();
            $merged = PluginConfigNormalizer::normalize(Config::load($files));

            foreach (is_array($merged['plugins'] ?? null) ? $merged['plugins'] : [] as $candidate) {
                if (is_array($candidate) && ManagedRules::nameOf($candidate) === $target) {
                    $yours = true;
                    break;
                }
            }

            if ($yours) {
                $this->err(sprintf(
                    "Refused: \"%s\" is one of your own rules, not one this command wrote.\n\n"
                    . "Rewriting your configuration would destroy its comments, which is the whole\n"
                    . "reason there are two files. Edit it where it is declared, or set\n"
                    . "`enable: false` on that entry. Only rules in %s\n"
                    . "can be changed from here.\n",
                    $target,
                    $managedPath
                ));
            } else {
                $this->err(sprintf("Refused: %s.\n", $changed['problem']));
            }

            return self::EXIT_REFUSED;
        }

        if (!$dryRun && !ManagedRules::write($managedPath, $changed['rules'])) {
            $this->err(sprintf("Could not write %s\n", $managedPath));
            return self::EXIT_REFUSED;
        }

        $verb = match ($action) {
            'remove' => $dryRun ? 'Would remove' : 'Removed',
            'disable' => $dryRun ? 'Would disable' : 'Disabled',
            default => $dryRun ? 'Would enable' : 'Enabled',
        };

        $finish(
            [
                'action' => $action,
                'name' => $target,
                'dry_run' => $dryRun,
                'managed_file' => $managedPath,
                'remaining' => count($changed['rules']),
            ],
            [
                sprintf('%s %s', $verb, $target),
                sprintf('  %s %s', $dryRun ? 'in' : 'written to', $managedPath),
            ],
            self::EXIT_OK
        );
    }

    /**
     * Report and stop.
     *
     * @param bool $json
     *   Whether --json was asked for.
     * @param array<mixed> $result
     *   The machine-readable result.
     * @param array<mixed> $lines
     *   What to print when --json was not asked for.
     * @param int $code
     *   The exit code.
     */
    private function finish(bool $json, array $result, array $lines, int $code): never
    {
        if ($json) {
            $this->out(json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        } else {
            foreach ($lines as $line) {
                $this->out((is_string($line) ? $line : '') . "\n");
            }
        }

        throw $this->stop($code);
    }
}
