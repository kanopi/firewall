<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Console\Command;

use Kanopi\Firewall\Utility\StarterConfig;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * `firewall init`: write a starting configuration (#210).
 *
 * Four questions instead of a blank YAML file, and a new install on the shipped presets
 * rather than a hand-rolled list. Answer them, or pass them as options: with no terminal
 * to ask on -- a scaffolding script, a container build -- the defaults are used, because
 * a prompt that blocks a build is worse than no generator.
 */
final class InitCommand extends FirewallCommand
{
    protected function configure(): void
    {
        $this
            ->setName('init')
            ->setDescription('Write a starting configuration')
            ->addOption('platform', null, InputOption::VALUE_REQUIRED, 'wordpress | drupal | other')
            ->addOption('cdn', null, InputOption::VALUE_REQUIRED, 'none | cloudflare | pantheon | wpengine | fastly')
            ->addOption('storage', null, InputOption::VALUE_REQUIRED, 'file | database | redis')
            ->addOption('mode', null, InputOption::VALUE_REQUIRED, 'log (observe first, recommended) | block (enforce now)')
            ->addOption('output', null, InputOption::VALUE_REQUIRED, 'Where to write. Default config/firewall.yml')
            ->addOption('print', null, InputOption::VALUE_NONE, 'Write to stdout and create nothing')
            ->addOption('force', null, InputOption::VALUE_NONE, 'Overwrite an existing file')
            ->setHelp(<<<'TEXT'
            Anything not given is asked for, unless there is no terminal to ask on --
            then the default is used, so this is safe in a scaffolding script.

            Exit codes:
              0  written
              1  refused to overwrite, or could not write
              2  usage error
            TEXT);
    }

    protected function handle(InputInterface $input): int
    {
        // The options as getopt() returned them, which is what choose() reads: a key
        // only for what was given, and a flag as FALSE.
        $options = [];

        foreach (['platform', 'cdn', 'storage', 'mode', 'output'] as $name) {
            $value = $input->getOption($name);

            if (is_string($value) && $value !== '') {
                $options[$name] = $value;
            }
        }

        foreach (['print', 'force'] as $name) {
            if ($input->getOption($name) === true) {
                $options[$name] = false;
            }
        }

        $choices = StarterConfig::choices();

        // A terminal to ask on. Without one -- a container build, a CI step, a pipe --
        // the defaults stand rather than the process blocking on a prompt nobody sees.
        // `--no-interaction` says the same on a terminal, and SHELL_INTERACTIVE=1 is
        // Console's own way of asking for prompts without one.
        $interactive = $input->isInteractive()
            && (stream_isatty($this->stdin()) || getenv('SHELL_INTERACTIVE') === '1');

        if ($interactive) {
            $this->out("\nA starting configuration. Press enter to take the CAPITALISED default.\n\n");
        }

        $platform = $this->choose($options, 'platform', $choices['platform'], 'other', 'Platform?', $interactive);
        $cdn = $this->choose($options, 'cdn', $choices['cdn'], 'none', 'Behind a CDN?', $interactive);
        $storage = $this->choose($options, 'storage', $choices['storage'], 'file', 'Storage?', $interactive);
        $mode = $this->choose($options, 'mode', $choices['mode'], 'log', 'Start enforcing?', $interactive);

        $yaml = StarterConfig::render($platform, $cdn, $storage, $mode);

        if (isset($options['print'])) {
            $this->out($yaml);
            return 0;
        }

        $output = $options['output'] ?? null;
        $output = is_string($output) ? $output : 'config/firewall.yml';

        if (is_file($output) && !isset($options['force'])) {
            $this->err(sprintf(
                "Error: %s already exists. Pass --force to overwrite it, or --output=PATH to write elsewhere.\n",
                $output
            ));

            return 1;
        }

        $directory = dirname($output);

        if (!is_dir($directory) && !@mkdir($directory, 0755, true) && !is_dir($directory)) {
            $this->err(sprintf("Error: could not create %s\n", $directory));
            return 1;
        }

        if (@file_put_contents($output, $yaml) === false) {
            $this->err(sprintf("Error: could not write %s\n", $output));
            return 1;
        }

        $this->out(sprintf("\n  Wrote %s\n", $output));
        $this->out("\n  Next:\n");
        $this->out(sprintf("    vendor/bin/firewall check --config=%s --lint\n", $output));
        $this->out(sprintf("    vendor/bin/firewall doctor %s\n", $output));
        $this->out(sprintf(
            "    vendor/bin/firewall check --config=%s --url=/wp-admin/ --explain\n",
            $output
        ));

        if ($mode === 'log') {
            $this->out("\n  It is observing, not enforcing. Read the log for a week, then set `mode: block`.\n");
        }

        return 0;
    }

    /**
     * Resolve one choice from a flag, a prompt, or the default.
     *
     * @param array<string, mixed> $options
     *   Parsed options.
     * @param array<int, string> $accepted
     *   Values this choice accepts.
     */
    private function choose(array $options, string $name, array $accepted, string $default, string $question, bool $interactive): string
    {
        $given = $options[$name] ?? null;

        if (is_string($given) && $given !== '') {
            if (!in_array($given, $accepted, true)) {
                $this->err(sprintf(
                    "Error: --%s must be one of: %s (given: %s)\n",
                    $name,
                    implode(', ', $accepted),
                    $given
                ));

                throw $this->stop(2);
            }

            return $given;
        }

        if (!$interactive) {
            return $default;
        }

        $labels = array_map(
            static fn(string $value): string => $value === $default ? strtoupper($value) : $value,
            $accepted
        );

        while (true) {
            $this->out(sprintf("  %-22s %s: ", $question, implode(' / ', $labels)));
            $answer = fgets($this->stdin());

            if ($answer === false) {
                // stdin closed mid-question. Taking the default is friendlier than
                // exiting non-zero on somebody's Ctrl-D.
                $this->out("\n");

                return $default;
            }

            $answer = strtolower(trim($answer));

            if ($answer === '') {
                return $default;
            }

            if (in_array($answer, $accepted, true)) {
                return $answer;
            }

            $this->out(sprintf("    Not one of: %s\n", implode(', ', $accepted)));
        }
    }
}
