<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Console\Command;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\SourceCache;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Source\SourceLoader;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\PluginConfigNormalizer;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * `firewall sources`: refresh every `metadata.sources` list a config declares, out of band.
 *
 * So a cron entry, not a visitor's request, pays for fetching a list that went stale.
 */
final class SourcesCommand extends FirewallCommand
{
    protected function configure(): void
    {
        $this
            ->setName('sources')
            ->setDescription('Refresh every metadata.sources list a config declares')
            ->addArgument('config', InputArgument::IS_ARRAY, 'Configuration files, merged in order')
            ->addOption('force', null, InputOption::VALUE_NONE, 'Fetch every source, fresh or not')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Report what would be fetched without fetching it')
            ->addOption('quiet', null, InputOption::VALUE_NONE, 'Only report failures')
            ->addOption('cache-dir', null, InputOption::VALUE_REQUIRED, 'Where cached copies are kept')
            ->setHelp(<<<'TEXT'
            Fetches every rule source a configuration declares and refreshes its cached
            copy, so no request has to wait on a fetch.

            Exit codes:
              0  every source refreshed, or still fresh
              1  at least one source could not be fetched
              2  the configuration could not be read
            TEXT);
    }

    protected function handle(InputInterface $input): int
    {
        /** @var array<int, string> $files */
        $files = $input->getArgument('config');

        $force = $input->getOption('force') === true;
        $dryRun = $input->getOption('dry-run') === true;
        $quiet = $input->getOption('quiet') === true;
        $cacheDir = is_string($input->getOption('cache-dir')) ? $input->getOption('cache-dir') : null;

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
        $config = PluginConfigNormalizer::normalize(Config::load($files));

        foreach (Config::getLoadErrors() as $error) {
            $this->err(sprintf("Could not load %s: %s\n", $error['file'], $error['message']));
        }

        $plugins = $config['plugins'] ?? [];

        if (!is_array($plugins) || $plugins === []) {
            $this->err("Configuration declares no plugins.\n");
            return 2;
        }

        /*
         * The same upstream is often declared on several plugin entries — one to
         * challenge, one to block. Deduplicate on the definition fingerprint so a
         * shared list is fetched once per run rather than once per plugin.
         */
        $definitions = [];

        foreach ($plugins as $plugin) {
            if (!is_array($plugin)) {
                continue;
            }

            $declared = $plugin['metadata']['sources'] ?? null;

            if (!is_array($declared)) {
                continue;
            }

            foreach (array_values($declared) as $index => $declaration) {
                if (is_string($declaration)) {
                    $declaration = ['upstream' => $declaration];
                }

                if (!is_array($declaration)) {
                    continue;
                }

                try {
                    $definition = SourceDefinition::fromArray($declaration, $index);
                } catch (SourceException $sourceException) {
                    $this->err(sprintf("Invalid source: %s\n", $sourceException->getMessage()));
                    return 2;
                }

                $definitions[$definition->fingerprint()] = $definition;
            }
        }

        if ($definitions === []) {
            if (!$quiet) {
                $this->out("No sources declared.\n");
            }

            return 0;
        }

        $sourceCache = new SourceCache($cacheDir);
        $sourceLoader = new SourceLoader($sourceCache);
        $failed = 0;

        if (!$quiet) {
            $this->out(sprintf("Cache directory: %s\n\n", $sourceCache->directory()));
        }

        foreach ($definitions as $definition) {
            if ($dryRun) {
                $meta = $sourceCache->meta($definition);
                $count = (int) ($meta['entry_count'] ?? 0);
                $state = $meta === []
                    ? 'not cached'
                    : sprintf(
                        '%d %s, %s',
                        $count,
                        $count === 1 ? 'entry' : 'entries',
                        $sourceCache->isFresh($definition, $meta) ? 'fresh' : 'stale'
                    );

                $this->out(sprintf("  %-28s %s (%s)\n", $definition->name, $definition->displayUpstream(), $state));
                continue;
            }

            $started = microtime(true);

            try {
                $entries = $sourceLoader->load($definition, $force);

                if (!$quiet) {
                    $this->out(sprintf(
                        "  ✓ %-28s %d %s in %dms\n",
                        $definition->name,
                        count($entries),
                        count($entries) === 1 ? 'entry' : 'entries',
                        (int) round((microtime(true) - $started) * 1000)
                    ));
                }
            } catch (SourceException $sourceException) {
                $failed++;
                $this->err(sprintf("  ✗ %-28s %s\n", $definition->name, $sourceException->getMessage()));
            }
        }

        if ($failed > 0) {
            $this->err(sprintf("\n%d of %d sources failed.\n", $failed, count($definitions)));
            return 1;
        }

        if (!$quiet && !$dryRun) {
            $this->out(sprintf(
                "\n%d %s refreshed.\n",
                count($definitions),
                count($definitions) === 1 ? 'source' : 'sources'
            ));
        }

        return 0;
    }
}
