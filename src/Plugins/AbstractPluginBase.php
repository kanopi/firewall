<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Challenge\ChallengeProviderAwareInterface;
use Kanopi\Firewall\Logging\LoggingTrait;
use Kanopi\Firewall\Source\SourceManager;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\NestedArray;
use Kanopi\Firewall\Utility\Path;
use Symfony\Component\HttpFoundation\Request;

/**
 * Abstract Plugin used for creating a plugin.
 */
abstract class AbstractPluginBase implements PluginInterface, ChallengeProviderAwareInterface
{
    use LoggingTrait;

    /**
     * List of all the files being loaded.
     */
    protected array $files = [];

    /**
     * Which declared source contributed each entry, by config index.
     *
     * Only populated for entries that came from `metadata.sources`. Inline
     * `config:` entries and anything loaded through the legacy
     * `metadata.config` are absent, so a lookup miss means "local".
     *
     * @var array<int, string>
     */
    protected array $sourceProvenance = [];

    /**
     * Return logging context for the plugin.
     *
     * @return array
     *   Return additional logging context.
     */
    protected function getLoggingContext(): array
    {
        return [
            'plugin_name' => $this->getName(),
            'plugin_type' => self::class,
        ];
    }

    /**
     * Constructs a new plugin.
     *
     * @param array<int|string, mixed> $metadata
     *   Metadata for the plugin.
     * @param array<int|string, mixed> $config
     *   Configuration for the plugin.
     */
    public function __construct(protected array $metadata = [], protected array $config = [])
    {
        $entries = $this->loadDeclaredSources();

        // Load the extra config files for each plugin.
        if (isset($metadata['config'])) {
            $files = $metadata['config'];
            if (!is_array($files)) {
                if (is_string($files) && !Path::looksLikeUrl($files)) {
                    // Keep the path as written when realpath() fails. It used
                    // to become `false`, which Config::load() skips without a
                    // word; as a string it reaches Config::loadFile(), which
                    // records why it could not be read (#78).
                    $files = [@realpath($files) ?: $files];
                } elseif (is_string($files) && Path::looksLikeUrl($files)) {
                    $files = [$files];
                } else {
                    $files = [];
                }
            }


            $files[] = $config;
            $files = array_filter($files);

            foreach ($files as &$file) {
                if (is_string($file) && !Path::looksLikeUrl($file)) {
                    $file = realpath($file) ?: $file;
                }
            }

            unset($file);

            $this->files = $files;

            // A plugin's own config files fail open exactly like the top-level
            // ones do: an unreadable or malformed file leaves the plugin with
            // an empty rule list, which for a block plugin means it matches
            // nothing. Report what did not load — the logger is already
            // configured by the time plugins are constructed, so unlike the
            // bootstrap load this can be logged directly (#78).
            Config::clearLoadErrors();
            $this->config = Config::load($files);

            foreach (Config::getLoadErrors() as $error) {
                $this->getLogger()->error('Plugin config file failed to load — its rules are NOT active', [
                    'plugin' => $this->getName(),
                    'file' => $error['file'],
                    'reason' => $error['message'],
                ]);
            }

            $this->warnLegacyListConfig();

            $this->getLogger()->debug('Plugin initialized with config files', [
                'plugin' => $this->getName(),
                'config_files' => array_filter($files, is_string(...)),
                'metadata' => $this->metadata,
            ]);
        } else {
            $this->getLogger()->debug('Plugin initialized', [
                'plugin' => $this->getName(),
                'metadata' => $this->metadata,
                'config' => $this->config,
            ]);
        }

        $this->config = $this->mergeSourceEntries($entries, $this->config);
    }

    /**
     * Load every source declared under `metadata.sources`.
     *
     * Failures are governed by each source's own `on_error` and `required`
     * settings; a source marked required rethrows and takes the bootstrap with
     * it, which is what an allow list wants and a block list does not.
     *
     * @return array<int, mixed>
     *   Merged entries in declaration order, empty when nothing is declared.
     */
    protected function loadDeclaredSources(): array
    {
        $declared = $this->metadata['sources'] ?? null;

        if (!is_array($declared) || $declared === []) {
            return [];
        }

        $sourceManager = $this->sourceManager();
        $entries = $sourceManager->load($declared);

        $this->sourceProvenance = $sourceManager->provenance();

        foreach ($sourceManager->errors() as $error) {
            $this->getLogger()->warning('Plugin source did not contribute its entries', [
                'plugin' => $this->getName(),
                'source' => $error['source'],
                'reason' => $error['message'],
            ]);
        }

        return $entries;
    }

    /**
     * Combine source entries with whatever the plugin already had.
     *
     * `NestedArray::mergeDeepArray()` renumbers integer keys, so list entries
     * from sources append ahead of local ones while a map-shaped document —
     * the nested `scoring` and `risk_levels` trees VulnerabilityScore loads —
     * still merges by key. Local config lands last either way, so a site can
     * always add to a shared list without editing it.
     *
     * @param array<int, mixed> $entries
     *   Entries produced by declared sources.
     * @param array<array-key, mixed> $config
     *   Configuration assembled from files and inline rules.
     *
     * @return array<array-key, mixed>
     *   The merged configuration.
     */
    protected function mergeSourceEntries(array $entries, array $config): array
    {
        if ($entries === []) {
            return $config;
        }

        return NestedArray::mergeDeepArray([$entries, $config]);
    }

    /**
     * Note when `metadata.config` is doing a job `metadata.sources` now does.
     *
     * The key is only deprecated for rule *lists*, which sources handle with
     * declared formats and failure policies. It stays the mechanism for merging
     * nested configuration documents, so the notice is limited to the case that
     * actually has a replacement rather than firing on every use.
     */
    protected function warnLegacyListConfig(): void
    {
        if (isset($this->metadata['sources']) || $this->config === [] || !array_is_list($this->config)) {
            return;
        }

        $this->getLogger()->notice(
            'metadata.config is deprecated for rule lists; declare metadata.sources instead, '
            . 'which adds format handling, filtering, and per-source failure policy',
            [
                'plugin' => $this->getName(),
                'files' => array_values(array_filter($this->files, is_string(...))),
            ]
        );
    }

    /**
     * The source manager used to resolve `metadata.sources`.
     *
     * Overridable so tests can supply a manager backed by a temporary cache.
     *
     * @return SourceManager
     *   The manager.
     */
    protected function sourceManager(): SourceManager
    {
        return new SourceManager();
    }

    /**
     * Which source contributed the entry at a config index.
     *
     * @param int $index
     *   Index into the plugin's merged config.
     *
     * @return string|null
     *   The source name, or NULL when the entry is local.
     */
    public function entrySource(int $index): ?string
    {
        return $this->sourceProvenance[$index] ?? null;
    }

    /**
     * {@inheritdoc}
     */
    public function getStatusCode(?Request $request = null): int
    {
        return intval($this->metadata['status_code'] ?? 400);
    }

    /**
     * {@inheritdoc}
     */
    public function getExpirationTime(?Request $request = null): int
    {
        return intval($this->metadata['default_expiration_time'] ?? 0);
    }

    /**
     * {@inheritdoc}
     *
     * Read from `metadata.challenge_provider`, alongside the other
     * per-entry knobs. Only consulted for `response: challenge` entries —
     * setting it on a block or allow plugin is inert rather than an error,
     * since the same plugin class is often used for all three.
     */
    public function getChallengeProviderName(): ?string
    {
        $provider = $this->metadata['challenge_provider'] ?? null;

        if (!is_string($provider)) {
            return null;
        }

        $provider = trim($provider);

        return $provider === '' ? null : $provider;
    }
}
