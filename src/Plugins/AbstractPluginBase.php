<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Logging\LoggingTrait;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\Path;
use Symfony\Component\HttpFoundation\Request;

/**
 * Abstract Plugin used for creating a plugin.
 */
abstract class AbstractPluginBase implements PluginInterface
{
    use LoggingTrait;

    /**
     * List of all the files being loaded.
     */
    protected array $files = [];

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
}
