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
     *
     * @var string[]
     */
    protected array $files = [];

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
                    $files = [@realpath($files)];
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
                    $file = realpath($file);
                }
            }

            $this->files = $files;
            $this->config = Config::load($files);

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
