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
use Symfony\Component\HttpFoundation\Request;

/**
 * Abstract Plugin used for creating a plugin.
 */
abstract class AbstractPluginBase implements PluginInterface
{
    use LoggingTrait;

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
                $files = [@realpath($files)];
            }

            $files[] = $config;
            $files = array_filter($files);

            foreach ($files as &$file) {
                if (is_string($file)) {
                    $file = realpath($file);
                }
            }

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
