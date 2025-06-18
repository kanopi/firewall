<?php

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Logging\LoggingTrait;

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
    }

    /**
     * {@inheritdoc}
     */
    public function getStatusCode(): int
    {
        return (int) $this->metadata['status_code'] ?? 400;
    }

    /**
     * {@inheritdoc}
     */
    public function getExpirationTime(): int
    {
        return (int) $this->metadata['default_expiration_time'] ?? 0;
    }

}
