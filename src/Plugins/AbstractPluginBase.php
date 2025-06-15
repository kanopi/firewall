<?php

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Logging\LoggingTrait;
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
    }

    /**
     * {@inheritdoc}
     */
    abstract public function getName(): string;

    /**
     * {@inheritdoc}
     */
    abstract public function getDescription(): string;

    /**
     * {@inheritdoc}
     */
    abstract public function evaluate(Request $request): bool;
}
