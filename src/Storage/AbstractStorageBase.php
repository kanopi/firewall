<?php

namespace Kanopi\Firewall\Storage;

use Kanopi\Firewall\Logging\LoggingTrait;

/**
 * Abstract Class for Storage Base.
 */
abstract class AbstractStorageBase implements StorageInterface
{
    use LoggingTrait;

    /**
     * Construct a new AbstractStorageBase object.
     *
     * @param array<string, mixed> $config
     *   Configuration details.
     */
    public function __construct(protected array $config = [])
    {
    }
}
