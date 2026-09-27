<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Event;

/**
 * A configured listener whose constructor refuses its arguments (#396).
 */
class ListenerThatCannotBeBuilt
{
    public function __construct()
    {
        throw new \InvalidArgumentException('a webhook URL is required');
    }

    public function __invoke(): void
    {
    }
}
