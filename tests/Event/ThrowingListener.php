<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Event;

use Kanopi\Firewall\Event\DecisionEvent;

/**
 * A configured listener whose downstream is down (#396).
 */
class ThrowingListener
{
    public function __invoke(DecisionEvent $decisionEvent): void
    {
        throw new \RuntimeException('the notifier is down');
    }
}
