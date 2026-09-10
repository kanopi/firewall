<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Event;

use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * A listener that is having a bad day, which is the realistic case.
 *
 * Hosts register things that talk to sockets, queues and HTTP endpoints. All
 * of those fail, and none of them should be able to stop the firewall
 * blocking an attacker.
 */
class ThrowingDispatcher implements EventDispatcherInterface
{
    public int $calls = 0;

    public function dispatch(object $event): object
    {
        $this->calls++;

        throw new \RuntimeException('the metrics socket is not there');
    }
}
