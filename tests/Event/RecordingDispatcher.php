<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Event;

use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * The smallest thing that satisfies PSR-14, keeping everything it is given.
 *
 * Deliberately not Symfony's dispatcher. The point of #218 is that a host can
 * observe decisions with any PSR-14 implementation and without adopting
 * Symfony's, so the suite proves that by using one that is not Symfony's --
 * a test against `symfony/event-dispatcher` would have proved the opposite of
 * what the issue asked for, and would have added a dev dependency to do it.
 */
class RecordingDispatcher implements EventDispatcherInterface
{
    /**
     * @var array<int, object>
     */
    public array $events = [];

    public function dispatch(object $event): object
    {
        $this->events[] = $event;

        return $event;
    }

    /**
     * Every recorded event of one class.
     *
     * @param class-string $class
     *   The event class to filter on.
     *
     * @return array<int, object>
     *   The matching events, in dispatch order.
     */
    public function ofType(string $class): array
    {
        return array_values(array_filter($this->events, static fn(object $e): bool => $e instanceof $class));
    }

    /**
     * The class names of everything recorded, in order.
     *
     * @return array<int, string>
     *   Short class names.
     */
    public function names(): array
    {
        return array_map(
            static fn(object $e): string => substr((string) strrchr('\\' . $e::class, '\\'), 1),
            $this->events
        );
    }
}
