<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Event;

use Kanopi\Firewall\Event\DecisionEvent;

/**
 * A listener a configuration can name, which writes down what it was told (#396).
 *
 * Static, because the firewall builds it from a class name and a test cannot hold the
 * instance. `$journal` is shared with the test's own host dispatcher so the order the two
 * are told in can be asserted.
 */
class RecordingListener
{
    /**
     * @var array<int, string>
     */
    public static array $journal = [];

    public function __construct(private readonly string $label = 'configured')
    {
    }

    public function __invoke(DecisionEvent $decisionEvent): void
    {
        self::$journal[] = $this->label . ':' . substr((string) strrchr($decisionEvent::class, '\\'), 1);
    }
}
