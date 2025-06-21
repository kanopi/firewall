<?php

namespace Kanopi\Firewall\Tests\Logging;

use Kanopi\Firewall\Logging\LoggingTrait;

/**
 * Basic stub class using the LoggingTrait for test purposes.
 */
class LoggingTraitUser
{
    use LoggingTrait;

    public function logSomething(): void
    {
        $this->log('warning', 'Trait-based warning log', ['type' => 'example']);
    }
}