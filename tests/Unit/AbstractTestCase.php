<?php

namespace Kanopi\Firewall\Tests\Unit;


use Kanopi\Firewall\Logging\LoggingFactory;
use PHPUnit\Framework\TestCase;

/**
 * Abstract Class used for setting things up.
 */
abstract class AbstractTestCase extends TestCase
{

    /**
     * Set Up Method.
     */
    protected function setUp(): void
    {
        parent::setUp();
        LoggingFactory::setLogger(LoggingFactory::create([]));
    }
}