<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\DegradedBackends;

/**
 * A backend that started but cannot reach its server (#273).
 *
 * No Redis here on purpose. What is under test is the record a degraded backend
 * leaves behind, which is the half that makes the degrade visible to a host
 * application; whether Redis can be reached is `RedisStorage`'s problem.
 */
class DegradedBackendsTest extends AbstractTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        DegradedBackends::reset();
    }

    protected function tearDown(): void
    {
        DegradedBackends::reset();
        parent::tearDown();
    }

    /**
     * Nothing is recorded until something degrades.
     */
    public function testNothingIsRecordedByDefault(): void
    {
        $this->assertSame([], DegradedBackends::all());
    }

    /**
     * A degraded backend is recorded with the component it serves and why.
     *
     * The component is in the operator's terms rather than the class's, because
     * "the block list is unreachable" is the sentence a status report needs to
     * be able to write.
     */
    public function testADegradedBackendIsRecorded(): void
    {
        DegradedBackends::record('block list', 'Some\\RedisStorage', 'Connection refused');

        $this->assertSame(
            [['component' => 'block list', 'backend' => 'Some\\RedisStorage', 'error' => 'Connection refused']],
            DegradedBackends::all()
        );
    }

    /**
     * One unreachable server is one fact, however many times it is hit.
     *
     * A process constructs the same backend more than once -- two rate limit
     * rules against one server, or a status report building every rule to ask.
     * A report listing that three times reads like three problems.
     */
    public function testTheSameFailureIsRecordedOnce(): void
    {
        DegradedBackends::record('rate limit', 'Some\\RedisRateLimitStorage', 'Connection refused');
        DegradedBackends::record('rate limit', 'Some\\RedisRateLimitStorage', 'Connection refused');
        DegradedBackends::record('rate limit', 'Some\\RedisRateLimitStorage', 'Connection refused');

        $this->assertCount(1, DegradedBackends::all());
    }

    /**
     * Two genuinely different failures are two entries.
     *
     * Same class, different component; same component, different error. Both
     * are distinct facts an operator would want to see.
     */
    public function testDifferentFailuresAreKeptApart(): void
    {
        DegradedBackends::record('block list', 'Some\\RedisStorage', 'Connection refused');
        DegradedBackends::record('rate limit', 'Some\\RedisStorage', 'Connection refused');
        DegradedBackends::record('block list', 'Some\\RedisStorage', 'Connection timed out');

        $this->assertCount(3, DegradedBackends::all());
    }

    /**
     * The record can be cleared, for a process that wants to reassess.
     */
    public function testResetForgetsEverything(): void
    {
        DegradedBackends::record('block list', 'Some\\RedisStorage', 'Connection refused');
        DegradedBackends::reset();

        $this->assertSame([], DegradedBackends::all());
    }
}
