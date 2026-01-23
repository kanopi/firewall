<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Exception;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use PHPUnit\Framework\TestCase;

class FirewallBlockedExceptionTest extends TestCase
{
    public function testMessageAndDefaultStatusCode(): void
    {
        $exception = new FirewallBlockedException('Blocked');
        $this->assertSame('Blocked', $exception->getMessage());
        $this->assertSame(400, $exception->getCode());
        $this->assertSame(400, $exception->getStatusCode());
    }

    public function testCustomStatusCode(): void
    {
        $exception = new FirewallBlockedException('Forbidden', 403);
        $this->assertSame('Forbidden', $exception->getMessage());
        $this->assertSame(403, $exception->getStatusCode());
    }

    public function testPreviousException(): void
    {
        $previous = new \RuntimeException('original');
        $exception = new FirewallBlockedException('Blocked', 429, $previous);
        $this->assertSame($previous, $exception->getPrevious());
        $this->assertSame(429, $exception->getStatusCode());
    }

    public function testIsRuntimeException(): void
    {
        $exception = new FirewallBlockedException('test');
        $this->assertInstanceOf(\RuntimeException::class, $exception);
    }
}
