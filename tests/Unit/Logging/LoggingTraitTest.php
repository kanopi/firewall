<?php

namespace Kanopi\Firewall\Tests\Unit\Logging;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Tests\Logging\LoggingTraitUser;
use Monolog\Level;
use Monolog\Logger;
use Monolog\Handler\TestHandler;
use PHPUnit\Framework\TestCase;

/**
 * Test the LoggingTrait in isolation.
 */
final class LoggingTraitTest extends TestCase
{

    /**
     * Ensures any class using LoggingTrait can send messages to the configured logger.
     */
    public function testTraitLogsMessage(): void
    {
        $testHandler = new TestHandler();
        $logger = new Logger('test-trait');
        $logger->pushHandler($testHandler);

        LoggingFactory::setLogger($logger);

        $user = new LoggingTraitUser();
        $user->logSomething();

        $this->assertTrue($testHandler->hasWarningRecords());
        $this->assertTrue($testHandler->hasRecordThatContains('Trait-based warning log', Level::Warning));
    }

    /**
     * Regression for #64: CR/LF in string context values must be removed
     * before reaching the logger, so attacker-controlled bytes can't
     * inject extra log lines on handlers / formatters that emit
     * `%message%`-style output verbatim.
     */
    public function testSanitizeContextStripsCrlfFromStrings(): void
    {
        $user = new LoggingTraitUser();
        $sanitized = $user->publicSanitizeContext([
            'header' => "value\r\nfake-line: injected",
            'nested' => ['ok' => "ok\nbreak"],
            'number' => 42,
            'list' => ["a\r", "b\n", "c"],
        ]);

        $this->assertSame('valuefake-line: injected', $sanitized['header']);
        $this->assertSame('okbreak', $sanitized['nested']['ok']);
        $this->assertSame(42, $sanitized['number']);
        $this->assertSame(['a', 'b', 'c'], $sanitized['list']);
    }

    /**
     * Regression for #64: `getContext()` runs `sanitizeContext()` so the
     * default request context (which includes user_agent and URL) is
     * always CRLF-clean.
     */
    public function testGetContextSanitizesRequestDerivedValues(): void
    {
        $request = \Symfony\Component\HttpFoundation\Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '1.2.3.4',
            'HTTP_USER_AGENT' => "Mozilla/5.0\r\nFake-Header: 1",
        ]);

        $user = new LoggingTraitUser();
        $context = $user->publicGetContext($request, ['extra' => "extra\r\nvalue"]);

        $this->assertStringNotContainsString("\r", (string) $context['user_agent']);
        $this->assertStringNotContainsString("\n", (string) $context['user_agent']);
        $this->assertStringNotContainsString("\r", (string) $context['extra']);
        $this->assertStringNotContainsString("\n", (string) $context['extra']);
    }

    /**
     * Stringable objects are sanitised, not passed through.
     *
     * An object is not a string, so the string branch skips it — but a
     * formatter will call `__toString()` on it downstream and emit whatever
     * comes back. If that includes CRLF the log line is forgeable, which is
     * exactly the injection #64 closed for plain strings. The value must be
     * stringified and cleaned here, while the object stays out of the log
     * otherwise untouched.
     */
    public function testSanitizeContextStripsCrlfFromStringableObjects(): void
    {
        $user = new LoggingTraitUser();

        $stringable = new class () {
            public function __toString(): string
            {
                return "legit\r\nfake-line: injected";
            }
        };

        $sanitized = $user->publicSanitizeContext(['token' => $stringable]);

        $this->assertSame('legitfake-line: injected', $sanitized['token']);
    }

    /**
     * An object with no __toString() is left alone rather than coerced.
     *
     * Casting it would raise; the sanitiser has to fall through to the
     * pass-through branch instead.
     */
    public function testSanitizeContextLeavesNonStringableObjectsAlone(): void
    {
        $user = new LoggingTraitUser();

        $plain = new \stdClass();
        $plain->field = 'value';

        $sanitized = $user->publicSanitizeContext(['obj' => $plain]);

        $this->assertSame($plain, $sanitized['obj']);
    }
}