<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Logging;

use Kanopi\Firewall\Logging\Handler\DatabaseHandler;
use Kanopi\Firewall\Logging\LoggingFactory;
use Monolog\Handler\ErrorLogHandler;
use Monolog\Handler\HandlerInterface;
use Monolog\Handler\IFTTTHandler;
use Monolog\Handler\NativeMailerHandler;
use Monolog\Handler\PushoverHandler;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Handler\SendGridHandler;
use Monolog\Handler\SlackHandler;
use Monolog\Handler\SlackWebhookHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\SyslogHandler;
use Monolog\Handler\TelegramBotHandler;
use Monolog\Level;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

/**
 * Verifies that every logger example documented in README.md actually
 * constructs cleanly via LoggingFactory::create().
 *
 * Each case below mirrors a YAML block from the "Logging Configuration"
 * section of the README. The test parses the YAML the same way the
 * firewall does at boot, feeds it to the factory, and checks that the
 * expected Monolog handler ends up wired into the Logger. Construction
 * is enough — we deliberately do not attempt to send a real message
 * (no Slack, no email, no syslog daemon) because the goal here is to
 * catch signature drift in the docs, not to integration-test Monolog.
 *
 * When updating examples in README.md, mirror the change here so the
 * doc keeps shipping configs that actually work.
 */
final class ReadmeLoggingExamplesTest extends TestCase
{
    /**
     * @return array<string, array{0: string, 1: class-string<HandlerInterface>}>
     */
    public static function readmeExampleProvider(): array
    {
        return [
            'File logging (StreamHandler + LineFormatter)' => [
                <<<'YAML'
                logger:
                  - class: Monolog\Handler\StreamHandler
                    args:
                      - /tmp/firewall-readme-test.log
                      - Monolog\Level::Info
                    formatter:
                      class: Monolog\Formatter\LineFormatter
                      args:
                        - "[%datetime%] [%level_name%] [%context.plugin%] %message% %context% %extra%\n"
                        - "Y-m-d H:i:s"
                YAML,
                StreamHandler::class,
            ],

            'Rotating file logging (RotatingFileHandler)' => [
                <<<'YAML'
                logger:
                  - class: Monolog\Handler\RotatingFileHandler
                    args:
                      - /tmp/firewall-readme-test.log
                      - 7
                      - Monolog\Level::Info
                YAML,
                RotatingFileHandler::class,
            ],

            'JSON-structured logging (StreamHandler + JsonFormatter)' => [
                <<<'YAML'
                logger:
                  - class: Monolog\Handler\StreamHandler
                    args:
                      - /tmp/firewall-readme-test.ndjson
                      - Monolog\Level::Info
                    formatter:
                      class: Monolog\Formatter\JsonFormatter
                YAML,
                StreamHandler::class,
            ],

            'Syslog (SyslogHandler with named facility)' => [
                <<<'YAML'
                logger:
                  - class: Monolog\Handler\SyslogHandler
                    args:
                      - firewall
                      - user
                      - Monolog\Level::Warning
                YAML,
                SyslogHandler::class,
            ],

            'PHP error log (ErrorLogHandler)' => [
                <<<'YAML'
                logger:
                  - class: Monolog\Handler\ErrorLogHandler
                    args:
                      - 0
                      - Monolog\Level::Warning
                YAML,
                ErrorLogHandler::class,
            ],

            'Email — NativeMailerHandler' => [
                <<<'YAML'
                logger:
                  - class: Monolog\Handler\NativeMailerHandler
                    args:
                      - security@example.com
                      - "Firewall Alert"
                      - noreply@example.com
                      - Monolog\Level::Critical
                YAML,
                NativeMailerHandler::class,
            ],

            'Email — SendGridHandler' => [
                <<<'YAML'
                logger:
                  - class: Monolog\Handler\SendGridHandler
                    args:
                      - apikey
                      - SG.test-key
                      - noreply@example.com
                      - security@example.com
                      - "Firewall Alert"
                      - Monolog\Level::Critical
                YAML,
                SendGridHandler::class,
            ],

            'Slack — SlackWebhookHandler' => [
                <<<'YAML'
                logger:
                  - class: Monolog\Handler\SlackWebhookHandler
                    args:
                      - https://hooks.slack.com/services/T000/B000/test
                      - "#security-alerts"
                      - "Firewall"
                      - true
                      - ":shield:"
                      - false
                      - true
                      - Monolog\Level::Warning
                YAML,
                SlackWebhookHandler::class,
            ],

            'Slack — SlackHandler (token-based)' => [
                <<<'YAML'
                logger:
                  - class: Monolog\Handler\SlackHandler
                    args:
                      - xoxb-test-token
                      - "#security-alerts"
                      - "Firewall"
                      - true
                      - ":shield:"
                      - Monolog\Level::Critical
                YAML,
                SlackHandler::class,
            ],

            'Pushover — PushoverHandler' => [
                <<<'YAML'
                logger:
                  - class: Monolog\Handler\PushoverHandler
                    args:
                      - test-app-token
                      - test-user-key
                      - "Firewall Alert"
                      - Monolog\Level::Critical
                YAML,
                PushoverHandler::class,
            ],

            'IFTTT — IFTTTHandler' => [
                <<<'YAML'
                logger:
                  - class: Monolog\Handler\IFTTTHandler
                    args:
                      - firewall_alert
                      - test-maker-key
                      - Monolog\Level::Error
                YAML,
                IFTTTHandler::class,
            ],

            'Telegram — TelegramBotHandler' => [
                <<<'YAML'
                logger:
                  - class: Monolog\Handler\TelegramBotHandler
                    args:
                      - test-bot-token
                      - "@my_security_channel"
                      - Monolog\Level::Critical
                YAML,
                TelegramBotHandler::class,
            ],

            'Database logging — DatabaseHandler' => [
                <<<'YAML'
                logger:
                  - class: "Kanopi\\Firewall\\Logging\\Handler\\DatabaseHandler"
                    args:
                      - table: firewall_log
                        connection:
                          driver: pdo_mysql
                          host: db
                          dbname: app
                          user: firewall
                          password: secret
                        level: Monolog\Level::Warning
                        retention_days: 30
                YAML,
                DatabaseHandler::class,
            ],

            'Database logging reusing the storage connection' => [
                <<<'YAML'
                logger:
                  - class: "Kanopi\\Firewall\\Logging\\Handler\\DatabaseHandler"
                    args:
                      - table: firewall_log
                        level: Monolog\Level::Warning
                YAML,
                DatabaseHandler::class,
            ],
        ];
    }

    /**
     * The documented `level:` reaches the handler.
     *
     * `LoggingFactory` rewrites `Monolog\Level::*` strings found at the top
     * level of `args`, and `DatabaseHandler` takes one map, so its `level` sits
     * a layer deeper than that pass reaches. If the handler stopped resolving
     * the constant spelling itself, every documented example here would
     * silently fall back to the default rather than fail.
     */
    public function testDocumentedDatabaseHandlerLevelIsApplied(): void
    {
        $yaml = <<<'YAML'
        logger:
          - class: "Kanopi\\Firewall\\Logging\\Handler\\DatabaseHandler"
            args:
              - table: firewall_log
                level: Monolog\Level::Critical
        YAML;

        $handlers = LoggingFactory::create(Yaml::parse($yaml)['logger'])->getHandlers();

        self::assertInstanceOf(DatabaseHandler::class, $handlers[0]);
        self::assertSame(Level::Critical, $handlers[0]->getLevel());
        self::assertSame('firewall_log', $handlers[0]->getTable());
    }

    /**
     * Parse a README YAML block via the same parser the firewall uses
     * and assert LoggingFactory::create() wires up the expected handler.
     */
    #[DataProvider('readmeExampleProvider')]
    public function testReadmeExampleConstructsHandler(string $yaml, string $expectedHandlerClass): void
    {
        $parsed = Yaml::parse($yaml);

        $this->assertIsArray($parsed, 'README example should parse as YAML');
        $this->assertArrayHasKey('logger', $parsed, 'README example must have a logger: key');
        $this->assertIsArray($parsed['logger'], 'logger: must be a list of handlers');

        $logger = LoggingFactory::create($parsed['logger']);

        $handlers = $logger->getHandlers();
        $this->assertCount(1, $handlers, 'Exactly one handler expected from the example');
        $this->assertInstanceOf(
            $expectedHandlerClass,
            $handlers[0],
            sprintf('Expected %s but got %s', $expectedHandlerClass, $handlers[0]::class)
        );
    }

    /**
     * The combined multi-handler example from README.md should produce
     * one Logger with all four handlers attached in order. If a future
     * Monolog upgrade reshuffles a constructor and breaks the args list,
     * this test catches it.
     */
    public function testReadmeCombinedExampleConstructsAllFourHandlers(): void
    {
        $yaml = <<<'YAML'
        logger:
          - class: Monolog\Handler\RotatingFileHandler
            args:
              - /tmp/firewall-readme-combined.log
              - 14
              - Monolog\Level::Info

          - class: Monolog\Handler\SyslogHandler
            args:
              - firewall
              - user
              - Monolog\Level::Warning

          - class: Monolog\Handler\SlackWebhookHandler
            args:
              - https://hooks.slack.com/services/T000/B000/test
              - "#security-oncall"
              - "Firewall"
              - true
              - ":rotating_light:"
              - false
              - true
              - Monolog\Level::Critical

          - class: Monolog\Handler\PushoverHandler
            args:
              - test-app-token
              - test-user-key
              - "Firewall CRITICAL"
              - Monolog\Level::Critical
        YAML;

        $parsed = Yaml::parse($yaml);
        $logger = LoggingFactory::create($parsed['logger']);

        $handlers = $logger->getHandlers();
        $this->assertCount(4, $handlers);

        // Monolog stores handlers in reverse insertion order (LIFO).
        $this->assertInstanceOf(PushoverHandler::class, $handlers[0]);
        $this->assertInstanceOf(SlackWebhookHandler::class, $handlers[1]);
        $this->assertInstanceOf(SyslogHandler::class, $handlers[2]);
        $this->assertInstanceOf(RotatingFileHandler::class, $handlers[3]);
    }

    /**
     * Documentation contract: passing the literal string "LOG_USER" as
     * the syslog facility breaks because YAML does not resolve PHP
     * constants. This test guards the README callout that warns against
     * it — if Monolog ever starts accepting that string, the warning
     * should be revisited.
     */
    public function testSyslogRejectsLiteralPhpConstantStringAsFacility(): void
    {
        $yaml = <<<'YAML'
        logger:
          - class: Monolog\Handler\SyslogHandler
            args:
              - firewall
              - LOG_USER
              - Monolog\Level::Warning
        YAML;

        $parsed = Yaml::parse($yaml);

        $this->expectException(\UnexpectedValueException::class);
        LoggingFactory::create($parsed['logger']);
    }
}
