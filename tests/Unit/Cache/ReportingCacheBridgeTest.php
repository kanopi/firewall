<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Cache;

use Kanopi\Firewall\Cache\ReportingCacheBridge;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * A regex-corpus write the pool refused is reported, once (#394).
 *
 * Found against Memcached: the largest corpus entry is about 1.5 MB, and a pool that
 * refuses it passes the plugin's probe while every request pays the full parse.
 */
final class ReportingCacheBridgeTest extends TestCase
{
    private TestLogHandler $log;

    protected function setUp(): void
    {
        parent::setUp();

        LoggingFactory::setLogger(LoggingFactory::create([['class' => TestLogHandler::class]]));
        $handler = LoggingFactory::logger()->getHandlers()[0];
        $this->assertInstanceOf(TestLogHandler::class, $handler);
        $this->log = $handler;
    }

    /**
     * A pool that stores small values and refuses large ones, as Memcached does past its
     * item size limit.
     */
    private function pool(int $limit): ArrayAdapter
    {
        return new class ($limit) extends ArrayAdapter {
            public function __construct(private readonly int $limit)
            {
                parent::__construct();
            }

            public function save(CacheItemInterface $item): bool
            {
                return strlen(serialize($item->get())) <= $this->limit && parent::save($item);
            }
        };
    }

    public function testAWriteThatLandsSaysNothing(): void
    {
        $bridge = new ReportingCacheBridge($this->pool(1024));

        $this->assertTrue($bridge->save('small', ['regex' => 'x']));
        $this->assertSame(['regex' => 'x'], $bridge->fetch('small'));
        $this->assertFalse($this->log->hasWarningContaining('refused a write'));
    }

    public function testARefusedWriteIsReportedOnce(): void
    {
        $bridge = new ReportingCacheBridge($this->pool(1024));

        $this->assertFalse($bridge->save('corpus-a', str_repeat('x', 4096), 0));
        $this->assertFalse($bridge->save('corpus-b', str_repeat('y', 4096)));

        $this->assertTrue($this->log->hasWarningContaining('refused a write'));
        $this->assertCount(1, array_filter(
            $this->log->records,
            static fn ($record): bool => str_contains($record->message, 'refused a write')
        ), 'The first one says what is wrong; the rest would only repeat it');
    }

    /**
     * A lifetime is passed through only when one was given, as the parent expects.
     */
    public function testALifetimeIsPassedThrough(): void
    {
        $pool = $this->pool(1024);
        $bridge = new ReportingCacheBridge($pool);

        $bridge->save('expiring', 'value', 1);
        $bridge->save('forever', 'value');

        $this->assertTrue($pool->getItem('expiring')->isHit());
        $this->assertTrue($pool->getItem('forever')->isHit());
    }
}
