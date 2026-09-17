<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration;

use Kanopi\Firewall\Event\RequestTarpitted;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Storage\ConcurrencyGaugeInterface;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Tarpit\TarpitGate;
use Psr\EventDispatcher\EventDispatcherInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * `response: tarpit`, through the firewall (#329).
 *
 * Nothing here actually sleeps: the gate's sleep is a seam and these swap it
 * out. What is being tested is that the cap exists, that it is wired to a
 * backend that can count, and that a backend that cannot count stops the
 * firewall from starting.
 */
class TarpitTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();
        putenv('FIREWALL_BYPASS_CLI=1');

        $this->tempDir = sys_get_temp_dir() . '/firewall_tarpit_' . uniqid();
        if (!mkdir($this->tempDir, 0777, true)) {
            throw new \RuntimeException('Failed to create temp directory: ' . $this->tempDir);
        }
    }

    protected function tearDown(): void
    {
        foreach ((array) glob($this->tempDir . '/*') as $path) {
            if (is_string($path)) {
                @unlink($path);
            }
        }

        @rmdir($this->tempDir);
        parent::tearDown();
    }

    /**
     * The whole reason this was split out of #203 rather than shipped with it.
     *
     * A tarpit holds a php-fpm worker for its duration, so without an atomic
     * cap a handful of requests takes the site down — and the rule looks like
     * it is working while they do.
     */
    public function testATarpitRuleRefusesToStartWithoutABackendThatCanCount(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('cannot count how many holds are in flight');

        Firewall::create([$this->config(['type' => InMemoryStorage::class])]);
    }

    /**
     * And a configuration with no tarpit rule is unaffected, whatever its
     * backend — the check has to be about the rules, not about the storage.
     */
    public function testAConfigurationWithNoTarpitRuleIsUnaffected(): void
    {
        $config = $this->configArray(['type' => InMemoryStorage::class]);
        $config['plugins'][0]['response'] = 'block';

        $firewall = Firewall::create([$this->write($config, 'noTarpit.yml')]);

        $this->expectException(FirewallBlockedException::class);
        $firewall->evaluate($this->request());
    }

    public function testAMatchingRequestIsHeldAndThenContinues(): void
    {
        $firewall = Firewall::create([$this->config()]);
        $gate = $this->replaceGate($firewall, 5, 30);

        $this->assertTrue($firewall->evaluate($this->request()), 'A tarpit is not terminal');
        $this->assertSame([7], $gate->slept);
    }

    /**
     * Non-terminal on purpose: a tarpit rule and a block rule matching the same
     * client compose into a slow block rather than needing a feature of their
     * own.
     */
    public function testATarpitAndABlockComposeIntoASlowBlock(): void
    {
        $config = $this->configArray();
        $config['plugins'][] = [
            'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
            'response' => 'block',
            'enable' => true,
            'metadata' => ['name' => 'refuse'],
            'config' => ['10.0.0.50'],
        ];

        $firewall = Firewall::create([$this->write($config, 'slowBlock.yml')]);
        $gate = $this->replaceGate($firewall, 5, 30);

        try {
            $firewall->evaluate($this->request());
            $this->fail('Expected the block rule to still refuse it');
        } catch (FirewallBlockedException) {
            $this->assertSame([7], $gate->slept, 'The hold should have been paid before the refusal');
        }
    }

    /**
     * Under attack the tarpit stops tarpitting, rather than the site stopping
     * serving. That is the failure the site survives.
     *
     * The slots are claimed directly here because **one process cannot produce
     * the condition**: a synchronous hold claims, sleeps and releases before
     * the next request is evaluated, so sequential requests never meet the cap.
     * The cap is about the *other* workers, and claiming against the same
     * file-backed gauge is exactly what those workers do.
     */
    public function testAtCapacityTheRequestIsServedInsteadOfHeld(): void
    {
        $firewall = Firewall::create([$this->config()]);
        $gate = $this->replaceGate($firewall, 2, 30);
        $gauge = $this->gaugeOf($firewall);

        $this->assertTrue($firewall->evaluate($this->request()));
        $this->assertSame([7], $gate->slept);

        // Two other workers are now holding, which is the cap.
        $gauge->enter(TarpitGate::KEY, 60);
        $gauge->enter(TarpitGate::KEY, 60);

        $this->assertTrue($firewall->evaluate($this->request()), 'It should serve rather than refuse');
        $this->assertSame([7], $gate->slept, 'It held a request past the cap');

        // One of them finishes, and there is room again.
        $gauge->leave(TarpitGate::KEY);

        $this->assertTrue($firewall->evaluate($this->request()));
        $this->assertSame([7, 7], $gate->slept);
    }

    /**
     * A dry run that still takes a worker out of the pool for seven seconds is
     * not a dry run.
     */
    /**
     * A dry run that still takes a worker out of the pool for seven seconds is
     * not a dry run.
     *
     * Reached by calling `tarpit()` rather than `evaluate()`, because
     * `evaluate()` returns early under `PHP_SAPI === 'cli'` for every mode but
     * `exception` — so through the front door this test would pass without the
     * log-mode branch ever running, which is how it passed before this comment
     * existed.
     */
    public function testLogModeDoesNotActuallyHoldAnything(): void
    {
        $seen = [];
        $config = $this->configArray();
        $config['global']['mode'] = 'log';

        $firewall = Firewall::create([$this->write($config, 'logMode.yml')], [], $this->collector($seen));
        $gate = $this->replaceGate($firewall, 5, 30);

        $tarpit = new \ReflectionMethod($firewall, 'tarpit');
        $tarpit->invoke($firewall, $this->request(), $this->onlyRule($firewall));

        $this->assertSame([], $gate->slept, 'Log mode held a worker');
        $this->assertCount(1, $seen, 'A dry run still has to say what it would have done');
        $this->assertFalse($seen[0]->wasHeld());
        $this->assertSame('slow-them-down', $seen[0]->getPlugin()->getName());
        $this->assertSame(0, $seen[0]->getInFlight());
    }

    /**
     * The one tarpit rule this configuration declares, constructed.
     */
    private function onlyRule(Firewall $firewall): \Kanopi\Firewall\Plugins\PluginInterface
    {
        $manager = (new \ReflectionProperty($firewall, 'tarpitPluginManager'))->getValue($firewall);
        $this->assertInstanceOf(\Kanopi\Firewall\Plugins\PluginManager::class, $manager);

        return array_values($manager->getPlugins())[0];
    }

    /**
     * Assembled by hand rather than through `create()`, which is the only way
     * to reach a tarpit rule with no gate behind it. Silently sleeping without
     * a cap is the one behaviour the feature exists to prevent, so it does
     * nothing at all.
     */
    public function testATarpitWithNoGateHoldsNothing(): void
    {
        $firewall = Firewall::create([$this->config()]);
        $gate = $this->replaceGate($firewall, 5, 30);

        (new \ReflectionProperty($firewall, 'tarpitGate'))->setValue($firewall, null);

        $this->assertTrue($firewall->evaluate($this->request()));
        $this->assertSame([], $gate->slept);
    }

    public function testTheDecisionIsAnnouncedWithWhatHappened(): void
    {
        $seen = [];
        $firewall = Firewall::create([$this->config()], [], $this->collector($seen));
        $this->replaceGate($firewall, 1, 30);

        $firewall->evaluate($this->request());

        // Another worker takes the only slot.
        $this->gaugeOf($firewall)->enter(TarpitGate::KEY, 60);

        $firewall->evaluate($this->request());

        $this->assertCount(2, $seen);
        $this->assertTrue($seen[0]->wasHeld());
        $this->assertSame(7, $seen[0]->getSeconds());
        $this->assertSame('slow-them-down', $seen[0]->getPlugin()->getName());
        $this->assertSame(1, $seen[0]->getInFlight());
        $this->assertFalse($seen[1]->wasHeld(), 'The second was over the cap');
        $this->assertSame(0, $seen[1]->getSeconds());
        $this->assertSame(1, $seen[1]->getInFlight(), 'The other worker is still holding');
        $this->assertFalse($seen[0]->isEnforced(), 'A hold refuses nothing');
    }

    /**
     * A dispatcher that keeps every tarpit decision it is told about.
     *
     * @param array<int, RequestTarpitted> $seen
     */
    private function collector(array &$seen): EventDispatcherInterface
    {
        return new class ($seen) implements EventDispatcherInterface {
            /**
             * @param array<int, RequestTarpitted> $seen
             */
            public function __construct(public array &$seen)
            {
            }

            public function dispatch(object $event): object
            {
                if ($event instanceof RequestTarpitted) {
                    $this->seen[] = $event;
                }

                return $event;
            }
        };
    }

    /**
     * Swap the gate for one that counts sleeps instead of taking them, keeping
     * the real storage-backed gauge underneath.
     */
    private function replaceGate(Firewall $firewall, int $maxConcurrent, int $maxSeconds): TarpitGate
    {
        $gate = new class ($this->gaugeOf($firewall), $maxConcurrent, $maxSeconds) extends TarpitGate {
            /**
             * @var array<int, int>
             */
            public array $slept = [];

            protected function sleep(int $seconds): void
            {
                $this->slept[] = $seconds;
            }
        };

        $gateProperty = new \ReflectionProperty($firewall, 'tarpitGate');
        $gateProperty->setValue($firewall, $gate);

        return $gate;
    }

    /**
     * The firewall's own store, which is also the gauge behind the cap.
     */
    private function gaugeOf(Firewall $firewall): ConcurrencyGaugeInterface
    {
        $storage = (new \ReflectionProperty($firewall, 'storage'))->getValue($firewall);
        $this->assertInstanceOf(ConcurrencyGaugeInterface::class, $storage);

        return $storage;
    }

    private function request(): Request
    {
        return Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.50']);
    }

    /**
     * @param array<string, mixed> $storage
     */
    private function config(array $storage = []): string
    {
        return $this->write($this->configArray($storage));
    }

    /**
     * @param array<string, mixed> $storage
     *
     * @return array<string, mixed>
     */
    private function configArray(array $storage = []): array
    {
        return [
            'global' => ['mode' => 'exception'],
            'tarpit' => ['max_concurrent' => 5, 'max_seconds' => 30],
            'storage' => $storage === [] ? [
                'type' => 'Kanopi\Firewall\Storage\FileStorage',
                'config' => ['storage_file' => $this->tempDir . '/blocked.data'],
            ] : $storage,
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'tarpit',
                    'weight' => 0,
                    'enable' => true,
                    'metadata' => ['name' => 'slow-them-down', 'tarpit_seconds' => 7],
                    'config' => ['10.0.0.50'],
                ],
            ],
        ];
    }

    /**
     * @param array<string, mixed> $config
     */
    private function write(array $config, string $filename = 'tarpit.yml'): string
    {
        $file = $this->tempDir . '/' . $filename;
        file_put_contents($file, Yaml::dump($config, 6, 2));

        return $file;
    }
}
