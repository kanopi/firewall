<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\FirewallMode;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Monolog\Level;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * What the panic file does to a running firewall (#207).
 *
 * `PanicSwitchTest` covers reading the file. This covers the consequence:
 * the mode a request is actually evaluated in, and the log line that is the
 * only lasting evidence the switch was ever thrown.
 */
class PanicSwitchIntegrationTest extends AbstractTestCase
{
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-panic-live-' . uniqid();
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @chmod($file, 0600);
            @unlink($file);
        }

        @rmdir($this->dir);
        parent::tearDown();
    }

    /**
     * Build a firewall configured for `block`, optionally with a panic file.
     *
     * @param string|null $panicContents
     *   What to put in the panic file, or NULL to leave it absent.
     *
     * @return array{0: Firewall, 1: TestLogHandler, 2: string}
     *   The firewall, the captured log and the panic file's path.
     */
    private function build(?string $panicContents): array
    {
        $path = $this->dir . '/panic';

        if ($panicContents !== null) {
            file_put_contents($path, $panicContents);
        }

        $handler = new TestLogHandler(Level::Debug);

        $firewall = Firewall::create([
            [
                'logger' => [['class' => $handler]],
                'global' => ['mode' => 'block', 'panic_file' => $path],
            ],
        ]);

        return [$firewall, $handler, $path];
    }

    /**
     * With no panic file, nothing changes and nothing is said.
     */
    public function testNoPanicFileLeavesTheConfiguredModeAlone(): void
    {
        [$firewall, $handler] = $this->build(null);

        $this->assertSame(FirewallMode::Block, $firewall->getMode());
        $this->assertSame(FirewallMode::Block, $firewall->getConfiguredMode());
        $this->assertFalse($firewall->getPanicSwitch()['active']);
        $this->assertFalse($handler->hasWarningContaining('panic switch'));
    }

    /**
     * A panic file naming a mode changes the mode the firewall runs in, while
     * leaving the configured mode reportable -- a status page needs both to
     * say "this is temporary".
     */
    public function testAPanicFileChangesTheEffectiveMode(): void
    {
        [$firewall, , $path] = $this->build('log');

        $this->assertSame(FirewallMode::Log, $firewall->getMode());
        $this->assertSame(FirewallMode::Block, $firewall->getConfiguredMode());

        $panic = $firewall->getPanicSwitch();
        $this->assertTrue($panic['active']);
        $this->assertSame(FirewallMode::Log, $panic['mode']);
        $this->assertSame($path, $panic['path']);
        $this->assertNull($panic['problem']);
    }

    /**
     * The warning is the whole safety mechanism, so it carries enough to act
     * on without going and looking: which file, what it changed, and that
     * deleting it undoes this.
     */
    public function testAnActivePanicSwitchLogsLoudlyWithBothModes(): void
    {
        [, $handler, $path] = $this->build('log');

        $this->assertTrue($handler->hasWarningContaining('Firewall panic switch is ACTIVE'));

        $record = null;

        foreach ($handler->records as $candidate) {
            if (str_contains((string) $candidate->message, 'panic switch is ACTIVE')) {
                $record = $candidate;
            }
        }

        $this->assertNotNull($record);
        $this->assertSame(Level::Warning, $record->level);
        $this->assertSame($path, $record->context['panic_file']);
        $this->assertSame('block', $record->context['configured_mode']);
        $this->assertSame('log', $record->context['effective_mode']);
        $this->assertSame($path, $record->context['remove_to_restore']);
    }

    /**
     * A file that exists and names nothing usable leaves the mode alone --
     * and says so at `error`, because somebody just reached for the switch
     * and it did not take.
     *
     * @param string $contents
     *   What the file holds.
     */
    #[DataProvider('inertFiles')]
    public function testAnInertPanicFileIsReportedAtErrorAndChangesNothing(string $contents): void
    {
        [$firewall, $handler, $path] = $this->build($contents);

        $this->assertSame(FirewallMode::Block, $firewall->getMode());
        $this->assertFalse($firewall->getPanicSwitch()['active']);
        $this->assertNotNull($firewall->getPanicSwitch()['problem']);

        $this->assertTrue(
            $handler->hasErrorContaining('panic file is present but was not applied'),
            'An unusable panic file must be reported, not silently ignored.'
        );

        $record = null;

        foreach ($handler->records as $candidate) {
            if (str_contains((string) $candidate->message, 'panic file is present')) {
                $record = $candidate;
            }
        }

        $this->assertNotNull($record);
        $this->assertSame($path, $record->context['panic_file']);
        $this->assertSame('block', $record->context['effective_mode']);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function inertFiles(): array
    {
        return [
            // `touch panic` -- the most natural thing to try, and the one that
            // must not disable anything.
            'empty' => [''],
            'not a mode' => ['banhammer'],
        ];
    }

    /**
     * The switch reaches the request path, not just the accessors.
     *
     * `disabled` is the strongest thing it can do, so it is the one worth
     * proving end to end: a rule that blocks under the configured mode has to
     * stop blocking while the file is there.
     */
    public function testTheSwitchActuallyChangesWhatHappensToARequest(): void
    {
        $handler = new TestLogHandler(Level::Debug);
        $path = $this->dir . '/panic';

        $config = [
            'logger' => [['class' => $handler]],
            'global' => ['mode' => 'exception', 'panic_file' => $path],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
                    'response' => 'block',
                    'enable' => true,
                    'config' => ['203.0.113.5'],
                ],
            ],
        ];

        $request = $this->getRequest('203.0.113.5');

        try {
            Firewall::create([$config])->evaluate($request);
            $this->fail('Expected the rule to block before the switch was thrown.');
        } catch (\Kanopi\Firewall\Exception\FirewallBlockedException) {
            $this->addToAssertionCount(1);
        }

        file_put_contents($path, 'disabled');

        $this->assertTrue(
            Firewall::create([$config])->evaluate($request),
            'With the panic file in place the same request must be allowed through.'
        );
    }
}
