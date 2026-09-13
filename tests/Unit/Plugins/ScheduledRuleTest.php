<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Plugins\ScheduledRuleInterface;
use Kanopi\Firewall\Tests\Plugins\TestScheduledPlugin;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Schedule;
use Symfony\Component\HttpFoundation\Request;

/**
 * A rule inside and outside its window (#205).
 *
 * `Schedule` is tested against instants it is handed; this is the other half -- the rule
 * asking about *now*, and the manager acting on the answer. Both are pinned with date
 * boundaries decades away rather than by controlling the clock, so the suite is
 * deterministic without a clock abstraction the library does not otherwise need.
 */
final class ScheduledRuleTest extends AbstractTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        TestScheduledPlugin::$evaluations = 0;
    }

    /**
     * A rule with no schedule is awake, which is every rule written before 2.27.0.
     */
    public function testARuleWithoutAScheduleIsAlwaysAwake(): void
    {
        $plugin = new TestScheduledPlugin();

        $this->assertInstanceOf(ScheduledRuleInterface::class, $plugin);
        $this->assertNull($plugin->getSchedule());
        $this->assertTrue($plugin->isActiveNow());
    }

    /**
     * A rule inside its window is awake, and says which window.
     */
    public function testARuleInsideItsWindowIsAwake(): void
    {
        $plugin = new TestScheduledPlugin(['active' => ['timezone' => 'UTC', 'from' => '2000-01-01']]);

        $this->assertTrue($plugin->isActiveNow());
        $this->assertInstanceOf(Schedule::class, $plugin->getSchedule());
        $this->assertSame('from 2000-01-01 (UTC)', $plugin->getSchedule()->describe());
    }

    /**
     * A rule past its window is asleep.
     */
    public function testARulePastItsWindowIsAsleep(): void
    {
        $plugin = new TestScheduledPlugin(['active' => ['timezone' => 'UTC', 'until' => '2000-01-01']]);

        $this->assertFalse($plugin->isActiveNow());
    }

    /**
     * A schedule nobody can read takes the rule out rather than guessing.
     *
     * The throw is what `LazyObjectRegistry` turns into a failed rule, which is what
     * `getFailedRules()` and `firewall-doctor` report. Guessing would mean choosing
     * silently between over-blocking and not protecting.
     */
    public function testAnUnreadableScheduleStopsTheRule(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/active\.timezone` is required/');

        new TestScheduledPlugin(['active' => ['days' => ['mon']]]);
    }

    /**
     * The manager does not consult a sleeping rule.
     *
     * The evaluation count is the assertion. A rule that ran and had its answer thrown
     * away would pass an `assertFalse()` on the verdict and fail this -- and the
     * difference is a rate limit spending somebody's budget during a window it was never
     * going to enforce, and a GeoIP lookup per request for nothing.
     */
    public function testASleepingRuleIsNeverEvaluated(): void
    {
        $manager = PluginManager::createFromPluginsArray([[
            'plugin' => TestScheduledPlugin::class,
            'metadata' => ['name' => 'nightly', 'active' => ['timezone' => 'UTC', 'until' => '2000-01-01']],
        ]]);

        $this->assertFalse($manager->evaluate(new Request()));
        $this->assertSame(0, TestScheduledPlugin::$evaluations);
    }

    /**
     * An awake rule is consulted exactly as it always was.
     */
    public function testAnAwakeRuleIsEvaluated(): void
    {
        $manager = PluginManager::createFromPluginsArray([[
            'plugin' => TestScheduledPlugin::class,
            'metadata' => ['name' => 'nightly', 'active' => ['timezone' => 'UTC', 'from' => '2000-01-01']],
        ]]);

        $this->assertNotFalse($manager->evaluate(new Request()));
        $this->assertSame(1, TestScheduledPlugin::$evaluations);
    }

    /**
     * A sleeping rule does not stop the rules after it.
     *
     * Evaluation is first match wins, and "skipped" has to mean skipped rather than
     * "matched nothing and stopped looking" -- a scheduled rule sitting above a
     * permanent one would otherwise turn its own window off as well.
     */
    public function testASleepingRuleDoesNotShadowTheOnesBelowIt(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            [
                'plugin' => TestScheduledPlugin::class,
                'weight' => 1,
                'metadata' => ['name' => 'asleep', 'active' => ['timezone' => 'UTC', 'until' => '2000-01-01']],
            ],
            [
                'plugin' => TestScheduledPlugin::class,
                'weight' => 2,
                'metadata' => ['name' => 'awake'],
            ],
        ]);

        $matched = $manager->evaluate(new Request());

        $this->assertNotFalse($matched);
        $this->assertSame('awake', $matched->getName());
        $this->assertSame(1, TestScheduledPlugin::$evaluations);
    }

    /**
     * A plugin that does not implement the interface is not asked about windows.
     *
     * `ScheduledRuleInterface` is separate from `PluginInterface` so that a custom rule
     * written against the documented guide keeps working across an upgrade, which is only
     * true if the manager tolerates one that has never heard of it.
     */
    public function testAPluginWithoutTheInterfaceStillEvaluates(): void
    {
        $manager = PluginManager::createFromPluginsArray([[
            'plugin' => \Kanopi\Firewall\Tests\Plugins\TestTruePlugin::class,
            'metadata' => ['active' => ['timezone' => 'UTC', 'until' => '2000-01-01']],
        ]]);

        $this->assertNotFalse($manager->evaluate(new Request()));
    }
}
