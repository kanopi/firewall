<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Tests\Plugins\TestPriorityPluginHigh;
use Kanopi\Firewall\Tests\Plugins\TestPriorityPluginLow;
use Kanopi\Firewall\Tests\Plugins\TestTruePlugin;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

class PluginManagerTest extends AbstractTestCase
{
    /**
     * Test: A valid plugin returns false.
     */
    public function testValidPluginRegisteredButReturnsFalse(): void
    {
        $manager = PluginManager::create([
            TestFalsePlugin::class => [
                'enable' => true,
                'priority' => 5,
            ],
        ]);

        $this->assertFalse($manager->evaluate(new Request()));
    }

    /**
     * Test: Plugin class is missing.
     */
    public function testInvalidPluginClassIsSkipped(): void
    {
        $manager = PluginManager::create([
            'Invalid\Missing\Plugin' => [
                'enable' => true,
            ],
        ]);

        $this->assertFalse($manager->evaluate(new Request()));
    }

    /**
     * Test: Plugin does not implement PluginInterface.
     */
    public function testNonPluginInterfaceIsSkipped(): void
    {
        $manager = PluginManager::create([
            \stdClass::class => [
                'enable' => true,
            ],
        ]);

        $this->assertFalse($manager->evaluate(new Request()));
    }

    /**
     * Test: Plugin is disabled.
     */
    public function testDisabledPluginIsSkipped(): void
    {
        $manager = PluginManager::create([
            TestFalsePlugin::class => [
                'enable' => false,
            ],
        ]);

        $this->assertFalse($manager->evaluate(new Request()));
    }

    /**
     * Test: A plugin returns true and triggers callback.
     */
    public function testPluginReturnsTrueTriggersCallback(): void
    {
        $called = false;
        $manager = PluginManager::create([
            TestTruePlugin::class => [
                'enable' => true,
            ],
        ]);

        $callback = function (bool $block, Request $request, PluginInterface $plugin) use (&$called) {
            $called = true;
            $this->assertTrue($block);
            $this->assertInstanceOf(PluginInterface::class, $plugin);
        };

        $result = $manager->evaluate(new Request(), true, $callback);

        $this->assertTrue($result);
        $this->assertTrue($called);
    }

    /**
     * Test: Plugins are sorted by priority (lower first).
     */
    public function testPluginSortingByPriority(): void
    {
        $callOrder = [];

        $manager = PluginManager::create([
            TestPriorityPluginHigh::class => [
                'enable' => true,
                'priority' => 10,
                'metadata' => ['order' => &$callOrder],
            ],
            TestPriorityPluginLow::class => [
                'enable' => true,
                'priority' => 1,
                'metadata' => ['order' => &$callOrder],
            ],
        ]);

        $manager->evaluate(new Request());
        $this->assertSame(
            [TestPriorityPluginLow::class, TestPriorityPluginHigh::class],
            $callOrder
        );
    }
}
