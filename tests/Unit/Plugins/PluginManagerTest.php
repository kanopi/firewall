<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Tests\Plugins\TestFalsePlugin;
use Kanopi\Firewall\Tests\Plugins\TestObservablePlugin;
use Kanopi\Firewall\Tests\Plugins\TestPluginWithMetadata;
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

        $result = $manager->evaluate(new Request());

        $this->assertInstanceOf(TestTruePlugin::class, $result);
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

    /**
     * Test: createFromPluginsArray with valid plugin returns false when plugin returns false.
     */
    public function testCreateFromPluginsArrayValidPluginReturnsFalse(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            [
                'plugin' => TestFalsePlugin::class,
                'weight' => 5,
            ],
        ]);

        $this->assertFalse($manager->evaluate(new Request()));
    }

    /**
     * Test: createFromPluginsArray with missing plugin class is skipped.
     */
    public function testCreateFromPluginsArrayMissingClassSkipped(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            [
                'plugin' => 'Invalid\Missing\Plugin',
                'weight' => 0,
            ],
        ]);

        $this->assertFalse($manager->evaluate(new Request()));
    }

    /**
     * Test: createFromPluginsArray with non-PluginInterface class is skipped.
     */
    public function testCreateFromPluginsArrayNonPluginInterfaceSkipped(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            [
                'plugin' => \stdClass::class,
                'weight' => 0,
            ],
        ]);

        $this->assertFalse($manager->evaluate(new Request()));
    }

    /**
     * Test: createFromPluginsArray with plugin returning true.
     */
    public function testCreateFromPluginsArrayPluginReturnsTrue(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            [
                'plugin' => TestTruePlugin::class,
                'weight' => 0,
            ],
        ]);

        $result = $manager->evaluate(new Request());

        $this->assertInstanceOf(TestTruePlugin::class, $result);
    }

    /**
     * Test: createFromPluginsArray sorts by weight (lower first).
     */
    public function testCreateFromPluginsArraySortsByWeight(): void
    {
        $callOrder = [];

        $manager = PluginManager::createFromPluginsArray([
            [
                'plugin' => TestPriorityPluginHigh::class,
                'weight' => 10,
                'metadata' => ['order' => &$callOrder],
            ],
            [
                'plugin' => TestPriorityPluginLow::class,
                'weight' => 1,
                'metadata' => ['order' => &$callOrder],
            ],
        ]);

        $manager->evaluate(new Request());
        $this->assertSame(
            [TestPriorityPluginLow::class, TestPriorityPluginHigh::class],
            $callOrder
        );
    }

    /**
     * Test: createFromPluginsArray supports multiple instances of the same plugin.
     */
    public function testCreateFromPluginsArrayMultipleInstances(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            [
                'plugin' => TestFalsePlugin::class,
                'weight' => 0,
            ],
            [
                'plugin' => TestFalsePlugin::class,
                'weight' => 10,
            ],
        ]);

        $plugins = $manager->getPlugins();
        $this->assertCount(2, $plugins);
    }

    /**
     * Test: createFromPluginsArray with missing plugin key is skipped.
     */
    public function testCreateFromPluginsArrayMissingPluginKeySkipped(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            [
                'weight' => 0,
                'config' => ['something'],
            ],
        ]);

        $this->assertFalse($manager->evaluate(new Request()));
    }

    /**
     * Test: createFromPluginsArray with empty plugin key is skipped.
     */
    public function testCreateFromPluginsArrayEmptyPluginKeySkipped(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            [
                'plugin' => '',
                'weight' => 0,
            ],
        ]);

        $this->assertFalse($manager->evaluate(new Request()));
    }

    /**
     * Test: createFromPluginsArray defaults weight to 0 when not provided.
     */
    public function testCreateFromPluginsArrayDefaultWeight(): void
    {
        $callOrder = [];

        $manager = PluginManager::createFromPluginsArray([
            [
                'plugin' => TestPriorityPluginHigh::class,
                'weight' => 10,
                'metadata' => ['order' => &$callOrder],
            ],
            [
                'plugin' => TestPriorityPluginLow::class,
                // No weight specified, should default to 0
                'metadata' => ['order' => &$callOrder],
            ],
        ]);

        $manager->evaluate(new Request());
        // Low should come first since its default weight (0) < High's weight (10)
        $this->assertSame(
            [TestPriorityPluginLow::class, TestPriorityPluginHigh::class],
            $callOrder
        );
    }

    /**
     * Test: createFromPluginsArray passes the entry's metadata to the plugin
     * constructor. Regression for a coverage gap where metadata propagation
     * for the new plugins: array format was unverified end-to-end.
     */
    public function testCreateFromPluginsArrayPropagatesMetadataToPlugin(): void
    {
        TestPluginWithMetadata::$lastMetadata = [];
        TestPluginWithMetadata::$lastConfig = [];

        $manager = PluginManager::createFromPluginsArray([
            [
                'plugin' => TestPluginWithMetadata::class,
                'weight' => 0,
                'enable' => true,
                'metadata' => [
                    'db' => '/path/to/file.mmdb',
                    'nested' => ['key' => 'value'],
                ],
                'config' => ['rule-a', 'rule-b'],
            ],
        ]);

        // Iterating the manager forces lazy instantiation of the plugin.
        $manager->evaluate(new Request());

        $this->assertSame(
            ['db' => '/path/to/file.mmdb', 'nested' => ['key' => 'value']],
            TestPluginWithMetadata::$lastMetadata
        );
    }

    /**
     * Test: createFromPluginsArray passes the entry's config rules to the plugin
     * constructor. Companion to the metadata propagation test above.
     */
    public function testCreateFromPluginsArrayPropagatesConfigToPlugin(): void
    {
        TestPluginWithMetadata::$lastMetadata = [];
        TestPluginWithMetadata::$lastConfig = [];

        $manager = PluginManager::createFromPluginsArray([
            [
                'plugin' => TestPluginWithMetadata::class,
                'weight' => 0,
                'enable' => true,
                'config' => ['rule-a', 'rule-b', ['nested' => 'rule-c']],
            ],
        ]);

        $manager->evaluate(new Request());

        $this->assertSame(
            ['rule-a', 'rule-b', ['nested' => 'rule-c']],
            TestPluginWithMetadata::$lastConfig
        );
    }

    /**
     * Test: createFromPluginsArray defaults missing metadata and config to
     * empty arrays rather than failing or passing nulls.
     */
    public function testCreateFromPluginsArrayDefaultsMissingMetadataAndConfig(): void
    {
        TestPluginWithMetadata::$lastMetadata = ['stale'];
        TestPluginWithMetadata::$lastConfig = ['stale'];

        $manager = PluginManager::createFromPluginsArray([
            [
                'plugin' => TestPluginWithMetadata::class,
                'weight' => 0,
                'enable' => true,
                // No metadata, no config keys.
            ],
        ]);

        $manager->evaluate(new Request());

        $this->assertSame([], TestPluginWithMetadata::$lastMetadata);
        $this->assertSame([], TestPluginWithMetadata::$lastConfig);
    }

    /**
     * Test: createFromPluginsArray registers an entry that omits `enable`.
     *
     * The new format documents enable defaulting to true. PluginManager itself
     * registers every entry — the disabled filter lives in
     * PluginConfigNormalizer::partitionAndSort(), but a defensive default in
     * the manager is still worth pinning down so that a config that skips
     * `enable` doesn't silently drop the plugin if it ever bypasses the
     * normalizer (e.g., direct callers, future code paths).
     */
    public function testCreateFromPluginsArrayRegistersEntryWithoutEnableKey(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            [
                'plugin' => TestFalsePlugin::class,
                'weight' => 0,
                // No `enable` key — entry should still register.
            ],
        ]);

        $this->assertCount(1, $manager->getPlugins());
    }

    /**
     * A rule in observe mode matches, says so, and is not enforced (#201).
     */
    public function testObserveModeMatchIsNotEnforced(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => ['mode' => 'log']],
        ]);

        $this->assertFalse(
            $manager->evaluate(new Request()),
            'An observed match must be treated as no match by the evaluation loop'
        );
    }

    /**
     * The same rule without the key enforces, which is every existing config.
     */
    public function testWithoutModeTheRuleEnforces(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => []],
        ]);

        $this->assertInstanceOf(TestObservablePlugin::class, $manager->evaluate(new Request()));
    }

    /**
     * Observing one rule must not stop a later one enforcing.
     *
     * This is the whole point: the rest of the firewall keeps working while a
     * single rule is being watched.
     */
    public function testALaterRuleStillEnforcesWhenAnEarlierOneIsObserved(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'weight' => -10, 'metadata' => ['mode' => 'log']],
            ['plugin' => TestTruePlugin::class, 'weight' => 0],
        ]);

        $this->assertInstanceOf(TestTruePlugin::class, $manager->evaluate(new Request()));
    }

    /**
     * The observed match is logged where an operator will actually see it.
     *
     * `enforced` is a separate context key rather than a different message, so a
     * query counting matches can tell an observed one from an enforced one.
     */
    public function testObservedMatchIsLoggedAsUnenforced(): void
    {
        // The base test case installs a logger with no handlers, so give this
        // one somewhere to look.
        \Kanopi\Firewall\Logging\LoggingFactory::setLogger(
            \Kanopi\Firewall\Logging\LoggingFactory::create([
                ['class' => \Kanopi\Firewall\Tests\Logging\TestLogHandler::class],
            ])
        );

        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => ['mode' => 'log']],
        ]);

        $manager->evaluate(new Request());

        $handler = \Kanopi\Firewall\Logging\LoggingFactory::logger()->getHandlers()[0];
        $this->assertTrue(
            $handler->hasWarningContaining('observe mode'),
            'An observed match should be logged at warning level'
        );
    }

    /**
     * A plugin implementing PluginInterface directly is unaffected.
     *
     * Observe mode lives on a separate interface precisely so adding it cannot
     * make an existing custom plugin fatally incomplete.
     */
    public function testAPluginWithoutTheInterfaceIsUnaffectedByMode(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestTruePlugin::class, 'metadata' => ['mode' => 'log']],
        ]);

        $this->assertInstanceOf(
            TestTruePlugin::class,
            $manager->evaluate(new Request()),
            'A plugin that does not implement ObserveModeInterface still enforces'
        );
    }

    /**
     * A verify method that is not recognised turns the match off (#199).
     *
     * Not "match anyway": an operator who asked for verification and mistyped it
     * must not silently get an unverified allow rule.
     */
    public function testAnUnrecognisedVerifyMethodStopsTheMatch(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => ['verify' => 'reverse-lookup']],
        ]);

        $this->assertFalse($manager->evaluate(new Request()));
    }

    /**
     * Verification with no domain list is not verification.
     *
     * Any address with a PTR record would otherwise pass, which for an allow rule
     * is worse than no rule at all.
     */
    public function testVerifyWithNoSuffixesStopsTheMatch(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => ['verify' => 'reverse-dns']],
        ]);

        $this->assertFalse($manager->evaluate(new Request()));
    }

    /**
     * A rule declaring no verification is untouched, which is every existing config.
     */
    public function testWithoutVerifyTheMatchStands(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => []],
        ]);

        $this->assertInstanceOf(TestObservablePlugin::class, $manager->evaluate(new Request()));
    }

    /**
     * A plugin implementing PluginInterface directly is unaffected by the key.
     */
    public function testAPluginWithoutTheInterfaceIgnoresVerify(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestTruePlugin::class, 'metadata' => ['verify' => 'reverse-dns']],
        ]);

        $this->assertInstanceOf(TestTruePlugin::class, $manager->evaluate(new Request()));
    }
}
