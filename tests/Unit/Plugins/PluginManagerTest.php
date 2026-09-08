<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Tests\Plugins\TestFalsePlugin;
use Kanopi\Firewall\Tests\Plugins\TestObservablePlugin;
use Kanopi\Firewall\Tests\Plugins\TestThrowingPlugin;
use Kanopi\Firewall\Tests\Plugins\TestPluginWithMetadata;
use Kanopi\Firewall\Tests\Plugins\TestPriorityPluginHigh;
use Kanopi\Firewall\Tests\Plugins\TestPriorityPluginLow;
use Kanopi\Firewall\Tests\Plugins\TestTruePlugin;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
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

    /**
     * A plugin whose constructor throws must not fatal the request (#243).
     *
     * The registry caught the throw and yielded null, and evaluate() called
     * getName() on it -- `Call to a member function getName() on null`. An
     * Error rather than an Exception, so a host catching \Exception, and
     * FirewallMode::Exception with it, never saw it.
     */
    public function testAPluginThatCannotBeConstructedDoesNotFatal(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestThrowingPlugin::class],
        ]);

        $this->assertFalse($manager->evaluate(new Request()));
    }

    /**
     * The rules around a broken one still run.
     */
    public function testARuleAfterABrokenOneStillEvaluates(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestThrowingPlugin::class, 'weight' => -10],
            ['plugin' => TestTruePlugin::class, 'weight' => 0],
        ]);

        $this->assertInstanceOf(TestTruePlugin::class, $manager->evaluate(new Request()));
    }

    /**
     * A broken plugin is not counted among the live ones.
     */
    public function testABrokenPluginIsNotReturnedByGetPlugins(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestThrowingPlugin::class],
            ['plugin' => TestTruePlugin::class],
        ]);

        $plugins = $manager->getPlugins();

        $this->assertCount(1, $plugins, 'Only the plugin that constructed should be returned');
        $this->assertNotContains(null, $plugins);
    }

    /**
     * Construction is attempted once, not once per iteration.
     *
     * Retrying would re-run a constructor that throws on every request -- and for
     * a storage backend, reattempt a connection that is not coming back.
     */
    public function testABrokenPluginIsNotReconstructedOnEveryPass(): void
    {
        TestThrowingPlugin::$constructions = 0;

        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestThrowingPlugin::class],
        ]);

        $manager->evaluate(new Request());
        $manager->evaluate(new Request());
        $manager->getPlugins();

        $this->assertSame(1, TestThrowingPlugin::$constructions);
    }

    /**
     * The failure is logged where an operator will see it.
     *
     * A rule that cannot be constructed is a rule that is not running, and for a
     * block rule that is a fail-open with no other symptom.
     */
    public function testABrokenPluginIsLoggedAsInactive(): void
    {
        \Kanopi\Firewall\Logging\LoggingFactory::setLogger(
            \Kanopi\Firewall\Logging\LoggingFactory::create([
                ['class' => \Kanopi\Firewall\Tests\Logging\TestLogHandler::class],
            ])
        );

        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestThrowingPlugin::class],
        ]);
        $manager->evaluate(new Request());

        $handler = \Kanopi\Firewall\Logging\LoggingFactory::logger()->getHandlers()[0];
        $this->assertTrue(
            $handler->hasErrorContaining('could not be constructed'),
            'A rule that failed to construct should be an error, not a warning'
        );
    }

    /**
     * The failed rule is reportable, not only loggable.
     *
     * A log line is not something a status report can read. The name carries the
     * `Class:index` id the registry was given, so two rules of the same class are
     * distinguishable, and the error is the constructor's own message (#260).
     */
    public function testABrokenPluginIsReportedWithItsError(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestTruePlugin::class],
            ['plugin' => TestThrowingPlugin::class],
        ]);

        $manager->getPlugins();

        $this->assertSame(
            [['plugin' => TestThrowingPlugin::class . ':1', 'error' => 'cannot connect to storage']],
            $manager->getFailedPlugins()
        );
    }

    /**
     * Nothing is reported before anything is constructed.
     *
     * Rules are built lazily, so an empty report from a manager that has not
     * evaluated means "nothing attempted", not "nothing wrong".
     */
    public function testNoFailureIsReportedBeforeConstruction(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestThrowingPlugin::class],
        ]);

        $this->assertSame([], $manager->getFailedPlugins());
    }

    /**
     * A manager whose rules all build reports nothing.
     */
    public function testAWorkingManagerReportsNoFailures(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestTruePlugin::class],
        ]);

        $this->assertCount(1, $manager->getPlugins(), 'The rule really did build');
        $this->assertSame([], $manager->getFailedPlugins());
    }

    /**
     * A recognised mode is accepted silently; only an unrecognised one warns.
     */
    public function testAnExplicitEnforceModeIsAcceptedWithoutWarning(): void
    {
        \Kanopi\Firewall\Logging\LoggingFactory::setLogger(
            \Kanopi\Firewall\Logging\LoggingFactory::create([
                ['class' => \Kanopi\Firewall\Tests\Logging\TestLogHandler::class],
            ])
        );

        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => ['mode' => 'block']],
        ]);
        $manager->evaluate(new Request());

        $handler = \Kanopi\Firewall\Logging\LoggingFactory::logger()->getHandlers()[0];
        $this->assertFalse(
            $handler->hasWarningContaining('mode is not recognised'),
            '"block" is an explicit no-op, not a mistake'
        );
    }

    /**
     * A non-string mode is reported rather than silently ignored.
     */
    public function testANonStringModeWarns(): void
    {
        \Kanopi\Firewall\Logging\LoggingFactory::setLogger(
            \Kanopi\Firewall\Logging\LoggingFactory::create([
                ['class' => \Kanopi\Firewall\Tests\Logging\TestLogHandler::class],
            ])
        );

        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => ['mode' => ['log']]],
        ]);
        $manager->evaluate(new Request());

        $handler = \Kanopi\Firewall\Logging\LoggingFactory::logger()->getHandlers()[0];
        $this->assertTrue($handler->hasWarningContaining('mode is not recognised'));
    }

    /**
     * verify_suffixes that are not strings are discarded, leaving none -- which
     * is not verification, so the rule matches nothing.
     */
    public function testNonStringVerifySuffixesAreRejected(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => [
                'verify' => 'reverse-dns',
                'verify_suffixes' => [123, ['nested']],
            ]],
        ]);

        $this->assertFalse($manager->evaluate(new Request()));
    }

    /**
     * A request with no client address cannot be verified.
     */
    public function testAVerifiedRuleWithNoClientAddressDoesNotMatch(): void
    {
        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => [
                'verify' => 'reverse-dns',
                'verify_suffixes' => ['.googlebot.com'],
            ]],
        ]);

        $request = new Request();
        $request->server->remove('REMOTE_ADDR');

        $this->assertFalse($manager->evaluate($request));
    }

    /**
     * A verified rule matches when the verdict is already cached.
     *
     * Seeded through `verify_cache`, so the whole path -- the plugin building its
     * verifier, the verifier reading its pool -- runs without a DNS query.
     */
    public function testAVerifiedRuleMatchesOnACachedVerdict(): void
    {
        $pool = new \Symfony\Component\Cache\Adapter\ArrayAdapter();
        $key = 'rdns_' . hash('sha256', '66.249.66.1|.googlebot.com');
        $item = $pool->getItem($key);
        $item->set(true);
        $pool->save($item);

        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => [
                'verify' => 'reverse-dns',
                'verify_suffixes' => ['.googlebot.com'],
                'verify_cache' => $pool,
            ]],
        ]);

        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '66.249.66.1');

        $this->assertInstanceOf(TestObservablePlugin::class, $manager->evaluate($request));
    }

    /**
     * And does not match when the cached verdict is a refusal.
     */
    public function testAVerifiedRuleDoesNotMatchOnACachedRefusal(): void
    {
        $pool = new \Symfony\Component\Cache\Adapter\ArrayAdapter();
        $key = 'rdns_' . hash('sha256', '203.0.113.5|.googlebot.com');
        $item = $pool->getItem($key);
        $item->set(false);
        $pool->save($item);

        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => [
                'verify' => 'reverse-dns',
                'verify_suffixes' => ['.googlebot.com'],
                'verify_cache' => $pool,
            ]],
        ]);

        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $this->assertFalse($manager->evaluate($request));
    }

    /**
     * The verifier is built once per plugin, not once per request it handles.
     */
    public function testTheVerifierIsReusedAcrossRequests(): void
    {
        $pool = new \Symfony\Component\Cache\Adapter\ArrayAdapter();

        foreach (['66.249.66.1', '66.249.66.2'] as $ip) {
            $item = $pool->getItem('rdns_' . hash('sha256', $ip . '|.googlebot.com'));
            $item->set(true);
            $pool->save($item);
        }

        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => [
                'verify' => 'reverse-dns',
                'verify_suffixes' => ['.googlebot.com'],
                'verify_cache' => $pool,
            ]],
        ]);

        foreach (['66.249.66.1', '66.249.66.2'] as $ip) {
            $request = Request::create('/');
            $request->server->set('REMOTE_ADDR', $ip);
            $this->assertInstanceOf(TestObservablePlugin::class, $manager->evaluate($request));
        }
    }

    /**
     * With no pool configured, the plugin builds its own on the filesystem.
     *
     * Seeded through the same adapter the plugin constructs, so the default path
     * is exercised without a DNS query.
     */
    public function testTheDefaultVerificationCacheIsUsedWhenNonePassed(): void
    {
        $dir = sys_get_temp_dir() . '/kanopi-firewall-rdns';
        $pool = new \Symfony\Component\Cache\Adapter\FilesystemAdapter('kanopi_firewall_rdns', 3600, $dir);

        $key = 'rdns_' . hash('sha256', '66.249.66.7|.googlebot.com');
        $item = $pool->getItem($key);
        $item->set(true);
        $pool->save($item);

        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => [
                'verify' => 'reverse-dns',
                'verify_suffixes' => ['.googlebot.com'],
            ]],
        ]);

        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '66.249.66.7');

        $this->assertInstanceOf(
            TestObservablePlugin::class,
            $manager->evaluate($request),
            'The plugin should find the verdict in the pool it builds by default'
        );

        $pool->deleteItem($key);
    }

    /**
     * The TTL and threshold keys are read rather than ignored.
     */
    public function testVerificationTuningKeysAreAccepted(): void
    {
        $pool = new \Symfony\Component\Cache\Adapter\ArrayAdapter();
        $key = 'rdns_' . hash('sha256', '66.249.66.8|.googlebot.com');
        $item = $pool->getItem($key);
        $item->set(true);
        $pool->save($item);

        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => [
                'verify' => 'reverse-dns',
                'verify_suffixes' => ['.googlebot.com'],
                'verify_cache' => $pool,
                'verify_ttl' => 60,
                'verify_negative_ttl' => 120,
                'verify_slow_threshold_ms' => 10,
            ]],
        ]);

        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '66.249.66.8');

        $this->assertInstanceOf(TestObservablePlugin::class, $manager->evaluate($request));
    }

    /**
     * Non-numeric tuning values fall back to the documented defaults.
     */
    public function testNonNumericVerificationTuningFallsBack(): void
    {
        $pool = new \Symfony\Component\Cache\Adapter\ArrayAdapter();
        $key = 'rdns_' . hash('sha256', '66.249.66.9|.googlebot.com');
        $item = $pool->getItem($key);
        $item->set(true);
        $pool->save($item);

        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => [
                'verify' => 'reverse-dns',
                'verify_suffixes' => ['.googlebot.com'],
                'verify_cache' => $pool,
                'verify_ttl' => 'soon',
                'verify_negative_ttl' => ['later'],
                'verify_slow_threshold_ms' => 'slow',
            ]],
        ]);

        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '66.249.66.9');

        $this->assertInstanceOf(TestObservablePlugin::class, $manager->evaluate($request));
    }

    /**
     * KANOPI_FIREWALL_CACHE_DIR moves the verification cache.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testTheVerificationCacheHonoursTheConfiguredDirectory(): void
    {
        $dir = sys_get_temp_dir() . '/fw-rdns-configured-' . uniqid();
        mkdir($dir, 0700, true);
        define('KANOPI_FIREWALL_CACHE_DIR', $dir);

        $pool = new \Symfony\Component\Cache\Adapter\FilesystemAdapter('kanopi_firewall_rdns', 3600, $dir);
        $item = $pool->getItem('rdns_' . hash('sha256', '66.249.66.11|.googlebot.com'));
        $item->set(true);
        $pool->save($item);

        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => [
                'verify' => 'reverse-dns',
                'verify_suffixes' => ['.googlebot.com'],
            ]],
        ]);

        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '66.249.66.11');

        $this->assertInstanceOf(TestObservablePlugin::class, $manager->evaluate($request));
    }

    /**
     * A cache that cannot be built costs a lookup, not the rule.
     *
     * The directory is pointed at a path underneath an existing *file*, which
     * cannot be created, so the adapter's constructor throws.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testAnUnbuildableVerificationCacheIsSurvivable(): void
    {
        $blocker = tempnam(sys_get_temp_dir(), 'fw-rdns-blocker');
        define('KANOPI_FIREWALL_CACHE_DIR', $blocker . '/cannot-exist');

        \Kanopi\Firewall\Logging\LoggingFactory::setLogger(
            \Kanopi\Firewall\Logging\LoggingFactory::create([
                ['class' => \Kanopi\Firewall\Tests\Logging\TestLogHandler::class],
            ])
        );

        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => [
                'verify' => 'reverse-dns',
                'verify_suffixes' => ['.googlebot.com'],
            ]],
        ]);

        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '198.51.100.77');

        // No cache and no PTR for a documentation address: it fails closed
        // rather than fatalling on the missing pool.
        $this->assertFalse($manager->evaluate($request));

        @unlink($blocker);
    }
}
