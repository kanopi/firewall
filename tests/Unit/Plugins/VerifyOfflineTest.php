<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Diagnostics\Doctor;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\AbstractPluginBase;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Kanopi\Firewall\Tests\Plugins\TestObservablePlugin;
use Kanopi\Firewall\Utility\ReverseDnsVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;

/**
 * Reverse-DNS verification has its own offline switch (#391).
 *
 * `KANOPI_FIREWALL_SOURCES_OFFLINE` keeps rule-list fetches off the request path, and it
 * also switched verification off, with no way back and no warning. On a host that sets it
 * -- `drupal/basic_firewall` does by default -- a verified crawler allow rule matched
 * nobody, a genuine crawler included.
 *
 * A constant cannot be undefined once defined, so every test that needs it runs in its own
 * process.
 */
final class VerifyOfflineTest extends TestCase
{
    private function log(): TestLogHandler
    {
        LoggingFactory::setLogger(LoggingFactory::create([['class' => TestLogHandler::class]]));
        $handler = LoggingFactory::logger()->getHandlers()[0];
        $this->assertInstanceOf(TestLogHandler::class, $handler);

        return $handler;
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function plugin(array $metadata): TestObservablePlugin
    {
        return new TestObservablePlugin($metadata + ['verify' => 'reverse-dns', 'verify_suffixes' => ['.googlebot.com']], []);
    }

    /**
     * Whether the verifier this plugin builds is offline.
     */
    private function verifierIsOffline(TestObservablePlugin $plugin): bool
    {
        $verifier = (new \ReflectionMethod($plugin, 'reverseDnsVerifier'))->invoke($plugin);
        $this->assertInstanceOf(ReverseDnsVerifier::class, $verifier);

        return (bool) (new \ReflectionProperty($verifier, 'offline'))->getValue($verifier);
    }

    /**
     * @return array<string, array{0: mixed, 1: bool}>
     */
    public static function provideVerifyOfflineValues(): array
    {
        return [
            'true' => [true, true],
            'false' => [false, false],
            'a YAML string' => ['false', false],
            'yes' => ['yes', true],
            'one' => [1, true],
        ];
    }

    /**
     * The key wins when it is set, in any form YAML or an environment variable produces.
     */
    #[DataProvider('provideVerifyOfflineValues')]
    public function testTheKeyDecidesWhenItIsSet(mixed $value, bool $offline): void
    {
        $this->assertSame(
            ['offline' => $offline, 'source' => 'metadata'],
            AbstractPluginBase::verificationOffline(['verify_offline' => $value])
        );
    }

    /**
     * Not a boolean at all, and it is not guessed at: the default applies.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testAnUnreadableValueIsIgnored(): void
    {
        $this->assertSame(
            ['offline' => false, 'source' => 'default'],
            AbstractPluginBase::verificationOffline(['verify_offline' => 'maybe'])
        );
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testWithNeitherSetVerificationIsOnline(): void
    {
        $this->assertSame(['offline' => false, 'source' => 'default'], AbstractPluginBase::verificationOffline([]));
        $this->assertFalse($this->verifierIsOffline($this->plugin([])));
    }

    /**
     * Unchanged on upgrade: with the constant set and nothing else said, verification is
     * off exactly as before.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testTheConstantStillSwitchesItOffByDefault(): void
    {
        define('KANOPI_FIREWALL_SOURCES_OFFLINE', true);

        $this->assertSame(['offline' => true, 'source' => 'constant'], AbstractPluginBase::verificationOffline([]));
        $this->assertTrue($this->verifierIsOffline($this->plugin([])));
    }

    /**
     * The point of #391: verification on, rule sources still offline.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testVerifyOfflineFalseVerifiesWhileSourcesStayOffline(): void
    {
        define('KANOPI_FIREWALL_SOURCES_OFFLINE', true);
        $log = $this->log();

        $plugin = $this->plugin(['verify_offline' => false]);

        $this->assertFalse($this->verifierIsOffline($plugin));
        $this->assertFalse($log->hasWarningContaining('switched off by KANOPI_FIREWALL_SOURCES_OFFLINE'));
    }

    /**
     * Switched off by another feature's switch, and saying so -- a `debug` line per
     * request used to be the only trace.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testSwitchedOffByTheConstantIsAWarning(): void
    {
        define('KANOPI_FIREWALL_SOURCES_OFFLINE', true);
        $log = $this->log();

        $this->plugin([]);

        $this->assertTrue($log->hasWarningContaining('switched off by KANOPI_FIREWALL_SOURCES_OFFLINE'));
    }

    /**
     * Chosen deliberately, and not nagged about on every request.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testSwitchedOffDeliberatelyIsNotAWarning(): void
    {
        define('KANOPI_FIREWALL_SOURCES_OFFLINE', true);
        $log = $this->log();

        $plugin = $this->plugin(['verify_offline' => true]);

        $this->assertTrue($this->verifierIsOffline($plugin));
        $this->assertFalse($log->hasWarningContaining('switched off by KANOPI_FIREWALL_SOURCES_OFFLINE'));
    }

    /**
     * A rule that does not verify has nothing to warn about.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testARuleThatDoesNotVerifyIsNotWarnedAbout(): void
    {
        define('KANOPI_FIREWALL_SOURCES_OFFLINE', true);
        $log = $this->log();

        new TestObservablePlugin([], []);

        $this->assertFalse($log->hasWarningContaining('switched off by KANOPI_FIREWALL_SOURCES_OFFLINE'));
    }

    /**
     * Offline, a verdict another node wrote to a shared `verify_cache` is still honoured
     * -- which is why the warning says "nobody new" rather than "nobody".
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testOfflineACachedVerdictIsStillHonoured(): void
    {
        define('KANOPI_FIREWALL_SOURCES_OFFLINE', true);

        $pool = new ArrayAdapter();
        $item = $pool->getItem('rdns_' . hash('sha256', '66.249.66.1|.googlebot.com'));
        $item->set(true);
        $pool->save($item);

        $manager = PluginManager::createFromPluginsArray([
            ['plugin' => TestObservablePlugin::class, 'metadata' => [
                'verify' => 'reverse-dns',
                'verify_suffixes' => ['.googlebot.com'],
                'verify_cache' => $pool,
            ]],
        ]);

        $known = Request::create('/');
        $known->server->set('REMOTE_ADDR', '66.249.66.1');
        $unknown = Request::create('/');
        $unknown->server->set('REMOTE_ADDR', '66.249.66.2');

        $this->assertInstanceOf(TestObservablePlugin::class, $manager->evaluate($known));
        $this->assertFalse($manager->evaluate($unknown), 'Nobody new is verified offline');
    }

    // -----------------------------------------------------------------------
    // firewall-doctor
    // -----------------------------------------------------------------------

    /**
     * @param array<string, mixed> $metadata
     *
     * @return array<int, Diagnosis>
     */
    private function doctorWarnings(array $metadata, ?string $name = null): array
    {
        $dir = sys_get_temp_dir() . '/fw-verify-offline-' . uniqid();
        mkdir($dir, 0700, true);

        $findings = (new Doctor([[
            'global' => ['mode' => 'block'],
            'storage' => [
                'type' => 'Kanopi\\Firewall\\Storage\\FileStorage',
                'config' => ['storage_file' => $dir . '/blocked.data'],
            ],
            'plugins' => [[
                'plugin' => TestObservablePlugin::class,
                'response' => 'bypass',
                'enable' => true,
                'metadata' => $metadata + ($name === null ? [] : ['name' => $name]) + [
                    'verify' => 'reverse-dns',
                    'verify_suffixes' => ['.googlebot.com'],
                ],
                'config' => [],
            ]],
        ]]))->run();

        return array_values(array_filter(
            $findings,
            static fn (Diagnosis $d): bool => str_contains($d->title, 'verification is switched off')
        ));
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testTheDoctorNamesARuleSwitchedOffByTheConstant(): void
    {
        define('KANOPI_FIREWALL_SOURCES_OFFLINE', true);

        $named = $this->doctorWarnings([], 'verified-googlebot');
        $this->assertCount(1, $named);
        $this->assertSame(Diagnosis::WARNING, $named[0]->status);
        $this->assertStringContainsString('Rule verified-googlebot', $named[0]->title);

        $unnamed = $this->doctorWarnings([]);
        $this->assertStringContainsString('Rule TestObservablePlugin', $unnamed[0]->title);
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testTheDoctorIsQuietWhenTheRuleHasDecided(): void
    {
        define('KANOPI_FIREWALL_SOURCES_OFFLINE', true);

        $this->assertSame([], $this->doctorWarnings(['verify_offline' => false]));
        $this->assertSame([], $this->doctorWarnings(['verify_offline' => true]));
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testTheDoctorIsQuietWithoutTheConstant(): void
    {
        $this->assertSame([], $this->doctorWarnings([]));
    }
}
