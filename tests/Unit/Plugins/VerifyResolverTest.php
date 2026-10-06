<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Kanopi\Firewall\Tests\Plugins\TestObservablePlugin;
use Kanopi\Firewall\Tests\Unit\Utility\ReverseDns\Fixtures\ScriptedResolver;
use Kanopi\Firewall\Utility\ReverseDns\DnsOverHttpResolver;
use Kanopi\Firewall\Utility\ReverseDns\LookupResult;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsSettings;
use Kanopi\Firewall\Utility\ReverseDns\UnusableResolver;
use Kanopi\Firewall\Utility\ReverseDnsVerifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;

/**
 * A rule's verification uses the resolver `global.reverse_dns` chooses for it (#473).
 */
final class VerifyResolverTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        ReverseDnsSettings::reset();
        ScriptedResolver::reset();
    }

    protected function tearDown(): void
    {
        ReverseDnsSettings::reset();
        ScriptedResolver::reset();
        parent::tearDown();
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function plugin(array $metadata = []): TestObservablePlugin
    {
        return new TestObservablePlugin($metadata + [
            'verify' => 'reverse-dns',
            'verify_suffixes' => ['.googlebot.com'],
            // Its own pool, so no verdict survives from another test or run.
            'verify_cache' => new ArrayAdapter(),
        ], []);
    }

    private function verifier(TestObservablePlugin $plugin): ReverseDnsVerifier
    {
        $verifier = (new \ReflectionMethod($plugin, 'reverseDnsVerifier'))->invoke($plugin);
        $this->assertInstanceOf(ReverseDnsVerifier::class, $verifier);

        return $verifier;
    }

    private function property(ReverseDnsVerifier $reverseDnsVerifier, string $name): mixed
    {
        return (new \ReflectionProperty($reverseDnsVerifier, $name))->getValue($reverseDnsVerifier);
    }

    public function testWithNothingConfiguredTheVerifierMakesItsOwnLookups(): void
    {
        $verifier = $this->verifier($this->plugin());

        $this->assertNull($this->property($verifier, 'resolver'));
        $this->assertSame(250.0, $this->property($verifier, 'slowThresholdMs'));
    }

    public function testTheConfiguredProviderMakesTheLookups(): void
    {
        ReverseDnsSettings::configure(['reverse_dns' => [
            'provider' => 'platform',
            'providers' => ['platform' => ['resolver' => ScriptedResolver::class]],
        ]]);

        ScriptedResolver::$reverse['66.249.66.1'] = LookupResult::answer(['crawl.googlebot.com']);
        ScriptedResolver::$forward['crawl.googlebot.com A'] = LookupResult::answer(['66.249.66.1']);

        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '66.249.66.1']);

        $this->assertTrue($this->plugin()->passesIdentityVerification($request));
        $this->assertSame(['reverse 66.249.66.1', 'forward crawl.googlebot.com A'], ScriptedResolver::$asked);
    }

    public function testAProviderSetsTheBreakerThresholdUnlessTheRuleDoes(): void
    {
        ReverseDnsSettings::configure(['reverse_dns' => ['provider' => 'cloudflare', 'timeout_ms' => 400]]);

        $verifier = $this->verifier($this->plugin());
        $this->assertInstanceOf(DnsOverHttpResolver::class, $this->property($verifier, 'resolver'));
        $this->assertSame(850.0, $this->property($verifier, 'slowThresholdMs'));

        $this->assertSame(1000.0, $this->property($this->verifier($this->plugin(['verify_slow_threshold_ms' => 1000])), 'slowThresholdMs'));
    }

    public function testAResolverThatCannotBeBuiltVerifiesNobody(): void
    {
        LoggingFactory::setLogger(LoggingFactory::create([['class' => TestLogHandler::class]]));
        $handler = LoggingFactory::logger()->getHandlers()[0];
        $this->assertInstanceOf(TestLogHandler::class, $handler);

        // Never configured, so never validated: a rule built outside Firewall::create().
        $plugin = $this->plugin(['verify_provider' => 'nowhere']);

        $this->assertInstanceOf(UnusableResolver::class, $this->property($this->verifier($plugin), 'resolver'));
        $this->assertFalse($plugin->passesIdentityVerification(Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '66.249.66.1'])));
        $this->assertTrue($handler->hasErrorContaining('Reverse DNS resolver could not be built - the rule will not match'));
    }
}
