<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Diagnostics\Doctor;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\IpAddress;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Kanopi\Firewall\Utility\TrustedProxies;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Trusted proxies from YAML, applied for the firewall's own reads only (#397).
 *
 * `Request::setTrustedProxies()` is process-wide static state, so every test here starts
 * and ends with it cleared -- a test that leaked it would make the next one pass or fail
 * for reasons of its own.
 */
final class TrustedProxiesTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        putenv('FIREWALL_BYPASS_CLI=1');
        Request::setTrustedProxies([], -1);
    }

    protected function tearDown(): void
    {
        Request::setTrustedProxies([], -1);

        parent::tearDown();
    }

    /**
     * A firewall that blocks one address, with the given `global:` settings.
     *
     * @param array<string, mixed> $global
     */
    private function firewall(array $global, string $blocked = '203.0.113.9'): Firewall
    {
        return Firewall::create([[
            'global' => $global + ['mode' => 'exception', 'behind_proxy' => true],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'logger' => [['class' => TestLogHandler::class]],
            'plugins' => [[
                'plugin' => IpAddress::class,
                'response' => 'block',
                'enable' => true,
                'config' => [$blocked],
            ]],
        ]]);
    }

    private function request(string $peer, ?string $forwardedFor = null): Request
    {
        $server = ['REMOTE_ADDR' => $peer];

        if ($forwardedFor !== null) {
            $server['HTTP_X_FORWARDED_FOR'] = $forwardedFor;
        }

        return Request::create('/', 'GET', [], [], [], $server);
    }

    private function isBlocked(Firewall $firewall, Request $request): bool
    {
        try {
            $firewall->evaluate($request);

            return false;
        } catch (FirewallBlockedException) {
            return true;
        }
    }

    private function log(): TestLogHandler
    {
        $handler = LoggingFactory::logger()->getHandlers()[0] ?? null;
        $this->assertInstanceOf(TestLogHandler::class, $handler);

        return $handler;
    }

    // -----------------------------------------------------------------------
    // The request path
    // -----------------------------------------------------------------------

    /**
     * The client behind a trusted proxy is who the rules see.
     */
    public function testTheForwardedClientIsSeenThroughATrustedProxy(): void
    {
        $firewall = $this->firewall(['trusted_proxies' => ['10.0.0.0/8']]);

        $this->assertTrue($this->isBlocked($firewall, $this->request('10.0.0.5', '203.0.113.9')));
    }

    /**
     * And without it, the proxy's own address is -- which is the bug this closes for a
     * site that could only configure YAML.
     */
    public function testWithoutTrustedProxiesTheForwardedHeaderIsIgnored(): void
    {
        $firewall = $this->firewall([]);

        $this->assertFalse($this->isBlocked($firewall, $this->request('10.0.0.5', '203.0.113.9')));
    }

    /**
     * Spoofing: a forged X-Forwarded-For from a peer that is not a trusted proxy is not
     * believed, so a blocked client cannot claim to be somebody else.
     */
    public function testAForgedHeaderFromAnUntrustedPeerIsIgnored(): void
    {
        $firewall = $this->firewall(['trusted_proxies' => ['10.0.0.0/8']], '198.51.100.1');

        $this->assertTrue($this->isBlocked($firewall, $this->request('198.51.100.1', '192.0.2.44')));
    }

    /**
     * The host's global configuration is what it was, after every evaluation -- including
     * one that left as an exception.
     */
    public function testTheHostsConfigurationIsRestoredAfterEvery(): void
    {
        $firewall = $this->firewall(['trusted_proxies' => ['10.0.0.0/8']]);

        $this->assertTrue($this->isBlocked($firewall, $this->request('10.0.0.5', '203.0.113.9')));
        $this->assertSame([], Request::getTrustedProxies(), 'Restored after a block');
        $this->assertSame(-1, Request::getTrustedHeaderSet());

        $this->assertFalse($this->isBlocked($firewall, $this->request('10.0.0.5', '198.51.100.7')));
        $this->assertSame([], Request::getTrustedProxies(), 'Restored after an allow');

        // What the host sees is untouched: to it, the proxy is still the client.
        $this->assertSame('10.0.0.5', $this->request('10.0.0.5', '203.0.113.9')->getClientIp());
    }

    /**
     * A host that configured its own proxies wins, and is told once that the YAML is
     * being ignored -- the host knows its infrastructure.
     */
    public function testTheHostsOwnProxiesWin(): void
    {
        Request::setTrustedProxies(['192.0.2.0/24'], Request::HEADER_X_FORWARDED_FOR);
        $firewall = $this->firewall(['trusted_proxies' => ['10.0.0.0/8']]);

        // Through the YAML proxy: not believed, because the host's are in force.
        $this->assertFalse($this->isBlocked($firewall, $this->request('10.0.0.5', '203.0.113.9')));
        // Through the host's proxy: believed.
        $this->assertTrue($this->isBlocked($firewall, $this->request('192.0.2.10', '203.0.113.9')));

        $this->assertSame(['192.0.2.0/24'], Request::getTrustedProxies(), 'The host\'s configuration is left alone');

        $warnings = array_filter(
            $this->log()->records,
            static fn ($record): bool => str_contains($record->message, 'global.trusted_proxies is ignored')
        );
        $this->assertCount(1, $warnings, 'Said once, not on every request');
    }

    /**
     * Two firewalls in one process, each seeing its own.
     */
    public function testTwoFirewallsEachSeeTheirOwn(): void
    {
        $first = $this->firewall(['trusted_proxies' => ['10.0.0.0/8']]);
        $second = $this->firewall(['trusted_proxies' => ['172.16.0.0/12']]);

        $this->assertTrue($this->isBlocked($first, $this->request('10.0.0.5', '203.0.113.9')));
        $this->assertFalse($this->isBlocked($second, $this->request('10.0.0.5', '203.0.113.9')));
        $this->assertTrue($this->isBlocked($second, $this->request('172.16.0.5', '203.0.113.9')));
    }

    /**
     * `REMOTE_ADDR` trusts the immediate peer, for a load balancer whose address is not
     * known in advance -- resolved from the request being evaluated, not from `$_SERVER`.
     */
    public function testRemoteAddrTrustsTheRequestsOwnPeer(): void
    {
        $firewall = $this->firewall(['trusted_proxies' => 'REMOTE_ADDR']);

        $this->assertTrue($this->isBlocked($firewall, $this->request('10.9.9.9', '203.0.113.9')));
    }

    /**
     * With no peer there is nothing for `REMOTE_ADDR` to name, so nothing is trusted. Checked
     * on the proxies themselves: a request with no address at all is a separate problem for
     * the rules that read one.
     */
    public function testRemoteAddrWithNoPeerTrustsNobody(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['HTTP_X_FORWARDED_FOR' => '203.0.113.9']);
        $request->server->remove('REMOTE_ADDR');

        $restore = TrustedProxies::fromGlobal(['trusted_proxies' => ['REMOTE_ADDR', '10.0.0.1']])?->apply($request);

        $this->assertSame(['10.0.0.1'], Request::getTrustedProxies());
        $this->assertIsCallable($restore);

        $restore();
        $this->assertSame([], Request::getTrustedProxies());
    }

    /**
     * Expanded here rather than left to Symfony, whose 6.4 line does not know the keyword
     * and would trust nothing -- found by CI on PHP 8.1, which resolves 6.4.
     */
    public function testPrivateSubnetsIsAccepted(): void
    {
        $firewall = $this->firewall(['trusted_proxies' => ['PRIVATE_SUBNETS']]);

        $this->assertTrue($this->isBlocked($firewall, $this->request('192.168.4.4', '203.0.113.9')));

        $restore = TrustedProxies::fromGlobal(['trusted_proxies' => ['PRIVATE_SUBNETS']])?->apply($this->request('192.168.4.4'));
        $this->assertNotContains('PRIVATE_SUBNETS', Request::getTrustedProxies(), 'The keyword itself never reaches Symfony');
        $this->assertContains('192.168.0.0/16', Request::getTrustedProxies());
        $this->assertIsCallable($restore);
        $restore();
    }

    /**
     * Either source satisfies `require_trusted_proxies`.
     */
    public function testRequireTrustedProxiesIsSatisfiedByYaml(): void
    {
        $firewall = $this->firewall(['trusted_proxies' => ['10.0.0.0/8'], 'require_trusted_proxies' => true]);

        $this->assertInstanceOf(Firewall::class, $firewall);
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    /**
     * @return array<string, array{0: mixed}>
     */
    public static function provideSettingsDeclaringNone(): array
    {
        return ['absent' => [[]], 'empty list' => [['trusted_proxies' => []]], 'empty string' => [['trusted_proxies' => '']]];
    }

    #[DataProvider('provideSettingsDeclaringNone')]
    public function testDeclaringNoneIsNull(array $global): void
    {
        $this->assertNull(TrustedProxies::fromGlobal($global));
    }

    public function testTheDefaultHeadersLeaveHostAlone(): void
    {
        $this->assertSame(
            '10.0.0.0/8, 2001:db8::/32, trusting x-forwarded-for, x-forwarded-proto, x-forwarded-port',
            TrustedProxies::fromGlobal(['trusted_proxies' => ['10.0.0.0/8', ' 2001:db8::/32 ']])?->describe()
        );
    }

    public function testHeadersCanBeNamed(): void
    {
        $this->assertSame(
            '10.0.0.1, trusting forwarded, x-forwarded-host',
            TrustedProxies::fromGlobal(['trusted_proxies' => '10.0.0.1', 'trusted_headers' => ['Forwarded', 'X-Forwarded-Host', 'forwarded']])?->describe()
        );
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideRefusedSettings(): array
    {
        return [
            'not an address' => [['trusted_proxies' => ['proxy.internal']], '"proxy.internal" is not an address'],
            'not a string' => [['trusted_proxies' => [42]], 'int is not an address or range'],
            'a malformed prefix' => [['trusted_proxies' => ['10.0.0.0/abc']], 'is not an address'],
            'an IPv4 prefix past /32' => [['trusted_proxies' => ['10.0.0.0/33']], 'longer than /32'],
            'an IPv6 prefix past /128' => [['trusted_proxies' => ['2001:db8::/129']], 'longer than /128'],
            'every IPv4 address' => [['trusted_proxies' => ['0.0.0.0/0']], 'trusts every client'],
            'every IPv6 address' => [['trusted_proxies' => ['::/0']], 'trusts every client'],
            'a header that is not one' => [['trusted_proxies' => ['10.0.0.1'], 'trusted_headers' => ['x-real-ip']], '"x-real-ip" is not a forwarding header'],
        ];
    }

    /**
     * Refused at startup: a range that trusts everyone is the spoofing hole with extra
     * steps, and a header silently not trusted is a quiet version of it.
     *
     * @param array<string, mixed> $global
     */
    #[DataProvider('provideRefusedSettings')]
    public function testARefusedSettingStopsTheFirewallStarting(array $global, string $message): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($message);

        $this->firewall($global);
    }

    // -----------------------------------------------------------------------
    // firewall-doctor
    // -----------------------------------------------------------------------

    /**
     * @param array<string, mixed> $global
     */
    private function trustedProxyFinding(array $global): Diagnosis
    {
        $findings = (new Doctor([[
            'global' => $global + ['mode' => 'block'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'plugins' => [],
        ]]))->run();

        foreach ($findings as $finding) {
            if (str_contains(strtolower($finding->title), 'trusted_proxies') || str_contains($finding->title, 'Trusted proxies')) {
                return $finding;
            }
        }

        $this->fail('No trusted-proxies finding');
    }

    /**
     * Declared in YAML, it can be verified from a terminal -- the one form of this check
     * that was always "could not be verified from the command line" before.
     */
    public function testTheDoctorReportsYamlProxiesFromTheCommandLine(): void
    {
        $finding = $this->trustedProxyFinding(['trusted_proxies' => ['10.0.0.0/8']]);

        $this->assertSame(Diagnosis::OK, $finding->status);
        $this->assertSame('Trusted proxies configured in YAML', $finding->title);
        $this->assertStringContainsString('10.0.0.0/8, trusting x-forwarded-for', (string) $finding->detail);
    }

    public function testTheDoctorReportsARefusedSetting(): void
    {
        $finding = $this->trustedProxyFinding(['trusted_proxies' => ['0.0.0.0/0']]);

        $this->assertSame(Diagnosis::ERROR, $finding->status);
        $this->assertStringContainsString('trusts every client', (string) $finding->detail);
    }
}
