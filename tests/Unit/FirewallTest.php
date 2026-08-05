<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\StorageException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\IpAddress;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Storage\FileStorage;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Storage\StorageInterface;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\HttpFoundation\Request;

class FirewallTest extends AbstractTestCase
{
    private StorageInterface&MockObject $storage;
    private PluginManager&MockObject $blockManager;
    private PluginManager&MockObject $bypassManager;
    private PluginManager&MockObject $challengeManager;

    protected function setUp(): void {
        parent::setUp();
        $this->storage = $this->createMock(StorageInterface::class);
        $this->blockManager = $this->createMock(PluginManager::class);
        $this->bypassManager = $this->createMock(PluginManager::class);
        $this->challengeManager = $this->createMock(PluginManager::class);
    }

    /**
     * Creates a Firewall instance with protected constructor via reflection.
     */
    private function createFirewall(array $config = [], ?StorageInterface $storage = null): Firewall {
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $ref->newInstanceWithoutConstructor();
        $constructor = $ref->getConstructor();
        $constructor->setAccessible(true);
        $constructor->invoke(
            $firewall,
            $storage ?? $this->storage,
            $this->blockManager,
            $this->bypassManager,
            $this->challengeManager,
            $config
        );
        return $firewall;
    }

    /**
     * Ensure bypass plugin short-circuits evaluation and returns true.
     */
    public function testEvaluateBypassPluginAllows(): void
    {
        $request = Request::create('/');
        $request->attributes->set('x-request-id', 'abc123');
        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('TestPlugin');
        $this->bypassManager->method('evaluate')->willReturn($plugin);
        $firewall = $this->createFirewall(['mode' => 'exception']);
        $this->assertTrue($firewall->evaluate($request));
    }

    /**
     * Ensure blocked IP triggers sendBlockingResponse and stops evaluation.
     */
    public function testEvaluateBlockedIp(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '1.2.3.4']);
        $request->attributes->set('x-request-id', 'abc12e');

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn(['event_id' => 'mock-blocked']);

        $firewall = $this->createFirewall(['mode' => 'exception']);
        $this->expectException(FirewallBlockedException::class);
        $this->expectExceptionMessage('mock-blocked Request Banned');
        $this->expectExceptionCode(400);
        $firewall->evaluate($request);
    }

    /**
     * Ensure blocked IP triggers sendBlockingResponse and stops evaluation.
     */
    public function testEvaluateBlockedIpCustomStatusMessage(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '1.2.3.4']);
        $request->attributes->set('x-request-id', 'mock-blocked');

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn([]);

        $firewall = $this->createFirewall(['mode' => 'exception', 'banning_status_code' => 429, 'banning_message' => 'You are banned']);
        $this->expectException(FirewallBlockedException::class);
        $this->expectExceptionMessage('You are banned');
        $this->expectExceptionCode(429);
        $firewall->evaluate($request);
    }

    /**
     * Ensure blocking plugin can block and invoke sendBlockingResponse().
     */
    public function testEvaluateBlockingPluginBlocks(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '5.6.7.8']);
        $request->attributes->set('x-request-id', 'plugin-id');

        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('Blocker');
        $plugin->method('getExpirationTime')->willReturn(600);
        $plugin->method('getStatusCode')->willReturn(403);

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn(false);

        $this->blockManager->expects($this->once())->method('evaluate')->willReturn($plugin);

        $firewall = $this->createFirewall(['mode' => 'exception']);

        $this->expectException(FirewallBlockedException::class);
        $this->expectExceptionMessage('plugin-id Request Banned');
        $this->expectExceptionCode(403);
        $firewall->evaluate($request);
    }

    /**
     * Test Status Code when the value is 0.
     */
    public function testEvaluateBlockingPluginBlocksStatusCode(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '5.6.7.8']);
        $request->attributes->set('x-request-id', 'plugin-id');

        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('Blocker');
        $plugin->method('getExpirationTime')->willReturn(600);
        $plugin->method('getStatusCode')->willReturn(0);

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn(false);

        $this->blockManager->expects($this->once())->method('evaluate')->willReturn($plugin);

        $firewall = $this->createFirewall(['mode' => 'exception', 'banning_status_code' => 429, 'banning_message' => 'You are banned']);

        $this->expectException(FirewallBlockedException::class);
        $this->expectExceptionMessage('You are banned');
        $this->expectExceptionCode(429);
        $firewall->evaluate($request);
    }

    /**
     * Test Status Code when the value is 0.
     */
    public function testEvaluateBlockingPluginBlocksStatusCodeWithNoDefaults(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '5.6.7.8']);
        $request->attributes->set('x-request-id', 'plugin-id');

        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn('Blocker');
        $plugin->method('getExpirationTime')->willReturn(600);
        $plugin->method('getStatusCode')->willReturn(0);

        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn(false);

        $this->blockManager->expects($this->once())->method('evaluate')->willReturn($plugin);

        $firewall = $this->createFirewall(['mode' => 'exception']);

        $this->expectException(FirewallBlockedException::class);
        $this->expectExceptionMessage('plugin-id Request Banned');
        $this->expectExceptionCode(400);
        $firewall->evaluate($request);
    }

    /**
     * Ensure request not bypassed and not blocked continues to pass through.
     */
    public function testEvaluateContinuesIfNotBlocked(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '9.9.9.9']);
        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->storage->method('isBlocked')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn(false);
        $firewall = $this->createFirewall(['mode' => 'exception']);
        $this->assertTrue($firewall->evaluate($request));
    }

    /**
     * Ensure generated request ID is uppercase 32-character hash.
     */
    public function testGenerateIdReturnsValidHash(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '8.8.8.8']);
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('generateId');
        $method->setAccessible(true);
        $id = $method->invoke($firewall, $request);
        $this->assertMatchesRegularExpression('/^[A-F0-9]{32}$/', $id);
    }

    /**
     * Regression test for #60: two IDs generated back-to-back from the same
     * client IP must differ. Pre-fix the ID was `md5($clientIp . time())`,
     * so two calls from the same IP within the same second returned the
     * same value — and an attacker who knew the IP and approximate time
     * could brute-force IDs across a tiny key space.
     */
    public function testGenerateIdIsNotDerivableFromClientIpAndTime(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '8.8.8.8']);
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('generateId');
        $method->setAccessible(true);

        $first = $method->invoke($firewall, $request);
        $second = $method->invoke($firewall, $request);

        $this->assertNotSame($first, $second, 'Two IDs from the same IP must not match (predictable ID regression).');
        $this->assertNotSame(strtoupper(md5('8.8.8.8' . time())), $first, 'ID must not be derivable from md5(ip . time()).');
    }

    /**
     * Regression test for #60: 1000 IDs from the same IP should all be
     * distinct. A 128-bit CSPRNG output has birthday-collision odds at
     * ~1 in 2^64 for this sample size — effectively zero. Pre-fix this
     * would routinely collide whenever the loop completed inside one
     * wall-clock second.
     */
    public function testGenerateIdProducesDistinctValuesUnderLoad(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '8.8.8.8']);
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('generateId');
        $method->setAccessible(true);

        $ids = [];
        for ($i = 0; $i < 1000; $i++) {
            $ids[] = $method->invoke($firewall, $request);
        }

        $this->assertCount(1000, array_unique($ids));
    }

    /**
     * Test the Firewall::create method.
     */
    public function testStaticCreate(): void
    {
        $firewall = Firewall::create();
        $this->assertInstanceOf(Firewall::class, $firewall);
    }

    /**
     * Test the Firewall::evaluate creates Request.
     */
    public function testEvaluate(): void
    {
        $firewall = Firewall::create([], ['[global][mode]' => 'exception']);
        $response = $firewall->evaluate();
        $this->assertTrue($response);
    }

    /**
     * Test the Interpolate Template function with GET.
     */
    public function testInterpolateTemplateGet(): void {
        $request = Request::create('/', 'GET', ['abc' => '123'], [], [], [
            'REMOTE_ADDR' => '8.8.8.8',
            'HTTP_HOST' => 'localhost',
            'HTTP_PORT' => 80,
            'HTTP_ACCEPT' => 'text/html',
        ]);
        $request->attributes->set('x-request-id', 'ABC123');
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('interpolateTemplate');
        $method->setAccessible(true);

        $message = '{{request.id}} Request Banned';
        $result = $method->invoke($firewall, $message, $request);
        $this->assertEquals('ABC123 Request Banned', $result);

        $message = '{{request.scheme}} {{request.method}} {{request.host}} {{request.ip}} {{request.path}} {{request.query.abc}} {{request.header.accept}}';
        $result = $method->invoke($firewall, $message, $request);
        $this->assertEquals('http GET localhost 8.8.8.8 / 123 text/html', $result);
    }

    /**
     * Test the Interpolate Template function with POST.
     */
    public function testInterpolateTemplatePost(): void
    {
        $request = Request::create('/', 'POST', ['abc' => '123'], [
            'X-REQUEST-ID' => 'ABC123',
        ], [], [
            'REMOTE_ADDR' => '8.8.8.8',
            'HTTP_HOST' => 'localhost',
            'HTTP_PORT' => 80,
            'HTTP_ACCEPT' => 'text/html',
        ]);
        $request->attributes->set('x-request-id', 'ABC123');
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('interpolateTemplate');
        $method->setAccessible(true);

        $message = '{{request.scheme}} {{request.method}} {{request.host}} {{request.ip}} {{request.path}} {{request.post.abc}} {{request.header.accept}} {{request.cookie.X-REQUEST-ID}} {{notfound}} {{context-element}}';
        $result = $method->invoke($firewall, $message, $request, ['context-element' => 'context']);
        $this->assertEquals('http POST localhost 8.8.8.8 / 123 text/html ABC123 {{notfound}} context', $result);
    }

    /**
     * Attacker-controlled header values must be HTML-escaped in the
     * banning message body — otherwise an integrator who uses the
     * documented {{request.header.*}} placeholder hands out reflected XSS.
     */
    public function testInterpolateEscapesHtmlInHeader(): void
    {
        $request = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '8.8.8.8',
            'HTTP_USER_AGENT' => '<script>alert(1)</script>',
        ]);
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('interpolateTemplate');
        $method->setAccessible(true);

        $result = $method->invoke($firewall, 'Blocked: {{request.header.user-agent}}', $request);

        $this->assertStringNotContainsString('<script>', $result);
        $this->assertStringContainsString('&lt;script&gt;', $result);
        $this->assertStringContainsString('alert(1)', $result);
    }

    /**
     * Attacker-controlled query values must be HTML-escaped.
     */
    public function testInterpolateEscapesHtmlInQuery(): void
    {
        $request = Request::create('/', 'GET', ['q' => '"><img src=x onerror=alert(1)>'], [], [], [
            'REMOTE_ADDR' => '8.8.8.8',
        ]);
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('interpolateTemplate');
        $method->setAccessible(true);

        $result = $method->invoke($firewall, '{{request.query.q}}', $request);

        $this->assertStringNotContainsString('<img', $result);
        $this->assertStringContainsString('&lt;img', $result);
        $this->assertStringContainsString('&quot;', $result);
    }

    /**
     * Attacker-controlled POST values must be HTML-escaped.
     */
    public function testInterpolateEscapesHtmlInPost(): void
    {
        $request = Request::create('/', 'POST', ['name' => '<b>x</b>'], [], [], [
            'REMOTE_ADDR' => '8.8.8.8',
        ]);
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('interpolateTemplate');
        $method->setAccessible(true);

        $result = $method->invoke($firewall, '{{request.post.name}}', $request);

        $this->assertSame('&lt;b&gt;x&lt;/b&gt;', $result);
    }

    /**
     * Attacker-controlled cookie values must be HTML-escaped.
     */
    public function testInterpolateEscapesHtmlInCookie(): void
    {
        $request = Request::create('/', 'GET', [], ['session' => '<svg/onload=alert(1)>'], [], [
            'REMOTE_ADDR' => '8.8.8.8',
        ]);
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('interpolateTemplate');
        $method->setAccessible(true);

        $result = $method->invoke($firewall, '{{request.cookie.session}}', $request);

        $this->assertStringNotContainsString('<svg', $result);
        $this->assertStringContainsString('&lt;svg', $result);
    }

    /**
     * CR/LF in substituted values must be stripped so they cannot inject
     * additional response headers / body lines.
     */
    public function testInterpolateStripsCrlfFromSubstitutions(): void
    {
        $request = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '8.8.8.8',
            'HTTP_USER_AGENT' => "line1\r\nSet-Cookie: pwned=1\r\n\r\n<html>injected",
        ]);
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('interpolateTemplate');
        $method->setAccessible(true);

        $result = $method->invoke($firewall, '{{request.header.user-agent}}', $request);

        $this->assertStringNotContainsString("\r", $result);
        $this->assertStringNotContainsString("\n", $result);
    }

    /**
     * Arbitrary context values are also untrusted (callers may pass user
     * input) and must be escaped consistently with the request-derived
     * placeholders.
     */
    public function testInterpolateEscapesArbitraryContextValues(): void
    {
        $request = Request::create('/');
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall();
        $method = $ref->getMethod('interpolateTemplate');
        $method->setAccessible(true);

        $result = $method->invoke(
            $firewall,
            '{{user_input}}',
            $request,
            ['user_input' => '<script>alert(1)</script>']
        );

        $this->assertSame('&lt;script&gt;alert(1)&lt;/script&gt;', $result);
    }

    /**
     * Confirm that is blocked returns true.
     */
    public function testDetermineExpirationTime(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '1.1.1.1']);
        $config = [
            'blocking_escalation' => [
                [
                    'window' => 600,
                    'offense' => 0,
                ],
                [
                    'window' => 3600,
                    'offense' => 3,
                    'duration' => 300,
                ],
                [
                    'window' => 86400,
                    'offense' => 4,
                    'duration' => 0,
                ]
            ],
        ];

        $storage = new InMemoryStorage();

        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall($config, $storage);
        $method = $ref->getMethod('determineExpirationTime');
        $method->setAccessible(true);

        $storage->recordOffense($request->getClientIp());
        $result = $method->invoke($firewall, $request, 0);
        $this->assertEquals(0, $result);

        $storage->recordOffense($request->getClientIp());
        $result = $method->invoke($firewall, $request, 100);
        $this->assertEquals(100, $result);

        $storage->recordOffense($request->getClientIp());
        $result = $method->invoke($firewall, $request, 100);
        $this->assertEquals(300, $result);

        $storage->recordOffense($request->getClientIp());
        $result = $method->invoke($firewall, $request, 100);
        $this->assertEquals(0, $result);
    }

    /**
     * Confirm that is blocked returns true.
     */
    public function testDetermineExpirationTimeDefaults(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '1.1.1.1']);
        $config = [
            'blocking_escalation' => [
                [
                    'offense' => 0,
                    'duration' => 300
                ],
                [
                    'window' => 3600,
                    'offense' => 3,
                    'duration' => 300,
                ],
                [
                    'window' => 86400,
                    'offense' => 4,
                    'duration' => 0,
                ]
            ],
        ];

        $storage = new InMemoryStorage();

        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall($config, $storage);
        $method = $ref->getMethod('determineExpirationTime');
        $method->setAccessible(true);

        $storage->recordOffense($request->getClientIp());
        $result = $method->invoke($firewall, $request, 0);
        $this->assertEquals(0, $result);

        $storage->recordOffense($request->getClientIp());
        $result = $method->invoke($firewall, $request, 100);
        $this->assertEquals(300, $result);
    }

    /**
     * Test Returns true if successful.
     */
    public function testBlockFunction(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '1.1.1.1']);
        $storage = new InMemoryStorage();

        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $this->createFirewall([], $storage);
        $method = $ref->getMethod('block');
        $method->setAccessible(true);

        $plugin = new IpAddress();

        $result = $method->invoke($firewall, $request, $plugin);
        $this->assertTrue($result);
    }

    /**
     * Test Firewall::create with new plugins: array format.
     */
    public function testStaticCreateWithNewPluginsFormat(): void
    {
        $config = [
            'plugins' => [
                [
                    'plugin' => IpAddress::class,
                    'response' => 'allow',
                    'weight' => -200,
                    'enable' => true,
                    'config' => ['127.0.0.1'],
                ],
            ],
            'global' => [
                'mode' => 'exception',
            ],
        ];

        $firewall = Firewall::create([$config]);
        $this->assertInstanceOf(Firewall::class, $firewall);
    }

    /**
     * Test Firewall::create with mixed old and new format.
     */
    public function testStaticCreateWithMixedFormat(): void
    {
        $config = [
            'plugins' => [
                [
                    'plugin' => IpAddress::class,
                    'response' => 'allow',
                    'weight' => -300,
                    'enable' => true,
                    'config' => ['10.0.0.1'],
                ],
            ],
            'bypass' => [
                IpAddress::class => [
                    'priority' => -200,
                    'enable' => true,
                    'config' => ['127.0.0.1'],
                ],
            ],
            'block' => [
                IpAddress::class => [
                    'priority' => -100,
                    'enable' => true,
                    'config' => ['192.168.1.100'],
                ],
            ],
            'global' => [
                'mode' => 'exception',
            ],
        ];

        $firewall = Firewall::create([$config]);
        $this->assertInstanceOf(Firewall::class, $firewall);
    }

    /**
     * Test that a `response: block` entry actually blocks at runtime when no
     * `response: allow` entries match. The counterpart to
     * testBypassEvaluatedBeforeBlock, verifying that response: block entries
     * are routed to the blocking PluginManager (not the bypass manager) and
     * reach sendBlockingResponse().
     */
    public function testResponseBlockEntryBlocksAtRuntime(): void
    {
        $config = [
            'plugins' => [
                [
                    'plugin' => IpAddress::class,
                    'response' => 'allow',
                    'weight' => -100,
                    'enable' => true,
                    'config' => ['10.0.0.1'],  // does NOT match the request below
                ],
                [
                    'plugin' => IpAddress::class,
                    'response' => 'block',
                    'weight' => 0,
                    'enable' => true,
                    'config' => ['127.0.0.1'], // matches the request below
                ],
            ],
            'global' => [
                'mode' => 'exception',
            ],
        ];

        $firewall = Firewall::create([$config]);
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '127.0.0.1']);

        $this->expectException(FirewallBlockedException::class);
        $firewall->evaluate($request);
    }

    /**
     * Regression test for end-to-end routing in mixed (new + legacy) configs:
     * the normalizer must put `bypass:` entries into the bypass manager and
     * `block:` entries into the block manager, alongside any `plugins:` array
     * entries, with all weights respected.
     */
    public function testMixedFormatRoutesLegacyAndNewEntriesToCorrectManager(): void
    {
        $config = [
            // New-format allow entry for 10.0.0.1
            'plugins' => [
                [
                    'plugin' => IpAddress::class,
                    'response' => 'allow',
                    'weight' => -100,
                    'enable' => true,
                    'config' => ['10.0.0.1'],
                ],
            ],
            // Legacy bypass for 10.0.0.2
            'bypass' => [
                IpAddress::class => [
                    'priority' => -100,
                    'enable' => true,
                    'config' => ['10.0.0.2'],
                ],
            ],
            // Legacy block for 127.0.0.1
            'block' => [
                IpAddress::class => [
                    'priority' => 0,
                    'enable' => true,
                    'config' => ['127.0.0.1'],
                ],
            ],
            'global' => [
                'mode' => 'exception',
            ],
        ];

        $firewall = Firewall::create([$config]);

        // Request from a new-format allow IP: passes.
        $allowRequestNew = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.1']);
        $this->assertTrue($firewall->evaluate($allowRequestNew), 'New-format allow should pass.');

        // Request from a legacy bypass IP: passes.
        $allowRequestLegacy = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.2']);
        $this->assertTrue($firewall->evaluate($allowRequestLegacy), 'Legacy bypass should pass.');

        // Request from the legacy block IP: blocks.
        $blockRequest = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '127.0.0.1']);
        $this->expectException(FirewallBlockedException::class);
        $firewall->evaluate($blockRequest);
    }

    /**
     * Test that bypass (allow) plugins are evaluated before block plugins.
     */
    public function testBypassEvaluatedBeforeBlock(): void
    {
        // Configure to allow localhost but block everything
        $config = [
            'plugins' => [
                [
                    'plugin' => IpAddress::class,
                    'response' => 'allow',
                    'weight' => 0,
                    'enable' => true,
                    'config' => ['127.0.0.1'],
                ],
                [
                    'plugin' => IpAddress::class,
                    'response' => 'block',
                    'weight' => 0,
                    'enable' => true,
                    'config' => ['127.0.0.1'], // Same IP would be blocked if allow wasn't first
                ],
            ],
            'global' => [
                'mode' => 'exception',
            ],
        ];

        $firewall = Firewall::create([$config]);
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '127.0.0.1']);

        // Should pass because allow is evaluated first
        $this->assertTrue($firewall->evaluate($request));
    }

    /**
     * Helper: build a logger-config entry that routes records to a
     * captured TestLogHandler. The handler instance is returned so
     * assertions can inspect it after `Firewall::create()` completes —
     * `create()` itself rebuilds the static logger, so installing one
     * via setLogger() ahead of the call would be replaced.
     */
    private function captureLogger(): TestLogHandler
    {
        $handler = new TestLogHandler(\Monolog\Level::Debug);
        // LoggingFactory::create() accepts handler instances directly under
        // the `class` key, bypassing the string-class instantiation path.
        return $handler;
    }

    /**
     * Regression for #58: empty trusted-proxies setup produces a clear
     * warning. Pre-fix the library silently trusted Symfony defaults — if
     * those ever return to honouring X-Forwarded-For, attackers spoof
     * source IPs and bypass IP/CIDR/rate-limit checks.
     */
    public function testCreateWarnsWhenTrustedProxiesNotConfigured(): void
    {
        $previous = Request::getTrustedProxies();
        $previousHeaderSet = Request::getTrustedHeaderSet();
        Request::setTrustedProxies([], 0);

        try {
            $handler = $this->captureLogger();
            Firewall::create([
                ['logger' => [['class' => $handler]]],
            ]);

            $this->assertTrue(
                $handler->hasWarningContaining('getTrustedProxies() is empty'),
                'Expected trusted-proxies warning when none configured.'
            );
        } finally {
            Request::setTrustedProxies($previous, $previousHeaderSet);
        }
    }

    /**
     * Regression for #58: when trusted proxies are configured, no warning
     * fires.
     */
    public function testCreateDoesNotWarnWhenTrustedProxiesConfigured(): void
    {
        $previous = Request::getTrustedProxies();
        $previousHeaderSet = Request::getTrustedHeaderSet();
        Request::setTrustedProxies(['10.0.0.0/8'], Request::HEADER_X_FORWARDED_FOR);

        try {
            $handler = $this->captureLogger();
            Firewall::create([
                ['logger' => [['class' => $handler]]],
            ]);

            $this->assertFalse(
                $handler->hasWarningContaining('getTrustedProxies() is empty'),
                'Trusted proxies are configured — no warning should fire.'
            );
        } finally {
            Request::setTrustedProxies($previous, $previousHeaderSet);
        }
    }

    /**
     * Regression for #58: when `global.require_trusted_proxies: true` is
     * set and trusted proxies are empty, the firewall should refuse to
     * start instead of silently allowing spoofable IPs through.
     */
    public function testCreateThrowsWhenTrustedProxiesRequiredButMissing(): void
    {
        $previous = Request::getTrustedProxies();
        $previousHeaderSet = Request::getTrustedHeaderSet();
        Request::setTrustedProxies([], 0);

        try {
            $this->expectException(ConfigurationException::class);
            $this->expectExceptionMessage('getTrustedProxies() is empty');
            Firewall::create([
                ['global' => ['require_trusted_proxies' => true]],
            ]);
        } finally {
            Request::setTrustedProxies($previous, $previousHeaderSet);
        }
    }

    /**
     * Regression for #99: `global.behind_proxy: false` asserts the fact the
     * library cannot observe — that nothing sits in front of this deployment
     * — and silences the check entirely.
     *
     * Before this existed there was no such setting. `create()` runs per
     * request, so a site with no proxy logged an unsilenceable warning on
     * 100% of requests, and the only escape was passing
     * `Request::setTrustedProxies()` a value that was not true.
     */
    public function testCreateIsSilentWhenBehindProxyAssertedFalse(): void
    {
        $previous = Request::getTrustedProxies();
        $previousHeaderSet = Request::getTrustedHeaderSet();
        Request::setTrustedProxies([], 0);

        try {
            $handler = $this->captureLogger();
            Firewall::create([
                [
                    'logger' => [['class' => $handler]],
                    'global' => ['behind_proxy' => false],
                ],
            ]);

            $this->assertFalse(
                $handler->hasWarningContaining('getTrustedProxies() is empty'),
                'behind_proxy: false must silence the trusted-proxies warning.'
            );
            $this->assertFalse(
                $handler->hasErrorContaining('getTrustedProxies() is empty'),
                'behind_proxy: false must not downgrade to an error either.'
            );
        } finally {
            Request::setTrustedProxies($previous, $previousHeaderSet);
        }
    }

    /**
     * Regression for #99: an explicit "there is no proxy" assertion wins over
     * `require_trusted_proxies: true`.
     *
     * Throwing anyway would leave an operator who has told the truth about
     * their deployment with no way to start the firewall at all.
     */
    public function testBehindProxyFalseOverridesRequireTrustedProxies(): void
    {
        $previous = Request::getTrustedProxies();
        $previousHeaderSet = Request::getTrustedHeaderSet();
        Request::setTrustedProxies([], 0);

        try {
            $firewall = Firewall::create([
                [
                    'global' => [
                        'behind_proxy' => false,
                        'require_trusted_proxies' => true,
                    ],
                ],
            ]);

            $this->assertInstanceOf(
                Firewall::class,
                $firewall,
                'behind_proxy: false should make require_trusted_proxies moot, not fatal.'
            );
        } finally {
            Request::setTrustedProxies($previous, $previousHeaderSet);
        }
    }

    /**
     * Regression for #99: asserting `behind_proxy: true` without wiring
     * `Request::setTrustedProxies()` is a definite misconfiguration rather
     * than an open question, so it is logged at `error` — but it still does
     * not throw unless `require_trusted_proxies` says so.
     */
    public function testCreateLogsErrorWhenBehindProxyAssertedButUnwired(): void
    {
        $previous = Request::getTrustedProxies();
        $previousHeaderSet = Request::getTrustedHeaderSet();
        Request::setTrustedProxies([], 0);

        try {
            $handler = $this->captureLogger();
            Firewall::create([
                [
                    'logger' => [['class' => $handler]],
                    'global' => ['behind_proxy' => true],
                ],
            ]);

            $this->assertTrue(
                $handler->hasErrorContaining('global.behind_proxy is true'),
                'An asserted-but-unwired proxy should be reported at error level.'
            );
        } finally {
            Request::setTrustedProxies($previous, $previousHeaderSet);
        }
    }

    /**
     * Regression for #99: `behind_proxy: true` combined with
     * `require_trusted_proxies: true` still refuses to start.
     */
    public function testBehindProxyTrueStillThrowsWhenRequired(): void
    {
        $previous = Request::getTrustedProxies();
        $previousHeaderSet = Request::getTrustedHeaderSet();
        Request::setTrustedProxies([], 0);

        try {
            $this->expectException(ConfigurationException::class);
            $this->expectExceptionMessage('global.behind_proxy is true');
            Firewall::create([
                [
                    'global' => [
                        'behind_proxy' => true,
                        'require_trusted_proxies' => true,
                    ],
                ],
            ]);
        } finally {
            Request::setTrustedProxies($previous, $previousHeaderSet);
        }
    }

    /**
     * Regression for #99: an unparseable `behind_proxy` must fail safe.
     *
     * Silencing a security warning is the dangerous direction, so a value
     * that is neither truthy nor falsy is treated as "posture unknown" and
     * still warns rather than being read as `false`.
     *
     */
    #[DataProvider('provideUnparseableBehindProxyValues')]
    public function testUnparseableBehindProxyStillWarns(mixed $value): void
    {
        $previous = Request::getTrustedProxies();
        $previousHeaderSet = Request::getTrustedHeaderSet();
        Request::setTrustedProxies([], 0);

        try {
            $handler = $this->captureLogger();
            Firewall::create([
                [
                    'logger' => [['class' => $handler]],
                    'global' => ['behind_proxy' => $value],
                ],
            ]);

            $this->assertTrue(
                $handler->hasWarningContaining('getTrustedProxies() is empty'),
                'An unparseable behind_proxy must not be read as a false assertion.'
            );
        } finally {
            Request::setTrustedProxies($previous, $previousHeaderSet);
        }
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function provideUnparseableBehindProxyValues(): array
    {
        return [
            'empty string' => [''],
            'arbitrary string' => ['maybe'],
            'array' => [['10.0.0.0/8']],
        ];
    }

    /**
     * Regression for #99: YAML-ish string booleans are honoured, so a value
     * arriving from an `%env()%` token or a quoted YAML scalar behaves the
     * same as a real boolean.
     *
     */
    #[DataProvider('provideFalsyBehindProxyStrings')]
    public function testStringFalsyBehindProxyIsHonoured(string $value): void
    {
        $previous = Request::getTrustedProxies();
        $previousHeaderSet = Request::getTrustedHeaderSet();
        Request::setTrustedProxies([], 0);

        try {
            $handler = $this->captureLogger();
            Firewall::create([
                [
                    'logger' => [['class' => $handler]],
                    'global' => ['behind_proxy' => $value],
                ],
            ]);

            $this->assertFalse(
                $handler->hasWarningContaining('getTrustedProxies() is empty'),
                sprintf('behind_proxy: "%s" should read as a false assertion.', $value)
            );
        } finally {
            Request::setTrustedProxies($previous, $previousHeaderSet);
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function provideFalsyBehindProxyStrings(): array
    {
        return [
            'false' => ['false'],
            'zero' => ['0'],
            'no' => ['no'],
            'off' => ['off'],
        ];
    }

    /**
     * Test plugins are sorted by weight within their response group.
     */
    public function testPluginsSortedByWeightWithinGroup(): void
    {
        // Plugin with higher weight should be evaluated after plugin with lower weight
        $config = [
            'plugins' => [
                [
                    'plugin' => IpAddress::class,
                    'response' => 'block',
                    'weight' => 100,
                    'enable' => true,
                    'config' => ['1.2.3.4'],
                ],
                [
                    'plugin' => IpAddress::class,
                    'response' => 'block',
                    'weight' => -100,
                    'enable' => true,
                    'config' => ['5.6.7.8'],
                ],
            ],
            'global' => [
                'mode' => 'exception',
            ],
        ];

        $firewall = Firewall::create([$config]);
        $this->assertInstanceOf(Firewall::class, $firewall);
    }

    /**
     * Regression for #79: `create()` used to advertise a
     * FirewallBlockedException for unloadable config inputs. Nothing is
     * raised — a string that isn't a readable file, and an argument that is
     * neither string, array, nor null, are both skipped.
     */
    public function testCreateSkipsUnloadableConfigInputsWithoutThrowing(): void
    {
        $firewall = Firewall::create([
            sys_get_temp_dir() . '/fw79-does-not-exist.yml',
            42,
            null,
        ]);

        $this->assertInstanceOf(Firewall::class, $firewall);
    }

    /**
     * Regression for #79: `StorageFactory::create()` runs inline inside
     * `create()` and is not wrapped, so an unusable storage file surfaces
     * as a StorageException out of `create()`.
     */
    public function testCreateThrowsStorageExceptionForUnusableStorageFile(): void
    {
        // The parent directory does not exist, so touch() fails regardless
        // of the uid the suite runs as.
        $unusable = sys_get_temp_dir() . '/fw79-missing-dir/storage_data.json';

        $this->expectException(StorageException::class);
        $this->expectExceptionMessage('Unable to create file');
        Firewall::create([
            [
                'storage' => [
                    'type' => FileStorage::class,
                    'config' => ['storage_file' => $unusable],
                ],
            ],
        ]);
    }

    /**
     * Regression for #79: a challenge plugin without `challenge.secret`
     * fails at startup with a ConfigurationException — one of the two
     * exceptions `create()` now documents.
     */
    public function testCreateThrowsConfigurationExceptionForChallengeWithoutSecret(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('`challenge.secret`');
        Firewall::create([
            [
                'plugins' => [
                    [
                        'plugin' => IpAddress::class,
                        'response' => 'challenge',
                        'enable' => true,
                        'config' => ['1.2.3.4'],
                    ],
                ],
            ],
        ]);
    }

    /**
     * Regression for #78: a config file that never loaded produced a
     * firewall with no plugins, no exception, and nothing in the log. The
     * default is still lenient, but the failure is now reported at `error`.
     */
    public function testCreateLogsErrorWhenConfigInputFailsToLoad(): void
    {
        $handler = $this->captureLogger();
        $missing = sys_get_temp_dir() . '/fw78-does-not-exist-' . uniqid() . '.yml';

        $firewall = Firewall::create([
            $missing,
            ['logger' => [['class' => $handler]]],
        ]);

        $this->assertInstanceOf(Firewall::class, $firewall);
        $this->assertTrue(
            $handler->hasErrorContaining('config file failed to load'),
            'Expected an error log naming the config file that did not load.'
        );
    }

    /**
     * Regression for #78: a load that succeeds says nothing.
     */
    public function testCreateDoesNotLogConfigErrorWhenEveryInputLoads(): void
    {
        $handler = $this->captureLogger();

        Firewall::create([
            ['logger' => [['class' => $handler]]],
        ]);

        $this->assertFalse(
            $handler->hasErrorContaining('config file failed to load'),
            'Nothing failed to load — no config error should be reported.'
        );
    }

    /**
     * Regression for #78: `global.require_config: true` turns a silent
     * fail-open into a startup failure, so a deploy that renames or fails
     * to ship a config file fails the deploy instead.
     */
    public function testCreateThrowsWhenRequireConfigAndInputFailsToLoad(): void
    {
        $missing = sys_get_temp_dir() . '/fw78-does-not-exist-' . uniqid() . '.yml';

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('global.require_config is enabled');
        Firewall::create([
            $missing,
            ['global' => ['require_config' => true]],
        ]);
    }

    /**
     * Regression for #78: the flag is reachable through the override
     * syntax too, which is the only route left when the config file that
     * would have carried it is the one that failed to load.
     */
    public function testCreateThrowsWhenRequireConfigSetViaOverride(): void
    {
        $missing = sys_get_temp_dir() . '/fw78-does-not-exist-' . uniqid() . '.yml';

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($missing);
        Firewall::create([$missing], ['[global][require_config]' => true]);
    }

    /**
     * Regression for #78: strict mode only fires on an actual failure — a
     * complete load starts normally.
     */
    public function testCreateStartsWithRequireConfigWhenEveryInputLoads(): void
    {
        $firewall = Firewall::create([
            ['global' => ['require_config' => true], 'plugins' => []],
        ]);

        $this->assertInstanceOf(Firewall::class, $firewall);
    }

    /**
     * Regression for #78: `require_config: false` is honoured even though
     * `create()` runs the `global` section through `array_filter()`, which
     * strips the value before the posture check would otherwise see it.
     */
    public function testCreateRespectsExplicitRequireConfigFalse(): void
    {
        $missing = sys_get_temp_dir() . '/fw78-does-not-exist-' . uniqid() . '.yml';

        $firewall = Firewall::create([
            $missing,
            ['global' => ['require_config' => false]],
        ]);

        $this->assertInstanceOf(Firewall::class, $firewall);
    }

    /**
     * Regression for #78: when the only config file is the one that failed,
     * its YAML cannot carry the flag — the constant can.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testCreateHonoursRequireConfigConstant(): void
    {
        define('KANOPI_FIREWALL_REQUIRE_CONFIG', true);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('global.require_config is enabled');
        Firewall::create([sys_get_temp_dir() . '/fw78-constant-missing.yml']);
    }

    /**
     * Redirect targets that must not survive sanitisation.
     *
     * This is the open-redirect guard on the challenge flow. `redirect_to`
     * comes off the interstitial's POST, so an attacker picks it — and the
     * value is handed to `window.location.href` after a successful solve. A
     * protocol-relative `//evil.test` is the case worth naming: it looks like
     * a path, passes a naive "starts with /" check, and navigates off-site.
     *
     * @return array<string, array{0: string}>
     */
    public static function hostileRedirectTargetProvider(): array
    {
        return [
            'empty' => [''],
            'no leading slash' => ['wp-admin'],
            'absolute url' => ['https://evil.test/'],
            'scheme relative' => ['//evil.test/'],
            'scheme relative with path' => ['//evil.test/steal'],
            'backslash escape' => ['/\\evil.test'],
            'javascript scheme' => ['javascript:alert(1)'],
            'data scheme' => ['data:text/html,<script>alert(1)</script>'],
        ];
    }

    #[DataProvider('hostileRedirectTargetProvider')]
    public function testSanitizeRedirectRefusesOffSiteTargets(string $target): void
    {
        $method = new \ReflectionMethod(Firewall::class, 'sanitizeRedirect');

        $this->assertSame(
            '/',
            $method->invoke($this->minimalFirewall(), $target),
            sprintf('"%s" must not be used as a redirect target', $target)
        );
    }

    /**
     * Same-origin paths are passed through unchanged.
     *
     * The guard has to be narrow enough to still work: sending every solver
     * back to `/` instead of the page they asked for would make the challenge
     * flow useless.
     *
     * @return array<string, array{0: string}>
     */
    public static function safeRedirectTargetProvider(): array
    {
        return [
            'root' => ['/'],
            'path' => ['/wp-admin/'],
            'path with query' => ['/search?q=hello'],
            'path with fragment' => ['/page#section'],
            'single slash then text' => ['/evil.test'],
        ];
    }

    #[DataProvider('safeRedirectTargetProvider')]
    public function testSanitizeRedirectKeepsSameOriginPaths(string $target): void
    {
        $method = new \ReflectionMethod(Firewall::class, 'sanitizeRedirect');

        $this->assertSame($target, $method->invoke($this->minimalFirewall(), $target));
    }

    /**
     * A Firewall with no plugins, for exercising its protected helpers.
     */
    private function minimalFirewall(): Firewall
    {
        $ref = new \ReflectionClass(Firewall::class);
        $firewall = $ref->newInstanceWithoutConstructor();
        $constructor = $ref->getConstructor();
        $constructor->setAccessible(true);
        $constructor->invoke(
            $firewall,
            new InMemoryStorage(),
            PluginManager::createFromPluginsArray([]),
            PluginManager::createFromPluginsArray([]),
            PluginManager::createFromPluginsArray([]),
            ['mode' => 'exception']
        );

        return $firewall;
    }
}