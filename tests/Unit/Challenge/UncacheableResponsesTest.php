<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\AltchaChallengeProvider;
use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\RecaptchaChallengeProvider;
use Kanopi\Firewall\Challenge\SingleUseSolutionInterface;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\NoStore;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * A challenge served from a cache, and a challenge submitted twice (#417).
 *
 * Behind an edge that cached the interstitial -- Pantheon's Global CDN caches a response
 * carrying only `Cache-Control: no-store` -- every visitor to a URL got the same single-use
 * ALTCHA challenge. The first solver spent it, and everybody after was refused and sent
 * back to the same cached page, in a loop. A double click did the same thing to one visitor
 * without any cache at all.
 */
final class UncacheableResponsesTest extends AbstractTestCase
{
    private const SECRET = 'uncacheable-responses-test-secret';

    // -----------------------------------------------------------------------
    // The headers
    // -----------------------------------------------------------------------

    /**
     * Every directive a cache might be reading, because `no-store` alone was not enough.
     */
    public function testTheHeaderSetKeepsAResponseOutOfEveryCache(): void
    {
        $cacheControl = array_map('trim', explode(',', NoStore::HEADERS['Cache-Control']));

        foreach (['private', 'no-store', 'no-cache', 'must-revalidate', 'max-age=0'] as $directive) {
            $this->assertContains($directive, $cacheControl);
        }

        $this->assertSame('no-cache', NoStore::HEADERS['Pragma']);
        $this->assertSame('0', NoStore::HEADERS['Expires']);
        $this->assertSame('no-store', NoStore::HEADERS['Surrogate-Control']);
        $this->assertSame('no-store', NoStore::HEADERS['CDN-Cache-Control']);
    }

    /**
     * No response the firewall writes still sends `no-store` on its own, or nothing.
     *
     * The response paths end in `exit()` and cannot be run in the suite, so this reads the
     * source: every `exit` that answers a request must be preceded, within its block, by
     * the header set.
     */
    public function testEveryResponseTheFirewallWritesSendsTheSet(): void
    {
        $source = (string) file_get_contents(dirname(__DIR__, 3) . '/src/Firewall.php');

        $this->assertStringNotContainsString("header('Cache-Control:", $source, 'A single Cache-Control header is back.');

        preg_match_all('/@codeCoverageIgnoreStart(.*?)@codeCoverageIgnoreEnd/s', $source, $blocks);

        $responding = array_filter($blocks[1], static fn(string $block): bool => str_contains($block, 'exit'));

        // The interstitial, both verify answers, block, lockdown and redirect.
        $this->assertGreaterThanOrEqual(6, count($responding));

        foreach ($responding as $block) {
            $this->assertStringContainsString('NoStore::send()', $block, trim(substr($block, 0, 200)));
        }
    }

    // -----------------------------------------------------------------------
    // Telling a cached page from a replay
    // -----------------------------------------------------------------------

    private function firewallWith(ChallengeProviderInterface $provider): Firewall
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
            ['mode' => 'exception'],
            $provider
        );

        return $firewall;
    }

    private function singleUseProvider(): ChallengeProviderInterface
    {
        return new class implements ChallengeProviderInterface, SingleUseSolutionInterface {
            public function getName(): string
            {
                return 'fixed-receipt';
            }

            public function renderInterstitial(Request $request, array $context): string
            {
                return '';
            }

            public function verifySolution(Request $request): bool
            {
                return true;
            }

            public function getSolutionReceipt(Request $request): ?array
            {
                // One challenge, as every visitor to a cached page is holding.
                return ['id' => 'the-cached-challenge', 'expires' => time() + 300];
            }
        };
    }

    private function consume(Firewall $firewall, string $ip): bool
    {
        $method = new \ReflectionMethod(Firewall::class, 'consumeSingleUseSolution');

        return $method->invoke(
            $firewall,
            Request::create('/_firewall/challenge', 'POST', [], [], [], ['REMOTE_ADDR' => $ip])
        );
    }

    private const SHARED = 'A spent challenge solution came back from a different client';

    /**
     * The signature of a cached interstitial: a second client holding the first one's
     * challenge. Still refused -- the solution is spent -- and now said out loud.
     */
    public function testASolutionSpentBySomebodyElseIsReportedAsACachedPage(): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $firewall = $this->firewallWith($this->singleUseProvider());

        $this->assertTrue($this->consume($firewall, '203.0.113.1'));
        $this->assertFalse($this->consume($firewall, '198.51.100.7'), 'Still spent.');

        $this->assertTrue($handler->hasRecordThatContains(self::SHARED, Level::Warning));
    }

    /**
     * The same client twice is a double click or a replay, not a cache, and stays quiet.
     */
    public function testTheSameClientTwiceIsNotReportedAsACachedPage(): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $firewall = $this->firewallWith($this->singleUseProvider());

        $this->assertTrue($this->consume($firewall, '203.0.113.1'));
        $this->assertFalse($this->consume($firewall, '203.0.113.1'));

        $this->assertFalse($handler->hasRecordThatContains(self::SHARED, Level::Warning));
    }

    /**
     * A record written before the spending client was kept says nothing either way.
     */
    public function testARecordWithNoClientSaysNothing(): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $firewall = $this->firewallWith($this->singleUseProvider());
        $storage = (new \ReflectionProperty($firewall, 'storage'))->getValue($firewall);
        $storage->set('fw_challenge_solution:' . hash('sha256', 'the-cached-challenge'), ['consumed_at' => time()], 300);

        $this->assertFalse($this->consume($firewall, '198.51.100.7'));
        $this->assertFalse($handler->hasRecordThatContains(self::SHARED, Level::Warning));
    }

    /**
     * The client is kept hashed, as the solution is, so the store holds no address.
     */
    public function testTheSpendingClientIsStoredHashed(): void
    {
        $firewall = $this->firewallWith($this->singleUseProvider());
        $this->consume($firewall, '203.0.113.1');

        $storage = (new \ReflectionProperty($firewall, 'storage'))->getValue($firewall);
        $record = $storage->get('fw_challenge_solution:' . hash('sha256', 'the-cached-challenge'));

        $this->assertIsArray($record);
        $this->assertSame(hash('sha256', '203.0.113.1'), $record['client']);
        $this->assertStringNotContainsString('203.0.113.1', (string) json_encode($record));
    }

    // -----------------------------------------------------------------------
    // One submission at a time
    // -----------------------------------------------------------------------

    /**
     * Every built-in interstitial.
     *
     * @return array<string, array{\Closure(): ChallengeProviderInterface}>
     */
    public static function providers(): array
    {
        return [
            'math' => [static fn(): ChallengeProviderInterface => new MathChallengeProvider(new TokenManager(self::SECRET))],
            'altcha' => [static fn(): ChallengeProviderInterface => new AltchaChallengeProvider(new TokenManager(self::SECRET))],
            'turnstile' => [static fn(): ChallengeProviderInterface => new TurnstileChallengeProvider([
                'site_key' => '1x00000000000000000000AA',
                'secret_key' => '1x0000000000000000000000000000000AA',
            ])],
            'recaptcha' => [static fn(): ChallengeProviderInterface => new RecaptchaChallengeProvider([
                'site_key' => '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
                'secret_key' => '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe',
            ])],
        ];
    }

    /**
     * Run the interstitial's own script under node, against a stub DOM, and report what a
     * double submission did.
     *
     * @return array{afterDouble: int, disabledInFlight: bool, disabledAfterFail: bool, afterRetry: int}
     */
    private function runSubmitScript(ChallengeProviderInterface $provider): array
    {
        $node = trim((string) shell_exec('command -v node 2>/dev/null'));

        if ($node === '') {
            if (getenv('CI') !== false) {
                $this->fail('node is required to run the interstitial script on CI, and was not found');
            }

            $this->markTestSkipped('node is not available to run the interstitial script');
        }

        $html = $provider->renderInterstitial(Request::create('/protected', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.5']), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => '/protected',
            'ttl' => '60',
            'header_name' => '',
        ]);

        preg_match_all('#<script>(.*?)</script>#s', $html, $scripts);
        $this->assertNotEmpty($scripts[1]);

        $harness = <<<'JS'
var calls = 0, pending = [];
var elements = {};
function el(id) {
  if (!elements[id]) {
    elements[id] = {
      id: id, disabled: false, textContent: '', action: '/_firewall/challenge',
      classList: { add: function () {}, remove: function () {} },
      addEventListener: function (type, fn) { this['on' + type] = fn; },
      setAttribute: function () {}, removeAttribute: function () {}
    };
  }
  return elements[id];
}
globalThis.document = { getElementById: el, querySelector: function () { return null; }, addEventListener: function () {} };
globalThis.window = globalThis;
window.location = { replace: function () {}, href: '' };
globalThis.localStorage = { setItem: function () {} };
// Every field present, so each provider's own guard lets the submission through.
globalThis.FormData = function () { return { get: function () { return 'solved'; } }; };
globalThis.fetch = function () { calls++; return new Promise(function (resolve) { pending.push(resolve); }); };
var realTimeout = setTimeout;
window.setTimeout = function () {};

JS;

        $drive = <<<'JS'

var form = el('challenge-form'), submit = el('submit');
function send() { form.onsubmit({ preventDefault: function () {} }); }
submit.disabled = false;
send();
send();
var afterDouble = calls, disabledInFlight = submit.disabled;
pending[0]({ ok: false, json: function () { return Promise.resolve({ error: 'invalid_solution' }); } });
realTimeout(function () {
  var disabledAfterFail = submit.disabled;
  submit.disabled = false;
  send();
  console.log(JSON.stringify({ afterDouble: afterDouble, disabledInFlight: disabledInFlight, disabledAfterFail: disabledAfterFail, afterRetry: calls }));
}, 20);
JS;

        $file = tempnam(sys_get_temp_dir(), 'fw-submit-') . '.js';
        file_put_contents($file, $harness . implode("\n", $scripts[1]) . $drive);

        $output = [];
        $status = 0;
        exec(escapeshellarg($node) . ' ' . escapeshellarg($file) . ' 2>&1', $output, $status);
        unlink($file);

        $this->assertSame(0, $status, implode("\n", $output));

        $result = json_decode((string) end($output), true);
        $this->assertIsArray($result, implode("\n", $output));

        return $result;
    }

    /**
     * A double click posts once. Before, it posted the same single-use solution twice, and
     * the refusal of the second raced the redirect of the first.
     *
     * @param \Closure(): ChallengeProviderInterface $provider
     */
    #[DataProvider('providers')]
    public function testASecondSubmitWhileTheFirstIsInFlightIsIgnored(\Closure $provider): void
    {
        $result = $this->runSubmitScript($provider());

        $this->assertSame(1, $result['afterDouble'], 'Two submits in flight posted twice.');
        $this->assertTrue($result['disabledInFlight'], 'The button stays enabled while a submission is in flight.');
    }

    /**
     * After a refusal the visitor can submit again, so a guard that never reset would not
     * trade one lockout for another.
     *
     * @param \Closure(): ChallengeProviderInterface $provider
     */
    #[DataProvider('providers')]
    public function testARefusalAllowsTheNextSubmission(\Closure $provider): void
    {
        $this->assertSame(2, $this->runSubmitScript($provider())['afterRetry']);
    }

    /**
     * The guard re-enables the button before the provider's own failure handling, so a
     * provider that needs a fresh token first still keeps it disabled -- and math, whose
     * answer can simply be retyped, gets it back.
     *
     * @return array<string, array{\Closure(): ChallengeProviderInterface, bool}>
     */
    public static function buttonAfterRefusal(): array
    {
        $providers = self::providers();

        return [
            'math re-enables' => [$providers['math'][0], false],
            'altcha fetches a new challenge' => [$providers['altcha'][0], true],
            'turnstile waits for a new token' => [$providers['turnstile'][0], true],
            'recaptcha waits for a new token' => [$providers['recaptcha'][0], true],
        ];
    }

    /**
     * @param \Closure(): ChallengeProviderInterface $provider
     */
    #[DataProvider('buttonAfterRefusal')]
    public function testTheProviderKeepsControlOfTheButtonAfterARefusal(\Closure $provider, bool $disabled): void
    {
        $this->assertSame($disabled, $this->runSubmitScript($provider())['disabledAfterFail']);
    }
}
