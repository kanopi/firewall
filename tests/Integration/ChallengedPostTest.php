<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration;

use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Firewall;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * What a visitor is told when their POST is challenged (#376).
 *
 * The submission is discarded and will stay discarded — keeping the body would
 * put card details and passwords into an HTML page. What was wrong is the
 * silence, and these are about ending it.
 */
class ChallengedPostTest extends TestCase
{
    private const SECRET = 'challenged-post-integration-secret';

    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();
        putenv('FIREWALL_BYPASS_CLI=1');

        $this->tempDir = sys_get_temp_dir() . '/firewall_post_' . uniqid();
        if (!mkdir($this->tempDir, 0777, true)) {
            throw new \RuntimeException('Failed to create temp directory: ' . $this->tempDir);
        }
    }

    protected function tearDown(): void
    {
        foreach ((array) glob($this->tempDir . '/*') as $path) {
            if (is_string($path)) {
                @unlink($path);
            }
        }

        @rmdir($this->tempDir);
        parent::tearDown();
    }

    /**
     * The visitor is told, rather than discovering it from an empty form.
     */
    public function testAChallengedPostSaysTheSubmissionWasNotKept(): void
    {
        $context = $this->challenge($this->checkoutPost());

        $this->assertSame(
            'Your submission was not kept. After verifying, you will need to fill the form in again.',
            $context['notice']
        );
    }

    /**
     * And it reaches the page, not just the context — a host in `mode: exception`
     * renders from one and a visitor reads the other.
     */
    public function testTheNoticeReachesTheRenderedPage(): void
    {
        $context = $this->challenge($this->checkoutPost());
        $html = $this->provider()->renderInterstitial($this->checkoutPost(), $context);

        $this->assertStringContainsString('Your submission was not kept', $html);
        $this->assertStringContainsString('class="notice"', $html);
    }

    /**
     * Almost every challenged request is a GET on the way in, and those render
     * exactly as they did before.
     *
     * @param string $method
     */
    #[DataProvider('safeMethodProvider')]
    public function testARequestWithNothingToLoseIsUnchanged(string $method): void
    {
        $request = Request::create('/protected', $method, [], [], [], ['REMOTE_ADDR' => '10.0.0.50']);
        $context = $this->challenge($request);

        $this->assertSame('', $context['notice']);

        // The element, not the word: the stylesheet always carries a `.notice`
        // rule, so asserting on the bare string would pass for the wrong reason
        // and keep passing if the notice were rendered empty.
        $this->assertStringNotContainsString(
            '<p class="notice">',
            $this->provider()->renderInterstitial($request, $context)
        );
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function safeMethodProvider(): array
    {
        return ['GET' => ['GET'], 'HEAD' => ['HEAD']];
    }

    /**
     * The body is discarded, and nothing about it is written into the page that
     * replaces it. Keeping it would put card details and passwords into HTML.
     */
    public function testNothingFromTheSubmittedBodyReachesThePage(): void
    {
        $request = Request::create(
            '/checkout',
            'POST',
            ['card_number' => '4111111111111111', 'cvv' => '737', 'note' => 'leave at door'],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.50']
        );

        $context = $this->challenge($request);
        $html = $this->provider()->renderInterstitial($request, $context);

        foreach (['4111111111111111', '737', 'leave at door', 'card_number'] as $secret) {
            $this->assertStringNotContainsString($secret, $html, sprintf('%s reached the interstitial', $secret));
            $this->assertStringNotContainsString($secret, (string) json_encode($context));
        }
    }

    /**
     * A page is what a browser navigating wants, and `*\/*` means anything will
     * do — otherwise every curl default would get JSON.
     *
     * @param array<string, string> $headers
     */
    #[DataProvider('wantsAPageProvider')]
    public function testABrowserStillGetsAPage(array $headers): void
    {
        $this->assertFalse($this->prefersJson($this->checkoutPost($headers)));
    }

    /**
     * @return array<string, array{0: array<string, string>}>
     */
    public static function wantsAPageProvider(): array
    {
        return [
            'a browser navigating' => [['HTTP_ACCEPT' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8']],
            'anything will do' => [['HTTP_ACCEPT' => '*/*']],
            'nothing asked for' => [[]],
            'html only' => [['HTTP_ACCEPT' => 'text/html']],
            // Neither a page nor JSON was asked for. A page is the safe answer:
            // a human can read one, and a machine that wanted something else
            // said so with a type this does not recognise.
            'something else entirely' => [['HTTP_ACCEPT' => 'text/plain']],
        ];
    }

    /**
     * Serving an interstitial to an XHR is a page a machine cannot solve,
     * arriving where a result was expected.
     *
     * @param array<string, string> $headers
     */
    #[DataProvider('wantsJsonProvider')]
    public function testAnApiCallerIsRecognised(array $headers): void
    {
        $this->assertTrue($this->prefersJson($this->checkoutPost($headers)));
    }

    /**
     * @return array<string, array{0: array<string, string>}>
     */
    public static function wantsJsonProvider(): array
    {
        return [
            'a jQuery-era XHR' => [['HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest']],
            'case insensitively' => [['HTTP_X_REQUESTED_WITH' => 'xmlhttprequest']],
            'accepting json' => [['HTTP_ACCEPT' => 'application/json']],
            'a json api' => [['HTTP_ACCEPT' => 'application/vnd.api+json']],
            'json ahead of a wildcard' => [['HTTP_ACCEPT' => 'application/json;q=0.9,*/*;q=0.1']],
        ];
    }

    /**
     * The message says what happened, and says the extra part only when there
     * was something to lose.
     */
    public function testTheJsonMessageMentionsTheLostBodyOnlyForASubmission(): void
    {
        $post = $this->challenge($this->checkoutPost(['HTTP_ACCEPT' => 'application/json']));
        $get = $this->challenge(Request::create('/protected', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.50']));

        $this->assertNotSame('', $post['notice']);
        $this->assertSame('', $get['notice']);
    }

    /**
     * The render context is what a host in `mode: exception` builds its own
     * response from, so the new key has to be there for them too.
     */
    public function testTheContextCarriesEveryKeyAHostNeeds(): void
    {
        $context = $this->challenge($this->checkoutPost());

        foreach (['submit_url', 'redirect_to', 'ttl', 'cookie_name', 'header_name', 'provider_token', 'notice'] as $key) {
            $this->assertArrayHasKey($key, $context);
        }
    }

    /**
     * @param array<string, string> $headers
     */
    private function checkoutPost(array $headers = []): Request
    {
        return Request::create(
            '/checkout',
            'POST',
            ['cart_id' => 'abc123'],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.50'] + $headers
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function challenge(Request $request): array
    {
        try {
            Firewall::create([$this->config()])->evaluate($request);
            $this->fail('Expected ChallengeRequiredException');
        } catch (ChallengeRequiredException $challengeRequiredException) {
            return $challengeRequiredException->getRenderContext();
        }

        return []; // Unreachable.
    }

    private function prefersJson(Request $request): bool
    {
        $firewall = Firewall::create([$this->config()]);

        return (bool) (new \ReflectionMethod($firewall, 'prefersJson'))->invoke($firewall, $request);
    }

    private function provider(): MathChallengeProvider
    {
        $provider = (new \ReflectionProperty(Firewall::create([$this->config()]), 'challengeProvider'))
            ->getValue(Firewall::create([$this->config()]));
        $this->assertInstanceOf(MathChallengeProvider::class, $provider);

        return $provider;
    }

    private function config(): string
    {
        $file = $this->tempDir . '/post.yml';

        file_put_contents($file, Yaml::dump([
            'global' => ['mode' => 'exception'],
            'challenge' => ['provider' => 'math', 'secret' => self::SECRET, 'ttl' => 900],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'challenge',
                    'weight' => 0,
                    'enable' => true,
                    'metadata' => ['name' => 'gate'],
                    'config' => ['10.0.0.50'],
                ],
            ],
        ], 6, 2));

        return $file;
    }
}
