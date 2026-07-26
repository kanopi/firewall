<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\AltchaChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

final class AltchaChallengeProviderTest extends AbstractTestCase
{
    private const SECRET = 'altcha-test-secret-value';

    public function testGetNameReturnsAltcha(): void
    {
        $provider = new AltchaChallengeProvider(new TokenManager(self::SECRET));
        $this->assertSame('altcha', $provider->getName());
    }

    public function testRenderProducesExpectedFields(): void
    {
        $provider = new AltchaChallengeProvider(new TokenManager(self::SECRET));
        $html = $provider->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => '/wanted-page',
            'ttl' => '900',
            'cookie_name' => 'fw_pass',
            'header_name' => 'X-FW',
        ]);

        $this->assertStringContainsString('<form', $html);
        $this->assertStringContainsString('action="/_firewall/challenge"', $html);
        $this->assertStringContainsString('<altcha-widget', $html);
        $this->assertStringContainsString('challengejson=', $html);
        $this->assertStringContainsString('name="' . AltchaChallengeProvider::REDIRECT_FIELD . '"', $html);
        $this->assertStringContainsString('name="' . AltchaChallengeProvider::TTL_FIELD . '"', $html);
        $this->assertStringContainsString('value="/wanted-page"', $html);
        $this->assertStringContainsString('value="900"', $html);
    }

    public function testRenderEmbedsChallengeJsonWithExpectedShape(): void
    {
        $provider = new AltchaChallengeProvider(new TokenManager(self::SECRET));
        $html = $provider->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => '/',
            'ttl' => '60',
            'cookie_name' => 'c',
            'header_name' => 'h',
        ]);

        $challenge = $this->extractChallenge($html);
        $this->assertSame('SHA-256', $challenge['algorithm']);
        $this->assertArrayHasKey('challenge', $challenge);
        $this->assertArrayHasKey('salt', $challenge);
        $this->assertArrayHasKey('signature', $challenge);
        $this->assertArrayHasKey('maxnumber', $challenge);
        $this->assertIsString($challenge['salt']);
        $this->assertStringContainsString('?expires=', $challenge['salt']);
    }

    public function testRenderEscapesContextValues(): void
    {
        $provider = new AltchaChallengeProvider(new TokenManager(self::SECRET));
        $html = $provider->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => '/"><script>alert(1)</script>',
            'ttl' => '60',
            'cookie_name' => 'fw_pass',
            'header_name' => 'X-FW',
        ]);

        $this->assertStringNotContainsString('<script>alert(1)</script>', $html);
        $this->assertStringContainsString('&lt;script&gt;', $html);
    }

    public function testRenderPinsWidgetAndEmitsIntegrityByDefault(): void
    {
        $provider = new AltchaChallengeProvider(new TokenManager(self::SECRET));
        $html = $this->render($provider);

        $this->assertStringContainsString(
            'src="' . AltchaChallengeProvider::DEFAULT_WIDGET_SRC . '"',
            $html
        );
        $this->assertStringContainsString(
            'integrity="' . AltchaChallengeProvider::DEFAULT_WIDGET_INTEGRITY . '"',
            $html
        );
        $this->assertStringContainsString('crossorigin="anonymous"', $html);
        // The bundle is an ES module; a classic script tag cannot load it.
        $this->assertStringContainsString('type="module"', $html);
    }

    public function testDefaultWidgetSrcIsPinnedToAnExactVersion(): void
    {
        // An unpinned URL silently changes what every challenge page loads.
        $this->assertMatchesRegularExpression(
            '#/altcha@\d+\.\d+\.\d+/#',
            AltchaChallengeProvider::DEFAULT_WIDGET_SRC
        );
        $this->assertStringStartsWith('sha384-', AltchaChallengeProvider::DEFAULT_WIDGET_INTEGRITY);
    }

    public function testCustomWidgetSrcIsHonoured(): void
    {
        $provider = new AltchaChallengeProvider(
            new TokenManager(self::SECRET),
            ['widget_src' => '/assets/altcha.min.js', 'widget_integrity' => 'sha384-custom']
        );
        $html = $this->render($provider);

        $this->assertStringContainsString('src="/assets/altcha.min.js"', $html);
        $this->assertStringContainsString('integrity="sha384-custom"', $html);
        $this->assertStringNotContainsString(AltchaChallengeProvider::DEFAULT_WIDGET_SRC, $html);
    }

    public function testCustomWidgetSrcWithoutIntegrityEmitsNoDigest(): void
    {
        // Carrying the default digest over to a different bundle would
        // block the script outright, so no attribute is emitted at all.
        $provider = new AltchaChallengeProvider(
            new TokenManager(self::SECRET),
            ['widget_src' => '/assets/altcha.min.js']
        );
        $html = $this->render($provider);

        $this->assertStringContainsString('src="/assets/altcha.min.js"', $html);
        $this->assertStringNotContainsString('integrity=', $html);
        $this->assertStringNotContainsString(AltchaChallengeProvider::DEFAULT_WIDGET_INTEGRITY, $html);
    }

    public function testBlankWidgetOptionsFallBackToTheDefaults(): void
    {
        $provider = new AltchaChallengeProvider(
            new TokenManager(self::SECRET),
            ['widget_src' => '   ', 'widget_integrity' => '']
        );
        $html = $this->render($provider);

        $this->assertStringContainsString(AltchaChallengeProvider::DEFAULT_WIDGET_SRC, $html);
        $this->assertStringContainsString(AltchaChallengeProvider::DEFAULT_WIDGET_INTEGRITY, $html);
    }

    public function testWidgetSrcIsEscapedIntoTheAttribute(): void
    {
        $provider = new AltchaChallengeProvider(
            new TokenManager(self::SECRET),
            ['widget_src' => '/a.js" onload="alert(1)']
        );
        $html = $this->render($provider);

        $this->assertStringNotContainsString('onload="alert(1)"', $html);
        $this->assertStringContainsString('&quot;', $html);
    }

    public function testVerifyAcceptsValidSolution(): void
    {
        $provider = new AltchaChallengeProvider(new TokenManager(self::SECRET));

        [$challenge, $number] = $this->renderAndSolve($provider);

        $request = $this->makeSubmissionRequest($this->encodeSolution($challenge, $number));
        $this->assertTrue($provider->verifySolution($request));
    }

    public function testVerifyRejectsMissingPayload(): void
    {
        $provider = new AltchaChallengeProvider(new TokenManager(self::SECRET));
        $this->assertFalse($provider->verifySolution($this->makeSubmissionRequest('')));
    }

    public function testVerifyRejectsNonBase64Payload(): void
    {
        $provider = new AltchaChallengeProvider(new TokenManager(self::SECRET));
        $this->assertFalse($provider->verifySolution($this->makeSubmissionRequest('!!!not-base64!!!')));
    }

    public function testVerifyRejectsNonJsonPayload(): void
    {
        $provider = new AltchaChallengeProvider(new TokenManager(self::SECRET));
        $this->assertFalse($provider->verifySolution(
            $this->makeSubmissionRequest(base64_encode('totally not json'))
        ));
    }

    public function testVerifyRejectsTamperedChallenge(): void
    {
        $provider = new AltchaChallengeProvider(new TokenManager(self::SECRET));

        [$challenge, $number] = $this->renderAndSolve($provider);
        $challenge['challenge'] = str_repeat('0', strlen((string) $challenge['challenge']));

        $request = $this->makeSubmissionRequest($this->encodeSolution($challenge, $number));
        $this->assertFalse($provider->verifySolution($request));
    }

    public function testVerifyRejectsWrongNumber(): void
    {
        $provider = new AltchaChallengeProvider(new TokenManager(self::SECRET));

        [$challenge, $number] = $this->renderAndSolve($provider);
        $request = $this->makeSubmissionRequest($this->encodeSolution($challenge, $number + 1));
        $this->assertFalse($provider->verifySolution($request));
    }

    public function testVerifyRejectsBadSignature(): void
    {
        $provider = new AltchaChallengeProvider(new TokenManager(self::SECRET));

        [$challenge, $number] = $this->renderAndSolve($provider);
        $challenge['signature'] = 'forged-signature';
        $request = $this->makeSubmissionRequest($this->encodeSolution($challenge, $number));
        $this->assertFalse($provider->verifySolution($request));
    }

    public function testVerifyRejectsExpiredChallenge(): void
    {
        $tokenManager = new TokenManager(self::SECRET);
        $provider = new AltchaChallengeProvider($tokenManager);

        $salt = bin2hex(random_bytes(8)) . '?expires=' . (time() - 60);
        $number = 42;
        $challenge = hash('sha256', $salt . $number);
        $signature = $tokenManager->sign($challenge);

        $payload = base64_encode((string) json_encode([
            'algorithm' => 'SHA-256',
            'challenge' => $challenge,
            'number' => $number,
            'salt' => $salt,
            'signature' => $signature,
        ]));

        $this->assertFalse($provider->verifySolution($this->makeSubmissionRequest($payload)));
    }

    public function testVerifyRejectsSaltWithoutExpiry(): void
    {
        $tokenManager = new TokenManager(self::SECRET);
        $provider = new AltchaChallengeProvider($tokenManager);

        // Properly signed, properly hashed — but the salt has no `?expires`.
        $salt = bin2hex(random_bytes(8));
        $number = 7;
        $challenge = hash('sha256', $salt . $number);
        $signature = $tokenManager->sign($challenge);

        $payload = base64_encode((string) json_encode([
            'algorithm' => 'SHA-256',
            'challenge' => $challenge,
            'number' => $number,
            'salt' => $salt,
            'signature' => $signature,
        ]));

        $this->assertFalse($provider->verifySolution($this->makeSubmissionRequest($payload)));
    }

    public function testVerifyRejectsWrongAlgorithm(): void
    {
        $provider = new AltchaChallengeProvider(new TokenManager(self::SECRET));

        [$challenge, $number] = $this->renderAndSolve($provider);
        $challenge['algorithm'] = 'SHA-1';

        $this->assertFalse($provider->verifySolution(
            $this->makeSubmissionRequest($this->encodeSolution($challenge, $number))
        ));
    }

    /**
     * Render an interstitial with a stock context.
     */
    private function render(AltchaChallengeProvider $provider): string
    {
        return $provider->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => '/',
            'ttl' => '60',
            'header_name' => 'X-FW',
        ]);
    }

    /**
     * Render the interstitial and brute-force the embedded challenge so
     * the test ends up holding a payload that would actually verify.
     *
     * @return array{0: array<string, mixed>, 1: int}
     */
    private function renderAndSolve(AltchaChallengeProvider $provider): array
    {
        $html = $provider->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => '/',
            'ttl' => '60',
            'cookie_name' => 'c',
            'header_name' => 'h',
        ]);

        $challenge = $this->extractChallenge($html);
        $number = $this->solve($challenge);

        return [$challenge, $number];
    }

    /**
     * @return array<string, mixed>
     */
    private function extractChallenge(string $html): array
    {
        $this->assertSame(1, preg_match('/challengejson="([^"]+)"/', $html, $m), 'challengejson attribute missing');
        $decoded = html_entity_decode($m[1], ENT_QUOTES, 'UTF-8');
        /** @var array<string, mixed>|null $data */
        $data = json_decode($decoded, true);
        $this->assertIsArray($data);
        return $data;
    }

    /**
     * Brute-force find N such that SHA-256(salt + N) == challenge — fast
     * enough at the default maxnumber to keep the suite snappy.
     *
     * @param array<string, mixed> $challenge
     */
    private function solve(array $challenge): int
    {
        $max = (int) $challenge['maxnumber'];
        $salt = (string) $challenge['salt'];
        $target = (string) $challenge['challenge'];

        for ($i = 0; $i <= $max; $i++) {
            if (hash_equals($target, hash('sha256', $salt . $i))) {
                return $i;
            }
        }

        $this->fail('Could not solve challenge within maxnumber');
    }

    /**
     * @param array<string, mixed> $challenge
     */
    private function encodeSolution(array $challenge, int $number): string
    {
        return base64_encode((string) json_encode([
            'algorithm' => $challenge['algorithm'],
            'challenge' => $challenge['challenge'],
            'number' => $number,
            'salt' => $challenge['salt'],
            'signature' => $challenge['signature'],
        ]));
    }

    private function makeSubmissionRequest(string $payload): Request
    {
        return Request::create(
            '/_firewall/challenge',
            'POST',
            [AltchaChallengeProvider::PAYLOAD_FIELD => $payload],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.5']
        );
    }
}
