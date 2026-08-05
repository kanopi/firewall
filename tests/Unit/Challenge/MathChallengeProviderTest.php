<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

final class MathChallengeProviderTest extends AbstractTestCase
{
    private const SECRET = 'math-test-secret-value';

    public function testRenderProducesExpectedFields(): void
    {
        $provider = new MathChallengeProvider(new TokenManager(self::SECRET));
        $request = $this->getRequest('10.0.0.5');

        $html = $provider->renderInterstitial($request, [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => '/wanted-page',
            'ttl' => '900',
            'cookie_name' => 'fw_pass',
            'header_name' => 'X-FW',
        ]);

        $this->assertStringContainsString('<form', $html);
        $this->assertStringContainsString('action="/_firewall/challenge"', $html);
        $this->assertStringContainsString('name="' . MathChallengeProvider::ANSWER_FIELD . '"', $html);
        $this->assertStringContainsString('name="' . MathChallengeProvider::STATE_FIELD . '"', $html);
        $this->assertStringContainsString('name="' . MathChallengeProvider::REDIRECT_FIELD . '"', $html);
        $this->assertStringContainsString('name="' . MathChallengeProvider::TTL_FIELD . '"', $html);
        $this->assertStringContainsString('value="/wanted-page"', $html);
        $this->assertStringContainsString('value="900"', $html);
        // Posed question must reach the body so a visitor can read it.
        $this->assertMatchesRegularExpression('/What is \d \+ \d\?/', $html);
    }

    public function testRenderEscapesContextValues(): void
    {
        $provider = new MathChallengeProvider(new TokenManager(self::SECRET));
        $request = $this->getRequest('10.0.0.5');

        $html = $provider->renderInterstitial($request, [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => '/"><script>alert(1)</script>',
            'ttl' => '60',
            'cookie_name' => 'fw_pass',
            'header_name' => 'X-FW',
        ]);

        $this->assertStringNotContainsString('<script>alert(1)</script>', $html);
        $this->assertStringContainsString('&lt;script&gt;', $html);
    }

    public function testVerifyAcceptsCorrectAnswer(): void
    {
        $tokenManager = new TokenManager(self::SECRET);
        $provider = new MathChallengeProvider($tokenManager);

        // Extract the signed state + the expected answer from rendered HTML.
        [$state, $answer] = $this->renderAndExtractSolution($provider);

        $request = $this->makeSubmissionRequest($state, $answer);

        $this->assertTrue($provider->verifySolution($request));
    }

    public function testVerifyRejectsWrongAnswer(): void
    {
        $tokenManager = new TokenManager(self::SECRET);
        $provider = new MathChallengeProvider($tokenManager);

        [$state, $answer] = $this->renderAndExtractSolution($provider);
        $wrong = (string) ((int) $answer + 1);

        $this->assertFalse($provider->verifySolution($this->makeSubmissionRequest($state, $wrong)));
    }

    public function testVerifyRejectsMissingFields(): void
    {
        $provider = new MathChallengeProvider(new TokenManager(self::SECRET));

        $this->assertFalse($provider->verifySolution($this->makeSubmissionRequest('', '5')));
        $this->assertFalse($provider->verifySolution($this->makeSubmissionRequest('a.b', '')));
        $this->assertFalse($provider->verifySolution($this->makeSubmissionRequest('no-dot', '5')));
    }

    public function testVerifyRejectsTamperedState(): void
    {
        $tokenManager = new TokenManager(self::SECRET);
        $provider = new MathChallengeProvider($tokenManager);

        [$state, $answer] = $this->renderAndExtractSolution($provider);
        [$data, $signature] = explode('.', $state, 2);

        // Bump the answer in the data half — signature should no longer match.
        $tampered = ((string) ((int) $answer + 1)) . substr($data, strlen($answer)) . '.' . $signature;

        $this->assertFalse($provider->verifySolution($this->makeSubmissionRequest($tampered, (string) ((int) $answer + 1))));
    }

    public function testVerifyRejectsExpiredState(): void
    {
        $tokenManager = new TokenManager(self::SECRET);
        $provider = new MathChallengeProvider($tokenManager);

        // Hand-craft an expired (but properly signed) state.
        $data = '5|' . (time() - 60);
        $expired = $data . '.' . $tokenManager->sign($data);

        $this->assertFalse($provider->verifySolution($this->makeSubmissionRequest($expired, '5')));
    }

    public function testGetNameReturnsMath(): void
    {
        $provider = new MathChallengeProvider(new TokenManager(self::SECRET));
        $this->assertSame('math', $provider->getName());
    }

    /**
     * @return array{0: string, 1: string} [signed state, correct answer]
     */
    private function renderAndExtractSolution(MathChallengeProvider $provider): array
    {
        $request = $this->getRequest('10.0.0.5');
        $html = $provider->renderInterstitial($request, [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => '/x',
            'ttl' => '60',
            'cookie_name' => 'c',
            'header_name' => 'h',
        ]);

        // Extract the signed state from the hidden input.
        $stateField = MathChallengeProvider::STATE_FIELD;
        preg_match('/name="' . preg_quote($stateField, '/') . '" value="([^"]+)"/', $html, $stateMatch);
        $this->assertNotEmpty($stateMatch, 'Hidden state field missing from rendered HTML');
        $state = $stateMatch[1];

        // The state encodes "answer|exp.signature" — split it back out so
        // the test knows the right answer without parsing the question.
        [$data, ] = explode('.', $state, 2);
        [$answer, ] = explode('|', $data, 2);

        return [$state, $answer];
    }

    /**
     * Signed state whose data half is not `answer|expiry`.
     *
     * @return array<string, array{0: string}>
     */
    public static function malformedStateDataProvider(): array
    {
        return [
            'no separator' => ['7'],
            'two separators' => ['7|9999999999|extra'],
            'empty' => [''],
            'separator only' => ['|'],
        ];
    }

    /**
     * A correctly signed state can still be the wrong shape.
     *
     * The signature is checked before the payload is split, so anyone holding
     * the secret — including a future bug in this class — can present signed
     * state that does not parse. Signing each case with the real secret is
     * the point: it reaches the shape check rather than stopping at the HMAC.
     */
    #[DataProvider('malformedStateDataProvider')]
    public function testCorrectlySignedMalformedStateIsRejected(string $data): void
    {
        $tokenManager = new TokenManager(self::SECRET);
        $provider = new MathChallengeProvider($tokenManager);

        $state = $data . '.' . $tokenManager->sign($data);

        $this->assertFalse($provider->verifySolution($this->makeSubmissionRequest($state, '7')));
    }

    private function makeSubmissionRequest(string $state, string $answer): Request
    {
        return Request::create(
            '/_firewall/challenge',
            'POST',
            [
                MathChallengeProvider::STATE_FIELD => $state,
                MathChallengeProvider::ANSWER_FIELD => $answer,
            ],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.5']
        );
    }
}
