<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration;

use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Firewall;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * The pass lifetime the firewall decided, surviving the round trip signed (#369).
 *
 * #367 clamped what the client proposed. This is about removing the proposal:
 * the number that decides is one the client cannot alter, and the posted `ttl`
 * field stops being believed.
 */
class SignedPassLifetimeTest extends TestCase
{
    private const SECRET = 'signed-lifetime-integration-secret';

    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();
        putenv('FIREWALL_BYPASS_CLI=1');

        $this->tempDir = sys_get_temp_dir() . '/firewall_signed_ttl_' . uniqid();
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
     * The rule's own lifetime reaches the token, without the form being asked.
     */
    public function testTheRulesLifetimeSurvivesTheRoundTripSigned(): void
    {
        $firewall = Firewall::create([$this->config(600)]);
        $token = $this->signedProviderToken($firewall);

        $this->assertStringContainsString('|600.', $token, 'The rendered token carries no signed lifetime');
        $this->assertEqualsWithDelta(600, $this->solveAndReadLifetime($firewall, $token, null), 1);
    }

    /**
     * The bug this closes: the posted field is no longer what decides.
     */
    public function testAPostedLifetimeIsIgnoredWhenOneIsSigned(): void
    {
        $firewall = Firewall::create([$this->config(600)]);
        $token = $this->signedProviderToken($firewall);

        $this->assertEqualsWithDelta(
            600,
            $this->solveAndReadLifetime($firewall, $token, '999999999'),
            1,
            'The client proposed a lifetime and was believed'
        );
    }

    /**
     * And a *smaller* posted value is ignored too. The point is not that the
     * client cannot ask for more — it is that the client is not asked.
     */
    public function testEvenAShorterPostedLifetimeIsIgnored(): void
    {
        $firewall = Firewall::create([$this->config(600)]);
        $token = $this->signedProviderToken($firewall);

        $this->assertEqualsWithDelta(600, $this->solveAndReadLifetime($firewall, $token, '5'), 1);
    }

    /**
     * `challenge.ttl` may have been lowered while the page was open, so the
     * signed value is clamped rather than trusted outright — a ceiling that
     * applied only to what the client sent would be a ceiling with a gap.
     */
    public function testASignedLifetimeIsStillClampedByTheCeiling(): void
    {
        $token = $this->signedProviderToken(Firewall::create([$this->config(3000, 3600)]));

        // The operator lowers the ceiling; the page in the visitor's browser
        // still carries the lifetime signed under the old one.
        $lowered = Firewall::create([$this->config(3000, 900, 'lowered.yml')]);

        $this->assertEqualsWithDelta(900, $this->solveAndReadLifetime($lowered, $token, null), 1);
    }

    /**
     * The upgrade window: an interstitial rendered before 2.32.0 carries the
     * provider name alone. Rejecting those would re-challenge every visitor who
     * happened to be mid-solve when the deploy landed.
     */
    public function testAnInterstitialRenderedBeforeThisReleaseStillVerifies(): void
    {
        $firewall = Firewall::create([$this->config(600)]);
        $legacy = $this->legacyProviderToken($firewall);

        $this->assertStringNotContainsString('|', $legacy);
        $this->assertEqualsWithDelta(300, $this->solveAndReadLifetime($firewall, $legacy, '300'), 1);
    }

    /**
     * And it falls back to #367's ceiling, which is exactly the defence in
     * depth that issue was written to be.
     */
    public function testALegacyInterstitialIsStillBoundedByTheCeiling(): void
    {
        $firewall = Firewall::create([$this->config(600, 900)]);
        $legacy = $this->legacyProviderToken($firewall);

        $this->assertEqualsWithDelta(900, $this->solveAndReadLifetime($firewall, $legacy, '999999999'), 1);
    }

    /**
     * A rewritten lifetime does not verify, which is the whole point of signing
     * it rather than merely sending it.
     */
    public function testEditingTheSignedLifetimeRefusesTheSubmission(): void
    {
        $firewall = Firewall::create([$this->config(600)]);
        $token = $this->signedProviderToken($firewall);
        $forged = str_replace('|600.', '|999999999.', $token);

        $this->assertNotSame($token, $forged, 'The token did not carry the lifetime this test rewrites');

        $this->expectException(ChallengeRequiredException::class);
        $this->solveAndReadLifetime($firewall, $forged, null);
    }

    /**
     * A refused submission is re-rendered with a signed lifetime too, so a
     * visitor who fails once does not drop back to proposing their own.
     */
    public function testARefusedSubmissionIsRetriedWithASignedLifetime(): void
    {
        $firewall = Firewall::create([$this->config(600)]);
        $token = $this->signedProviderToken($firewall);
        [$state, $answer] = $this->solvedState($firewall);

        try {
            $firewall->evaluate($this->submission([
                MathChallengeProvider::STATE_FIELD => $state,
                MathChallengeProvider::ANSWER_FIELD => (string) ((int) $answer + 1),
                MathChallengeProvider::PROVIDER_FIELD => $token,
                MathChallengeProvider::TTL_FIELD => '999999999',
            ]));
            $this->fail('Expected ChallengeRequiredException');
        } catch (ChallengeRequiredException $challengeRequiredException) {
            $context = $challengeRequiredException->getRenderContext();

            $this->assertSame('600', $context['ttl'], 'The retry echoed the posted lifetime');
            $this->assertStringContainsString('|600.', (string) $context['provider_token']);
        }
    }

    /**
     * The separator is only meaningful in the signed payload, so a provider
     * whose *name* carries a pipe still reads as a name — the split takes the
     * last one and requires digits after it.
     *
     * Reachable because a provider may be named by FQCN or by a custom short
     * name, and nothing forbids a pipe in either.
     */
    public function testAProviderNameCarryingASeparatorIsNotMistakenForALifetime(): void
    {
        $firewall = Firewall::create([$this->config(600)]);
        $split = new \ReflectionMethod($firewall, 'splitSignedProvider');

        $this->assertSame(['weird|name', null], $split->invoke($firewall, 'weird|name'));
        $this->assertSame(['weird|name', 600], $split->invoke($firewall, 'weird|name|600'));
        $this->assertSame(['math|0', null], $split->invoke($firewall, 'math|0'), 'Zero is not a lifetime');
        $this->assertSame(['math', null], $split->invoke($firewall, 'math'));
        $this->assertSame(['|600', null], $split->invoke($firewall, '|600'), 'A leading separator is a name');
    }

    /**
     * `getRenderContext()['ttl']` is public API — hosts in `mode: exception`
     * render from it — so it keeps meaning what it meant.
     */
    public function testTheRenderContextStillCarriesTheLifetimeForHosts(): void
    {
        $firewall = Firewall::create([$this->config(600)]);

        try {
            $firewall->evaluate(Request::create('/protected', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.50']));
            $this->fail('Expected ChallengeRequiredException');
        } catch (ChallengeRequiredException $challengeRequiredException) {
            $this->assertSame('600', $challengeRequiredException->getRenderContext()['ttl']);
        }
    }

    /**
     * The `provider_token` the firewall renders for this challenge.
     */
    private function signedProviderToken(Firewall $firewall): string
    {
        try {
            $firewall->evaluate(Request::create('/protected', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.50']));
            $this->fail('Expected ChallengeRequiredException');
        } catch (ChallengeRequiredException $challengeRequiredException) {
            return (string) $challengeRequiredException->getRenderContext()['provider_token'];
        }

        return ''; // Unreachable.
    }

    /**
     * A `provider_token` in the shape 2.31.0 and earlier produced: the provider
     * name signed on its own.
     */
    private function legacyProviderToken(Firewall $firewall): string
    {
        $name = explode('|', $this->signedProviderToken($firewall))[0];
        $tokenManager = new TokenManager(self::SECRET, 'math', 'math');

        return $name . '.' . $tokenManager->sign('challenge-provider:' . $name);
    }

    /**
     * Solve, submit, and report how long the minted pass lasts.
     */
    private function solveAndReadLifetime(Firewall $firewall, string $providerToken, ?string $postedTtl): int
    {
        [$state, $answer] = $this->solvedState($firewall);

        $fields = [
            MathChallengeProvider::STATE_FIELD => $state,
            MathChallengeProvider::ANSWER_FIELD => $answer,
            MathChallengeProvider::PROVIDER_FIELD => $providerToken,
        ];

        if ($postedTtl !== null) {
            $fields[MathChallengeProvider::TTL_FIELD] = $postedTtl;
        }

        $before = time();

        try {
            $firewall->evaluate($this->submission($fields));
            $this->fail('Expected ChallengeSolvedException');
        } catch (ChallengeSolvedException $challengeSolvedException) {
            [$payload] = explode('.', $challengeSolvedException->getToken(), 2);
            $claims = json_decode((string) base64_decode(strtr($payload, '-_', '+/'), true), true);
            $this->assertIsArray($claims);

            return (int) $claims['exp'] - $before;
        }

        return -1; // Unreachable.
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function solvedState(Firewall $firewall): array
    {
        $provider = (new \ReflectionProperty($firewall, 'challengeProvider'))->getValue($firewall);
        $this->assertInstanceOf(MathChallengeProvider::class, $provider);

        $html = $provider->renderInterstitial(
            Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.50']),
            ['submit_url' => '/_firewall/challenge', 'redirect_to' => '/protected', 'ttl' => '600']
        );

        preg_match('/name="' . preg_quote(MathChallengeProvider::STATE_FIELD, '/') . '" value="([^"]+)"/', $html, $match);
        $this->assertNotEmpty($match, 'state hidden input missing');

        [$data] = explode('.', $match[1], 2);
        [$answer] = explode('|', $data, 2);

        return [$match[1], $answer];
    }

    /**
     * @param array<string, string> $fields
     */
    private function submission(array $fields): Request
    {
        return Request::create(
            '/_firewall/challenge',
            'POST',
            $fields + [MathChallengeProvider::REDIRECT_FIELD => '/protected'],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.50']
        );
    }

    private function config(int $ruleTtl, int $ceiling = 3600, string $filename = 'signed.yml'): string
    {
        $file = $this->tempDir . '/' . $filename;

        file_put_contents($file, Yaml::dump([
            'global' => ['mode' => 'exception'],
            'challenge' => ['provider' => 'math', 'secret' => self::SECRET, 'ttl' => $ceiling],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'challenge',
                    'weight' => 0,
                    'enable' => true,
                    'metadata' => ['name' => 'gate', 'default_expiration_time' => $ruleTtl],
                    'config' => ['10.0.0.50'],
                ],
            ],
        ], 6, 2));

        return $file;
    }
}
