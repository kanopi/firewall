<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration;

use Kanopi\Firewall\Challenge\AltchaChallengeProvider;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\RecaptchaChallengeProvider;
use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Challenge\AlwaysVerifyingRecaptchaProvider;
use Kanopi\Firewall\Tests\Challenge\AlwaysVerifyingTurnstileProvider;
use Kanopi\Firewall\Tests\Challenge\LowScoringRecaptchaProvider;
use Kanopi\Firewall\Tests\Challenge\UnreachableRecaptchaProvider;
use Kanopi\Firewall\Tests\Challenge\UnreachableTurnstileProvider;
use Kanopi\Firewall\Traits\FileTrait;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * End-to-end coverage for the `response: challenge` flow.
 *
 * Walks the full lifecycle: a matching plugin triggers an interstitial,
 * the visitor submits the (correct) answer, the firewall mints a pass
 * token, and the next request bearing that token sails through.
 */
class ChallengeFlowTest extends TestCase
{
    use FileTrait;

    private string $tempDir;

    private const SECRET = 'integration-test-secret-value';

    /**
     * Google's documented always-passes reCAPTCHA v2 test pair.
     */
    private const RECAPTCHA_SITE_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';

    private const RECAPTCHA_SECRET_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

    protected function setUp(): void
    {
        parent::setUp();
        putenv('FIREWALL_BYPASS_CLI=1');

        $this->tempDir = sys_get_temp_dir() . '/firewall_challenge_' . uniqid();
        if (!mkdir($this->tempDir, 0777, true)) {
            throw new \RuntimeException('Failed to create temp directory: ' . $this->tempDir);
        }
    }

    protected function tearDown(): void
    {
        $this->recursiveRemoveDirectory($this->tempDir);
        parent::tearDown();
    }

    public function testMatchedChallengePluginThrowsRequired(): void
    {
        $firewall = Firewall::create([$this->configWithChallenge()]);

        $request = $this->blockedRequest('10.0.0.50', '/protected');

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($request);
    }

    public function testSubmissionWithCorrectAnswerMintsToken(): void
    {
        $firewall = Firewall::create([$this->configWithChallenge()]);

        [$state, $answer] = $this->generateSolvedState($firewall, '10.0.0.50');

        $request = Request::create(
            '/_firewall/challenge',
            'POST',
            [
                MathChallengeProvider::STATE_FIELD => $state,
                MathChallengeProvider::ANSWER_FIELD => $answer,
                MathChallengeProvider::REDIRECT_FIELD => '/protected',
                MathChallengeProvider::TTL_FIELD => '600',
            ],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.50']
        );

        try {
            $firewall->evaluate($request);
            $this->fail('Expected ChallengeSolvedException');
        } catch (ChallengeSolvedException $e) {
            $this->assertNotEmpty($e->getToken());
            $this->assertSame('/protected', $e->getRedirect());
        }
    }

    public function testSubmissionWithWrongAnswerThrowsChallengeRequired(): void
    {
        $firewall = Firewall::create([$this->configWithChallenge()]);

        [$state, $answer] = $this->generateSolvedState($firewall, '10.0.0.50');
        $wrong = (string) ((int) $answer + 1);

        $request = Request::create(
            '/_firewall/challenge',
            'POST',
            [
                MathChallengeProvider::STATE_FIELD => $state,
                MathChallengeProvider::ANSWER_FIELD => $wrong,
            ],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.50']
        );

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($request);
    }

    public function testBlockedIpCannotMintATokenViaSubmission(): void
    {
        $firewall = Firewall::create([$this->configWithChallenge()]);

        [$state, $answer] = $this->generateSolvedState($firewall, '10.0.0.50');

        // Durable repeat-offender state: this IP already earned a block.
        $storageRef = new \ReflectionProperty($firewall, 'storage');
        $storage = $storageRef->getValue($firewall);
        $storage->set('10.0.0.50', ['event_id' => 'PRIOR-OFFENSE'], time() + 3600);

        $request = Request::create(
            '/_firewall/challenge',
            'POST',
            [
                MathChallengeProvider::STATE_FIELD => $state,
                MathChallengeProvider::ANSWER_FIELD => $answer,
                MathChallengeProvider::REDIRECT_FIELD => '/protected',
                MathChallengeProvider::TTL_FIELD => '600',
            ],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.50']
        );

        $this->expectException(FirewallBlockedException::class);
        $firewall->evaluate($request);
    }

    public function testValidTokenInCookieAllowsRequest(): void
    {
        $firewall = Firewall::create([$this->configWithChallenge()]);

        $token = $this->mintTokenViaSolution($firewall, '10.0.0.50');

        $request = Request::create(
            '/protected',
            'GET',
            [],
            ['fw_challenge_pass' => $token],
            [],
            ['REMOTE_ADDR' => '10.0.0.50']
        );

        $this->assertTrue($firewall->evaluate($request));
    }

    public function testCustomCookieNameIsHonoured(): void
    {
        // `challenge.cookie_name` is operator-configurable; the firewall
        // must both write and read the pass token under that name, and
        // must not silently fall back to the default.
        $configFile = $this->writeConfig([
            'global' => ['mode' => 'exception'],
            'challenge' => [
                'provider' => 'math',
                'secret' => self::SECRET,
                'cookie_name' => 'my_custom_pass_cookie',
                'header_name' => 'X-Firewall-Challenge',
                'path' => '/_firewall/challenge',
            ],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'challenge',
                    'weight' => 0,
                    'enable' => true,
                    'metadata' => ['default_expiration_time' => 600],
                    'config' => ['10.0.0.50'],
                ],
            ],
        ], 'custom_cookie.yml');

        $firewall = Firewall::create([$configFile]);
        $token = $this->mintTokenViaSolution($firewall, '10.0.0.50');

        $underCustomName = Request::create(
            '/protected',
            'GET',
            [],
            ['my_custom_pass_cookie' => $token],
            [],
            ['REMOTE_ADDR' => '10.0.0.50']
        );
        $this->assertTrue($firewall->evaluate($underCustomName));

        // The default name must carry no weight once one is configured.
        $underDefaultName = Request::create(
            '/protected',
            'GET',
            [],
            ['fw_challenge_pass' => $token],
            [],
            ['REMOTE_ADDR' => '10.0.0.50']
        );

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($underDefaultName);
    }

    public function testEmptyCookieNameDisablesTheCookiePath(): void
    {
        // Documented as the way to turn off cookie delivery and rely on
        // the localStorage/header path only.
        $configFile = $this->writeConfig([
            'global' => ['mode' => 'exception'],
            'challenge' => [
                'provider' => 'math',
                'secret' => self::SECRET,
                'cookie_name' => '',
                'header_name' => 'X-Firewall-Challenge',
                'path' => '/_firewall/challenge',
            ],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'challenge',
                    'weight' => 0,
                    'enable' => true,
                    'metadata' => ['default_expiration_time' => 600],
                    'config' => ['10.0.0.50'],
                ],
            ],
        ], 'no_cookie.yml');

        $firewall = Firewall::create([$configFile]);
        $token = $this->mintTokenViaSolution($firewall, '10.0.0.50');

        // No cookie name configured, so no cookie is consulted...
        $viaCookie = Request::create(
            '/protected',
            'GET',
            [],
            ['fw_challenge_pass' => $token],
            [],
            ['REMOTE_ADDR' => '10.0.0.50']
        );

        // ...but the header delivery path still works.
        $viaHeader = Request::create(
            '/protected',
            'GET',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.50', 'HTTP_X_FIREWALL_CHALLENGE' => $token]
        );
        $this->assertTrue($firewall->evaluate($viaHeader));

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($viaCookie);
    }

    public function testValidTokenInHeaderAllowsRequest(): void
    {
        $firewall = Firewall::create([$this->configWithChallenge()]);

        $token = $this->mintTokenViaSolution($firewall, '10.0.0.50');

        $request = Request::create(
            '/protected',
            'GET',
            [],
            [],
            [],
            [
                'REMOTE_ADDR' => '10.0.0.50',
                'HTTP_X_FIREWALL_CHALLENGE' => $token,
            ]
        );

        $this->assertTrue($firewall->evaluate($request));
    }

    public function testTokenFromDifferentIpIsRejected(): void
    {
        // Use a CIDR so two distinct IPs both fall inside the challenge
        // plugin's scope — otherwise the second IP wouldn't be challenged
        // even without a token, masking the IP-binding behaviour.
        $configFile = $this->writeConfig([
            'global' => ['mode' => 'exception'],
            'challenge' => [
                'provider' => 'math',
                'secret' => self::SECRET,
                'cookie_name' => 'fw_challenge_pass',
                'header_name' => 'X-Firewall-Challenge',
                'path' => '/_firewall/challenge',
            ],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'challenge',
                    'weight' => 0,
                    'enable' => true,
                    'metadata' => ['default_expiration_time' => 600],
                    'config' => ['10.0.0.0/24'],
                ],
            ],
        ], 'cidr_challenge.yml');

        $firewall = Firewall::create([$configFile]);

        $token = $this->mintTokenViaSolution($firewall, '10.0.0.50');

        // Same token presented by a different client IP — token binding
        // fails, plugin still applies → challenge fires again.
        $request = Request::create(
            '/protected',
            'GET',
            [],
            ['fw_challenge_pass' => $token],
            [],
            ['REMOTE_ADDR' => '10.0.0.99']
        );

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($request);
    }

    public function testTamperedTokenIsRejected(): void
    {
        $firewall = Firewall::create([$this->configWithChallenge()]);

        $token = $this->mintTokenViaSolution($firewall, '10.0.0.50');
        // Replace the first signature character with a guaranteed-different
        // one; using strtr() would be flaky when the random base64url
        // signature happens to contain none of the target characters.
        [$payload, $signature] = explode('.', $token, 2);
        $replacement = $signature[0] === 'A' ? 'B' : 'A';
        $tampered = $payload . '.' . $replacement . substr($signature, 1);

        $request = Request::create(
            '/protected',
            'GET',
            [],
            ['fw_challenge_pass' => $tampered],
            [],
            ['REMOTE_ADDR' => '10.0.0.50']
        );

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($request);
    }

    public function testUnrelatedIpIsNotChallenged(): void
    {
        $firewall = Firewall::create([$this->configWithChallenge()]);

        $request = Request::create(
            '/protected',
            'GET',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '8.8.8.8']
        );

        $this->assertTrue($firewall->evaluate($request));
    }

    /**
     * A crafted array field is a rejected submission, not a 500 (#130).
     *
     * `InputBag::get()` throws BadRequestException on a non-scalar and
     * nothing between here and the host application catches it, so before the
     * fix one unauthenticated POST to any route serving `response: challenge`
     * produced an uncaught exception and a stack trace — repeatable at
     * whatever volume the caller cared to generate.
     */
    public function testArrayValuedSolutionFieldIsRejectedNotFatal(): void
    {
        $firewall = Firewall::create([$this->configWithChallenge()]);

        $request = Request::create(
            '/_firewall/challenge',
            'POST',
            [
                MathChallengeProvider::STATE_FIELD => ['x'],
                MathChallengeProvider::ANSWER_FIELD => ['7'],
                MathChallengeProvider::REDIRECT_FIELD => '/protected',
                MathChallengeProvider::TTL_FIELD => '600',
            ],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.50']
        );

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($request);
    }

    /**
     * The firewall reads `ttl` and `redirect_to` itself, outside any provider,
     * and they arrive on the same attacker-chosen POST (#130). Array values
     * fall back to the defaults rather than throwing — and the fallback
     * redirect is the site root, which is where sanitizeRedirect() sends
     * anything off-site anyway.
     */
    public function testArrayValuedTtlAndRedirectFallBackToDefaults(): void
    {
        $firewall = Firewall::create([$this->configWithChallenge()]);

        [$state, $answer] = $this->generateSolvedState($firewall, '10.0.0.50');

        $request = Request::create(
            '/_firewall/challenge',
            'POST',
            [
                MathChallengeProvider::STATE_FIELD => $state,
                MathChallengeProvider::ANSWER_FIELD => $answer,
                MathChallengeProvider::REDIRECT_FIELD => ['/protected'],
                MathChallengeProvider::TTL_FIELD => ['600'],
            ],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.50']
        );

        try {
            $firewall->evaluate($request);
            $this->fail('Expected ChallengeSolvedException');
        } catch (ChallengeSolvedException $e) {
            $this->assertNotEmpty($e->getToken());
            $this->assertSame('/', $e->getRedirect());
        }
    }

    public function testMissingSecretWithChallengePluginsThrowsAtStartup(): void
    {
        $configFile = $this->writeConfig([
            'global' => ['mode' => 'exception'],
            'challenge' => [
                'provider' => 'math',
                'secret' => '',
            ],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'challenge',
                    'weight' => 0,
                    'enable' => true,
                    'config' => ['10.0.0.50'],
                ],
            ],
        ]);

        $this->expectException(ConfigurationException::class);
        Firewall::create([$configFile]);
    }

    public function testNoChallengeConfigSkipsFeatureEntirely(): void
    {
        // Config with no challenge plugins — challenge feature should be dormant,
        // and the magic-path POST should fall through to whatever rules exist
        // (here: nothing, so it's allowed).
        $configFile = $this->writeConfig([
            'global' => ['mode' => 'exception'],
            'plugins' => [],
        ]);

        $firewall = Firewall::create([$configFile]);
        $request = Request::create('/_firewall/challenge', 'POST', [], [], [], [
            'REMOTE_ADDR' => '10.0.0.50',
        ]);

        $this->assertTrue($firewall->evaluate($request));
    }

    /**
     * Build a configuration with a challenge plugin that matches a single IP.
     */
    private function configWithChallenge(): string
    {
        return $this->writeConfig([
            'global' => ['mode' => 'exception'],
            'challenge' => [
                'provider' => 'math',
                'secret' => self::SECRET,
                'cookie_name' => 'fw_challenge_pass',
                'header_name' => 'X-Firewall-Challenge',
                'path' => '/_firewall/challenge',
            ],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'challenge',
                    'weight' => 0,
                    'enable' => true,
                    'metadata' => ['default_expiration_time' => 600],
                    'config' => ['10.0.0.50'],
                ],
            ],
        ]);
    }

    /**
     * Build a request that the configured challenge plugin will match.
     */
    private function blockedRequest(string $ip, string $path = '/'): Request
    {
        return Request::create($path, 'GET', [], [], [], ['REMOTE_ADDR' => $ip]);
    }

    /**
     * Drive the firewall through one full challenge cycle and return the
     * minted pass token.
     */
    private function mintTokenViaSolution(Firewall $firewall, string $ip): string
    {
        [$state, $answer] = $this->generateSolvedState($firewall, $ip);

        $request = Request::create(
            '/_firewall/challenge',
            'POST',
            [
                MathChallengeProvider::STATE_FIELD => $state,
                MathChallengeProvider::ANSWER_FIELD => $answer,
                MathChallengeProvider::REDIRECT_FIELD => '/protected',
                MathChallengeProvider::TTL_FIELD => '600',
            ],
            [],
            [],
            ['REMOTE_ADDR' => $ip]
        );

        try {
            $firewall->evaluate($request);
            $this->fail('Expected ChallengeSolvedException to fire on valid solution');
        } catch (ChallengeSolvedException $e) {
            return $e->getToken();
        }

        return ''; // Unreachable.
    }

    /**
     * Render the interstitial via reflection into the provider and pull out
     * the signed state + correct answer. Avoids parsing the HTML twice.
     *
     * @return array{0: string, 1: string}
     */
    private function generateSolvedState(Firewall $firewall, string $ip): array
    {
        $providerRef = new \ReflectionProperty($firewall, 'challengeProvider');
        $provider = $providerRef->getValue($firewall);
        $this->assertInstanceOf(MathChallengeProvider::class, $provider);

        $html = $provider->renderInterstitial(
            Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $ip]),
            [
                'submit_url' => '/_firewall/challenge',
                'redirect_to' => '/protected',
                'ttl' => '600',
                'cookie_name' => 'fw_challenge_pass',
                'header_name' => 'X-Firewall-Challenge',
            ]
        );

        $stateField = MathChallengeProvider::STATE_FIELD;
        preg_match('/name="' . preg_quote($stateField, '/') . '" value="([^"]+)"/', $html, $stateMatch);
        $this->assertNotEmpty($stateMatch, 'state hidden input missing');
        $state = $stateMatch[1];

        [$data, ] = explode('.', $state, 2);
        [$answer, ] = explode('|', $data, 2);

        return [$state, $answer];
    }

    /**
     * @param array<string, mixed> $config
     */
    private function writeConfig(array $config, string $filename = 'challenge_config.yml'): string
    {
        $file = $this->tempDir . '/' . $filename;
        if (file_put_contents($file, Yaml::dump($config, 6, 2)) === false) {
            throw new \RuntimeException('Failed to write config: ' . $file);
        }
        return $file;
    }

    private function recursiveRemoveDirectory(string $directory): void
    {
        if (!is_dir($directory)) {
            return;
        }
        $files = array_diff(scandir($directory), ['.', '..']);
        foreach ($files as $file) {
            $path = $directory . '/' . $file;
            if (is_dir($path)) {
                $this->recursiveRemoveDirectory($path);
            } else {
                unlink($path);
            }
        }
        rmdir($directory);
    }

    // -------------------------------------------------------------------
    // ALTCHA single-use solutions
    // -------------------------------------------------------------------

    public function testAltchaSolutionMintsATokenOnFirstSubmission(): void
    {
        $firewall = Firewall::create([$this->configWithAltchaChallenge()]);
        $payload = $this->solveAltcha($firewall, '10.0.0.50');

        try {
            $firewall->evaluate($this->altchaSubmission($payload, '10.0.0.50'));
            $this->fail('Expected ChallengeSolvedException');
        } catch (ChallengeSolvedException $e) {
            $this->assertNotEmpty($e->getToken());
        }
    }

    public function testAltchaSolutionCannotBeReplayed(): void
    {
        $config = $this->configWithAltchaChallenge();
        $firewall = Firewall::create([$config]);
        $payload = $this->solveAltcha($firewall, '10.0.0.50');

        // First submission spends the solution.
        try {
            $firewall->evaluate($this->altchaSubmission($payload, '10.0.0.50'));
            $this->fail('Expected ChallengeSolvedException on first submission');
        } catch (ChallengeSolvedException) {
            // Expected.
        }

        // Re-posting the identical payload must now be refused.
        $this->expectException(ChallengeRequiredException::class);
        Firewall::create([$config])->evaluate($this->altchaSubmission($payload, '10.0.0.50'));
    }

    public function testAltchaSolutionCannotBeRedistributedToOtherClients(): void
    {
        // The attack this closes: solve once, hand the payload to a fleet,
        // each client mints a pass token bound to its own IP.
        $config = $this->configWithAltchaChallenge();
        $payload = $this->solveAltcha(Firewall::create([$config]), '10.0.0.50');

        try {
            Firewall::create([$config])->evaluate($this->altchaSubmission($payload, '10.0.0.50'));
            $this->fail('Expected ChallengeSolvedException on first submission');
        } catch (ChallengeSolvedException) {
            // Expected.
        }

        foreach (['203.0.113.5', '198.51.100.9', '192.0.2.44'] as $ip) {
            try {
                Firewall::create([$config])->evaluate($this->altchaSubmission($payload, $ip));
                $this->fail('Replay from ' . $ip . ' was accepted');
            } catch (ChallengeRequiredException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testDistinctAltchaSolutionsAreEachAccepted(): void
    {
        // Burning one solution must not lock out unrelated visitors.
        $config = $this->configWithAltchaChallenge();

        foreach (['10.0.0.50', '10.0.0.50', '10.0.0.50'] as $ip) {
            $firewall = Firewall::create([$config]);
            $payload = $this->solveAltcha($firewall, $ip);

            try {
                $firewall->evaluate($this->altchaSubmission($payload, $ip));
                $this->fail('Expected ChallengeSolvedException');
            } catch (ChallengeSolvedException $e) {
                $this->assertNotEmpty($e->getToken());
            }
        }
    }

    /**
     * `altcha[]=x` is a rejected submission, not an uncaught exception (#130).
     *
     * Worth asserting through the firewall as well as at the provider: the
     * ALTCHA payload is read twice per submission — once by
     * `verifySolution()` and once by `getSolutionReceipt()` on the
     * single-use path — and only the full flow exercises both.
     */
    public function testArrayValuedAltchaPayloadIsRejectedNotFatal(): void
    {
        $firewall = Firewall::create([$this->configWithAltchaChallenge()]);

        $request = Request::create(
            '/_firewall/challenge',
            'POST',
            [
                AltchaChallengeProvider::PAYLOAD_FIELD => ['x'],
                AltchaChallengeProvider::REDIRECT_FIELD => '/protected',
                AltchaChallengeProvider::TTL_FIELD => '600',
            ],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.50']
        );

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($request);
    }

    /**
     * Config using the ALTCHA provider and a file-backed store, so
     * consumed-solution records survive across Firewall instances the way
     * they do across requests in production.
     */
    private function configWithAltchaChallenge(): string
    {
        return $this->writeConfig([
            'global' => ['mode' => 'exception'],
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\FileStorage',
                'config' => ['storage_file' => $this->tempDir . '/altcha-storage.data'],
            ],
            'challenge' => [
                'provider' => 'altcha',
                'secret' => self::SECRET,
                'cookie_name' => 'fw_challenge_altcha_pass',
                'header_name' => 'X-Firewall-Challenge-Altcha',
                'path' => '/_firewall/challenge',
            ],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\Url',
                    'response' => 'challenge',
                    'weight' => 0,
                    'enable' => true,
                    'metadata' => ['default_expiration_time' => 600],
                    'config' => ['path@starts_with:/protected'],
                ],
            ],
        ], 'altcha_config.yml');
    }

    /**
     * Render an ALTCHA interstitial, brute-force the embedded challenge,
     * and return the base64 payload the widget would post back.
     */
    private function solveAltcha(Firewall $firewall, string $ip): string
    {
        $providerRef = new \ReflectionProperty($firewall, 'challengeProvider');
        $provider = $providerRef->getValue($firewall);
        $this->assertInstanceOf(AltchaChallengeProvider::class, $provider);

        $html = $provider->renderInterstitial(
            Request::create('/protected', 'GET', [], [], [], ['REMOTE_ADDR' => $ip]),
            [
                'submit_url' => '/_firewall/challenge',
                'redirect_to' => '/protected',
                'ttl' => '600',
                'header_name' => 'X-Firewall-Challenge-Altcha',
            ]
        );

        $this->assertSame(1, preg_match('/challengejson="([^"]+)"/', $html, $m));
        $challenge = json_decode(html_entity_decode($m[1], ENT_QUOTES, 'UTF-8'), true);
        $this->assertIsArray($challenge);

        $number = null;
        for ($i = 0; $i <= (int) $challenge['maxnumber']; $i++) {
            if (hash('sha256', $challenge['salt'] . $i) === $challenge['challenge']) {
                $number = $i;
                break;
            }
        }
        $this->assertNotNull($number, 'Could not solve the ALTCHA challenge');

        return base64_encode((string) json_encode([
            'algorithm' => $challenge['algorithm'],
            'challenge' => $challenge['challenge'],
            'number' => $number,
            'salt' => $challenge['salt'],
            'signature' => $challenge['signature'],
        ]));
    }

    private function altchaSubmission(string $payload, string $ip): Request
    {
        return Request::create(
            '/_firewall/challenge',
            'POST',
            [
                AltchaChallengeProvider::PAYLOAD_FIELD => $payload,
                AltchaChallengeProvider::REDIRECT_FIELD => '/protected',
                AltchaChallengeProvider::TTL_FIELD => '600',
            ],
            [],
            [],
            ['REMOTE_ADDR' => $ip]
        );
    }

    // -------------------------------------------------------------------
    // Turnstile
    // -------------------------------------------------------------------

    public function testTurnstileChallengePluginThrowsRequired(): void
    {
        $firewall = Firewall::create([$this->configWithTurnstileChallenge()]);

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($this->blockedRequest('10.0.0.50', '/protected'));
    }

    public function testTurnstileInterstitialCarriesTheWidgetAndTheRedirect(): void
    {
        $firewall = Firewall::create([$this->configWithTurnstileChallenge()]);
        $provider = $this->challengeProvider($firewall);

        $html = $provider->renderInterstitial(
            Request::create('/protected', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.50']),
            [
                'submit_url' => '/_firewall/challenge',
                'redirect_to' => '/protected',
                'ttl' => '600',
                'header_name' => 'X-Firewall-Challenge-Turnstile',
            ]
        );

        $this->assertStringContainsString('class="cf-turnstile"', $html);
        $this->assertStringContainsString('data-sitekey="1x00000000000000000000AA"', $html);
        $this->assertStringContainsString('value="/protected"', $html);
        $this->assertStringNotContainsString('1x0000000000000000000000000000000AA', $html);
    }

    public function testVerifiedTurnstileTokenMintsAPassToken(): void
    {
        $firewall = Firewall::create([$this->configWithTurnstileChallenge()]);

        try {
            $firewall->evaluate($this->turnstileSubmission('a-token-cloudflare-likes', '10.0.0.50'));
            $this->fail('Expected ChallengeSolvedException');
        } catch (ChallengeSolvedException $e) {
            $this->assertNotEmpty($e->getToken());
            $this->assertSame('/protected', $e->getRedirect());
        }
    }

    public function testTurnstilePassTokenAllowsTheNextRequest(): void
    {
        $config = $this->configWithTurnstileChallenge();
        $token = '';

        try {
            Firewall::create([$config])->evaluate(
                $this->turnstileSubmission('a-token-cloudflare-likes', '10.0.0.50')
            );
        } catch (ChallengeSolvedException $e) {
            $token = $e->getToken();
        }

        $this->assertNotEmpty($token);

        $request = Request::create('/protected', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.50']);
        $request->cookies->set('fw_challenge_turnstile_pass', $token);

        // No exception: the pass token short-circuits the challenge bucket.
        Firewall::create([$config])->evaluate($request);
        $this->addToAssertionCount(1);
    }

    public function testEmptyTurnstileTokenIsRefused(): void
    {
        $firewall = Firewall::create([$this->configWithTurnstileChallenge()]);

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($this->turnstileSubmission('', '10.0.0.50'));
    }

    public function testUnreachableSiteverifyRefusesTheSubmission(): void
    {
        // Fail closed: the default must not hand out a pass token when
        // Cloudflare's verdict could not be obtained.
        $firewall = Firewall::create([
            $this->configWithTurnstileChallenge(UnreachableTurnstileProvider::class, 'turnstile_down.yml'),
        ]);

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($this->turnstileSubmission('a-token-nobody-can-check', '10.0.0.50'));
    }

    public function testUnreachableSiteverifyMintsATokenWhenConfiguredToAllow(): void
    {
        $firewall = Firewall::create([
            $this->configWithTurnstileChallenge(
                UnreachableTurnstileProvider::class,
                'turnstile_down_allow.yml',
                ['on_error' => 'allow']
            ),
        ]);

        $this->expectException(ChallengeSolvedException::class);
        $firewall->evaluate($this->turnstileSubmission('a-token-nobody-can-check', '10.0.0.50'));
    }

    public function testTurnstileWithoutKeysFailsAtStartup(): void
    {
        $config = $this->writeConfig([
            'global' => ['mode' => 'exception'],
            'challenge' => [
                'provider' => 'turnstile',
                'secret' => self::SECRET,
                'path' => '/_firewall/challenge',
            ],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\Url',
                    'response' => 'challenge',
                    'weight' => 0,
                    'enable' => true,
                    'config' => ['path@starts_with:/protected'],
                ],
            ],
        ], 'turnstile_keyless.yml');

        $this->expectException(ConfigurationException::class);
        Firewall::create([$config]);
    }

    /**
     * Config using a Turnstile provider whose siteverify call is stubbed.
     *
     * @param class-string $provider
     *   Provider FQCN — a subclass standing in for one Cloudflare behaviour.
     * @param string $filename
     *   Config filename, unique per case so the files do not collide.
     * @param array<string, mixed> $extraOptions
     *   Extra `provider_options` merged over the dummy keys.
     */
    private function configWithTurnstileChallenge(
        string $provider = AlwaysVerifyingTurnstileProvider::class,
        string $filename = 'turnstile_config.yml',
        array $extraOptions = []
    ): string {
        return $this->writeConfig([
            'global' => ['mode' => 'exception'],
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\FileStorage',
                'config' => ['storage_file' => $this->tempDir . '/turnstile-storage.data'],
            ],
            'challenge' => [
                'provider' => $provider,
                'secret' => self::SECRET,
                'cookie_name' => 'fw_challenge_turnstile_pass',
                'header_name' => 'X-Firewall-Challenge-Turnstile',
                'path' => '/_firewall/challenge',
                'provider_options' => $extraOptions + [
                    // Cloudflare's documented always-passes test pair.
                    'site_key' => '1x00000000000000000000AA',
                    'secret_key' => '1x0000000000000000000000000000000AA',
                ],
            ],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\Url',
                    'response' => 'challenge',
                    'weight' => 0,
                    'enable' => true,
                    'metadata' => ['default_expiration_time' => 600],
                    'config' => ['path@starts_with:/protected'],
                ],
            ],
        ], $filename);
    }

    /**
     * Reach the provider the Firewall built from config.
     */
    private function challengeProvider(Firewall $firewall): TurnstileChallengeProvider
    {
        $provider = (new \ReflectionProperty($firewall, 'challengeProvider'))->getValue($firewall);
        $this->assertInstanceOf(TurnstileChallengeProvider::class, $provider);

        return $provider;
    }

    private function turnstileSubmission(string $token, string $ip): Request
    {
        return Request::create(
            '/_firewall/challenge',
            'POST',
            [
                TurnstileChallengeProvider::PAYLOAD_FIELD => $token,
                TurnstileChallengeProvider::REDIRECT_FIELD => '/protected',
                TurnstileChallengeProvider::TTL_FIELD => '600',
            ],
            [],
            [],
            ['REMOTE_ADDR' => $ip]
        );
    }

    // -------------------------------------------------------------------
    // reCAPTCHA
    // -------------------------------------------------------------------

    public function testRecaptchaChallengePluginThrowsRequired(): void
    {
        $firewall = Firewall::create([$this->configWithRecaptchaChallenge()]);

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($this->blockedRequest('10.0.0.60', '/protected'));
    }

    public function testRecaptchaInterstitialCarriesTheWidgetAndTheRedirect(): void
    {
        $firewall = Firewall::create([$this->configWithRecaptchaChallenge()]);
        $provider = $this->recaptchaProvider($firewall);

        $html = $provider->renderInterstitial(
            Request::create('/protected', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.60']),
            [
                'submit_url' => '/_firewall/challenge',
                'redirect_to' => '/protected',
                'ttl' => '600',
                'header_name' => 'X-Firewall-Challenge-Recaptcha',
            ]
        );

        $this->assertStringContainsString('class="g-recaptcha"', $html);
        $this->assertStringContainsString('data-sitekey="' . self::RECAPTCHA_SITE_KEY . '"', $html);
        $this->assertStringContainsString('value="/protected"', $html);
        $this->assertStringNotContainsString(self::RECAPTCHA_SECRET_KEY, $html);
    }

    public function testVerifiedRecaptchaTokenMintsAPassToken(): void
    {
        $firewall = Firewall::create([$this->configWithRecaptchaChallenge()]);

        try {
            $firewall->evaluate($this->recaptchaSubmission('a-token-google-likes', '10.0.0.60'));
            $this->fail('Expected ChallengeSolvedException');
        } catch (ChallengeSolvedException $e) {
            $this->assertNotEmpty($e->getToken());
            $this->assertSame('/protected', $e->getRedirect());
        }
    }

    public function testRecaptchaPassTokenAllowsTheNextRequest(): void
    {
        $config = $this->configWithRecaptchaChallenge();
        $token = '';

        try {
            Firewall::create([$config])->evaluate(
                $this->recaptchaSubmission('a-token-google-likes', '10.0.0.60')
            );
        } catch (ChallengeSolvedException $e) {
            $token = $e->getToken();
        }

        $this->assertNotEmpty($token);

        $request = Request::create('/protected', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.60']);
        $request->cookies->set('fw_challenge_recaptcha_pass', $token);

        // No exception: the pass token short-circuits the challenge bucket.
        Firewall::create([$config])->evaluate($request);
        $this->addToAssertionCount(1);
    }

    public function testEmptyRecaptchaTokenIsRefused(): void
    {
        $firewall = Firewall::create([$this->configWithRecaptchaChallenge()]);

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($this->recaptchaSubmission('', '10.0.0.60'));
    }

    public function testUnreachableRecaptchaSiteverifyRefusesTheSubmission(): void
    {
        // Fail closed: the default must not hand out a pass token when
        // Google's verdict could not be obtained.
        $firewall = Firewall::create([
            $this->configWithRecaptchaChallenge(
                UnreachableRecaptchaProvider::class,
                'recaptcha_down.yml'
            ),
        ]);

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($this->recaptchaSubmission('a-token-nobody-can-check', '10.0.0.60'));
    }

    public function testUnreachableRecaptchaMintsATokenWhenConfiguredToAllow(): void
    {
        $firewall = Firewall::create([
            $this->configWithRecaptchaChallenge(
                UnreachableRecaptchaProvider::class,
                'recaptcha_down_allow.yml',
                ['on_error' => 'allow']
            ),
        ]);

        $this->expectException(ChallengeSolvedException::class);
        $firewall->evaluate($this->recaptchaSubmission('a-token-nobody-can-check', '10.0.0.60'));
    }

    public function testRecaptchaWithoutKeysFailsAtStartup(): void
    {
        $config = $this->writeConfig([
            'global' => ['mode' => 'exception'],
            'challenge' => [
                'provider' => 'recaptcha',
                'secret' => self::SECRET,
                'path' => '/_firewall/challenge',
            ],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\Url',
                    'response' => 'challenge',
                    'weight' => 0,
                    'enable' => true,
                    'config' => ['path@starts_with:/protected'],
                ],
            ],
        ], 'recaptcha_keyless.yml');

        $this->expectException(ConfigurationException::class);
        Firewall::create([$config]);
    }

    public function testVerifiedV3TokenMintsAPassToken(): void
    {
        $firewall = Firewall::create([
            $this->configWithRecaptchaChallenge(
                AlwaysVerifyingRecaptchaProvider::class,
                'recaptcha_v3.yml',
                ['version' => 'v3']
            ),
        ]);

        $this->expectException(ChallengeSolvedException::class);
        $firewall->evaluate($this->recaptchaV3Submission('a-token-google-likes', '10.0.0.60'));
    }

    public function testLowScoringV3TokenIsRefusedDespiteGooglesYes(): void
    {
        // The case unique to v3: siteverify was reachable and the token was
        // genuine, and the visitor is still refused — by the threshold, not
        // by Google. That has to arrive as a failed challenge, not a pass.
        $firewall = Firewall::create([
            $this->configWithRecaptchaChallenge(
                LowScoringRecaptchaProvider::class,
                'recaptcha_v3_low.yml',
                ['version' => 'v3', 'min_score' => 0.5]
            ),
        ]);

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($this->recaptchaV3Submission('a-token-google-likes', '10.0.0.60'));
    }

    public function testV3TokenPostedUnderTheV2FieldIsRefused(): void
    {
        // v3 reads its own field precisely so api.js's injected
        // `g-recaptcha-response` textarea cannot be what gets verified.
        $firewall = Firewall::create([
            $this->configWithRecaptchaChallenge(
                AlwaysVerifyingRecaptchaProvider::class,
                'recaptcha_v3_wrong_field.yml',
                ['version' => 'v3']
            ),
        ]);

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($this->recaptchaSubmission('a-token-google-likes', '10.0.0.60'));
    }

    public function testExplicitAudienceKeepsAV3PassOutOfAV2Route(): void
    {
        // A v3 pass is the weaker claim — the visitor cleared a score, not a
        // checkbox — so it must not open a v2-protected route. The `aud`
        // claim is built from the `challenge.provider` config string, which
        // is identical for both versions, so the separation has to be
        // configured rather than inferred. This is the documented fix.
        $v3Config = $this->configWithRecaptchaChallenge(
            AlwaysVerifyingRecaptchaProvider::class,
            'recaptcha_v3_audience.yml',
            ['version' => 'v3'],
            'recaptcha-v3'
        );
        $token = '';

        try {
            Firewall::create([$v3Config])->evaluate(
                $this->recaptchaV3Submission('a-token-google-likes', '10.0.0.60')
            );
        } catch (ChallengeSolvedException $e) {
            $token = $e->getToken();
        }

        $this->assertNotEmpty($token);

        $request = Request::create('/protected', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.60']);
        $request->cookies->set('fw_challenge_recaptcha_pass', $token);

        $this->expectException(ChallengeRequiredException::class);
        Firewall::create([$this->configWithRecaptchaChallenge()])->evaluate($request);
    }

    public function testWithoutAnExplicitAudienceAV3PassOpensAV2Route(): void
    {
        // The sharp edge the test above configures around, asserted so it
        // stays a known and documented limitation rather than a surprise.
        // `getName()` being version-scoped does NOT change this: the
        // audience comes from the config string, before any provider exists.
        $v3Config = $this->configWithRecaptchaChallenge(
            AlwaysVerifyingRecaptchaProvider::class,
            'recaptcha_v3_shared_audience.yml',
            ['version' => 'v3']
        );
        $token = '';

        try {
            Firewall::create([$v3Config])->evaluate(
                $this->recaptchaV3Submission('a-token-google-likes', '10.0.0.60')
            );
        } catch (ChallengeSolvedException $e) {
            $token = $e->getToken();
        }

        $request = Request::create('/protected', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.60']);
        $request->cookies->set('fw_challenge_recaptcha_pass', $token);

        // No exception: the two instances share an audience.
        Firewall::create([$this->configWithRecaptchaChallenge()])->evaluate($request);
        $this->addToAssertionCount(1);
    }

    /**
     * Config using a reCAPTCHA provider whose siteverify call is stubbed.
     *
     * @param class-string $provider
     *   Provider FQCN — a subclass standing in for one Google behaviour.
     * @param string $filename
     *   Config filename, unique per case so the files do not collide.
     * @param array<string, mixed> $extraOptions
     *   Extra `provider_options` merged over the test keys.
     * @param string $audience
     *   `challenge.audience`. Empty means the default, which is the
     *   `provider` config string and therefore shared across versions.
     */
    private function configWithRecaptchaChallenge(
        string $provider = AlwaysVerifyingRecaptchaProvider::class,
        string $filename = 'recaptcha_config.yml',
        array $extraOptions = [],
        string $audience = ''
    ): string {
        return $this->writeConfig([
            'global' => ['mode' => 'exception'],
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\FileStorage',
                'config' => ['storage_file' => $this->tempDir . '/recaptcha-storage.data'],
            ],
            'challenge' => [
                'provider' => $provider,
                'secret' => self::SECRET,
                'cookie_name' => 'fw_challenge_recaptcha_pass',
                'header_name' => 'X-Firewall-Challenge-Recaptcha',
                'path' => '/_firewall/challenge',
                'audience' => $audience,
                'provider_options' => $extraOptions + [
                    'site_key' => self::RECAPTCHA_SITE_KEY,
                    'secret_key' => self::RECAPTCHA_SECRET_KEY,
                ],
            ],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\Url',
                    'response' => 'challenge',
                    'weight' => 0,
                    'enable' => true,
                    'metadata' => ['default_expiration_time' => 600],
                    'config' => ['path@starts_with:/protected'],
                ],
            ],
        ], $filename);
    }

    /**
     * Reach the provider the Firewall built from config.
     */
    private function recaptchaProvider(Firewall $firewall): RecaptchaChallengeProvider
    {
        $provider = (new \ReflectionProperty($firewall, 'challengeProvider'))->getValue($firewall);
        $this->assertInstanceOf(RecaptchaChallengeProvider::class, $provider);

        return $provider;
    }

    private function recaptchaSubmission(string $token, string $ip): Request
    {
        return $this->recaptchaPost(RecaptchaChallengeProvider::PAYLOAD_FIELD, $token, $ip);
    }

    private function recaptchaV3Submission(string $token, string $ip): Request
    {
        return $this->recaptchaPost(RecaptchaChallengeProvider::V3_PAYLOAD_FIELD, $token, $ip);
    }

    private function recaptchaPost(string $field, string $token, string $ip): Request
    {
        return Request::create(
            '/_firewall/challenge',
            'POST',
            [
                $field => $token,
                RecaptchaChallengeProvider::REDIRECT_FIELD => '/protected',
                RecaptchaChallengeProvider::TTL_FIELD => '600',
            ],
            [],
            [],
            ['REMOTE_ADDR' => $ip]
        );
    }
}
