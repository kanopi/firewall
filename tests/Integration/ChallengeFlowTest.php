<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration;

use Kanopi\Firewall\Challenge\AltchaChallengeProvider;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Firewall;
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
}
