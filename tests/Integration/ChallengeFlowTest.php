<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration;

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
        // Flip a character in the signature portion.
        [$payload, $signature] = explode('.', $token, 2);
        $tampered = $payload . '.' . strtr($signature, ['A' => 'B', 'a' => 'b', '0' => '1']);

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
}
