<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration;

use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Challenge\ChallengeProviderRegistry;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\RecaptchaChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Challenge\AlwaysVerifyingRecaptchaProvider;
use Kanopi\Firewall\Tests\Plugins\CountingChallengePlugin;
use Kanopi\Firewall\Traits\FileTrait;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * End-to-end coverage for per-plugin challenge providers.
 *
 * One firewall, two challenge rules, two different providers: `/protected`
 * gets the cheap math question, `/admin` gets reCAPTCHA. What these tests
 * pin down is that the two stay separate in both directions — the right
 * interstitial goes out, the right verifier reads the solution back, and a
 * pass earned on one is worth nothing on the other.
 *
 * The reCAPTCHA half uses `AlwaysVerifyingRecaptchaProvider`, which is the
 * real provider with Google's siteverify replaced by a standing "yes", so
 * nothing here touches the network.
 */
class PerPluginChallengeProviderTest extends TestCase
{
    use FileTrait;

    private string $tempDir;

    private const SECRET = 'per-plugin-provider-test-secret';

    /**
     * Google's documented always-passes reCAPTCHA v2 test pair.
     */
    private const RECAPTCHA_SITE_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';

    private const RECAPTCHA_SECRET_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

    /**
     * The `challenge_provider` value the reCAPTCHA rule names.
     */
    private const RECAPTCHA_PROVIDER = AlwaysVerifyingRecaptchaProvider::class;

    protected function setUp(): void
    {
        parent::setUp();
        putenv('FIREWALL_BYPASS_CLI=1');

        $this->tempDir = sys_get_temp_dir() . '/firewall_per_plugin_' . uniqid();
        if (!mkdir($this->tempDir, 0777, true)) {
            throw new \RuntimeException('Failed to create temp directory: ' . $this->tempDir);
        }
    }

    protected function tearDown(): void
    {
        $this->recursiveRemoveDirectory($this->tempDir);
        parent::tearDown();
    }

    // -------------------------------------------------------------------
    // Which provider serves which rule
    // -------------------------------------------------------------------

    public function testEachRuleIsServedByItsOwnProvider(): void
    {
        $firewall = Firewall::create([$this->config()]);
        $registry = $this->registry($firewall);

        $this->assertInstanceOf(MathChallengeProvider::class, $registry->get('math'));
        $this->assertInstanceOf(RecaptchaChallengeProvider::class, $registry->get(self::RECAPTCHA_PROVIDER));
        $this->assertTrue($registry->hasOverrides());
    }

    public function testBothRulesStillChallenge(): void
    {
        // The response type is unchanged by any of this — naming a provider
        // decides which interstitial goes out, not whether one does.
        foreach (['/protected', '/admin'] as $path) {
            $firewall = Firewall::create([$this->config()]);

            try {
                $firewall->evaluate($this->visit($path));
                $this->fail('Expected a challenge on ' . $path);
            } catch (ChallengeRequiredException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testInterstitialCarriesTheSignedProviderName(): void
    {
        // The submission arrives as a fresh POST with the matched plugin
        // long gone, so the rendered page is the only thing that can say
        // which provider it is answering.
        $firewall = Firewall::create([$this->config()]);

        $html = $this->registry($firewall)->get(self::RECAPTCHA_PROVIDER)->renderInterstitial(
            $this->visit('/admin'),
            [
                'submit_url' => '/_firewall/challenge',
                'redirect_to' => '/admin',
                'ttl' => '600',
                'header_name' => 'X-Firewall-Challenge',
                'provider_token' => $this->signedProvider($firewall, self::RECAPTCHA_PROVIDER),
            ]
        );

        $field = ChallengeProviderInterface::PROVIDER_FIELD;
        $this->assertMatchesRegularExpression(
            '/name="' . preg_quote($field, '/') . '" value="[^"]+"/',
            $html
        );
        // The signature travels with it; the bare name would be rewritable.
        $this->assertStringContainsString('.', $this->postedProviderValue($html));
    }

    // -------------------------------------------------------------------
    // Strict scoping: a pass is worth what was solved, and no more
    // -------------------------------------------------------------------

    public function testRecaptchaPassOpensTheRecaptchaRule(): void
    {
        $config = $this->config();
        $token = $this->solveRecaptcha(Firewall::create([$config]));

        $this->assertTrue(
            Firewall::create([$config])->evaluate($this->visit('/admin', $token))
        );
    }

    public function testRecaptchaPassDoesNotOpenTheMathRule(): void
    {
        // Not because math is stronger — it is not — but because a token
        // attests to one solved challenge and nothing else. Ranking the two
        // would mean the firewall imposing an ordering on services it does
        // not control.
        $config = $this->config();
        $token = $this->solveRecaptcha(Firewall::create([$config]));

        $this->expectException(ChallengeRequiredException::class);
        Firewall::create([$config])->evaluate($this->visit('/protected', $token));
    }

    public function testMathPassOpensTheMathRule(): void
    {
        $config = $this->config();
        $token = $this->solveMath(Firewall::create([$config]));

        $this->assertTrue(
            Firewall::create([$config])->evaluate($this->visit('/protected', $token))
        );
    }

    public function testMathPassDoesNotOpenTheRecaptchaRule(): void
    {
        // The failure the whole feature would otherwise introduce: picking
        // reCAPTCHA for one rule is pointless if a math answer opens it.
        $config = $this->config();
        $token = $this->solveMath(Firewall::create([$config]));

        $this->expectException(ChallengeRequiredException::class);
        Firewall::create([$config])->evaluate($this->visit('/admin', $token));
    }

    public function testTrippingBothRulesCostsTwoChallenges(): void
    {
        // The stated consequence of strict scoping, asserted so it stays a
        // decision rather than a surprise: the same client solves math for
        // one route and reCAPTCHA for the other, and ends up holding two
        // tokens that each open exactly one.
        $config = $this->config();

        $mathToken = $this->solveMath(Firewall::create([$config]));
        $recaptchaToken = $this->solveRecaptcha(Firewall::create([$config]));

        $this->assertNotSame($mathToken, $recaptchaToken);
        $this->assertTrue(Firewall::create([$config])->evaluate($this->visit('/protected', $mathToken)));
        $this->assertTrue(Firewall::create([$config])->evaluate($this->visit('/admin', $recaptchaToken)));
    }

    public function testAPassTokenStillLeavesBlockPluginsRunning(): void
    {
        // Unchanged by per-plugin providers: the token says "I am human",
        // not "I am allowed everywhere".
        $config = $this->config();
        $token = $this->solveMath(Firewall::create([$config]));

        $this->expectException(\Kanopi\Firewall\Exception\FirewallBlockedException::class);
        Firewall::create([$config])->evaluate($this->visit('/wp-admin/install.php', $token));
    }

    // -------------------------------------------------------------------
    // The submission path
    // -------------------------------------------------------------------

    public function testSubmissionWithoutTheProviderFieldFallsBackToTheGlobalProvider(): void
    {
        // Keeps custom providers that render their own document working. The
        // resulting token is scoped to `challenge.provider`, so nothing is
        // widened by the fallback.
        $config = $this->config();
        $firewall = Firewall::create([$config]);
        [$state, $answer] = $this->mathState($firewall);

        $token = '';
        try {
            $firewall->evaluate($this->submission([
                MathChallengeProvider::STATE_FIELD => $state,
                MathChallengeProvider::ANSWER_FIELD => $answer,
            ]));
        } catch (ChallengeSolvedException $e) {
            $token = $e->getToken();
        }

        $this->assertNotEmpty($token);
        $this->assertTrue(Firewall::create([$config])->evaluate($this->visit('/protected', $token)));
    }

    public function testTamperedProviderFieldIsRefused(): void
    {
        // Signed, so rewriting the name to point at a different verifier
        // breaks the signature. Refused outright rather than quietly
        // verified by the default provider.
        $firewall = Firewall::create([$this->config()]);
        [$state, $answer] = $this->mathState($firewall);

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($this->submission([
            MathChallengeProvider::STATE_FIELD => $state,
            MathChallengeProvider::ANSWER_FIELD => $answer,
            ChallengeProviderInterface::PROVIDER_FIELD => 'math.not-a-real-signature',
        ]));
    }

    public function testProviderFieldWithNoSignatureIsRefused(): void
    {
        $firewall = Firewall::create([$this->config()]);
        [$state, $answer] = $this->mathState($firewall);

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($this->submission([
            MathChallengeProvider::STATE_FIELD => $state,
            MathChallengeProvider::ANSWER_FIELD => $answer,
            ChallengeProviderInterface::PROVIDER_FIELD => 'math',
        ]));
    }

    public function testProviderFieldWithAnEmptySignatureIsRefused(): void
    {
        // A trailing dot splits into a name and nothing. Refused before the
        // signature check rather than compared against an empty string.
        $firewall = Firewall::create([$this->config()]);
        [$state, $answer] = $this->mathState($firewall);

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($this->submission([
            MathChallengeProvider::STATE_FIELD => $state,
            MathChallengeProvider::ANSWER_FIELD => $answer,
            ChallengeProviderInterface::PROVIDER_FIELD => 'math.',
        ]));
    }

    public function testAnEmptyProviderNameSignsToNothing(): void
    {
        // What makes the hidden field disappear rather than render empty:
        // a provider with no name has nothing to carry, and an empty signed
        // value would only be noise in the POST.
        $firewall = Firewall::create([$this->config()]);

        $this->assertSame('', $this->signedProvider($firewall, ''));
    }

    public function testCorrectlySignedButUnresolvableProviderIsRefused(): void
    {
        // Reachable when the config changed while a page was open. The name
        // is authentic, so this is a misconfiguration rather than tampering
        // — but it still must not mint a token.
        $firewall = Firewall::create([$this->config()]);
        [$state, $answer] = $this->mathState($firewall);

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($this->submission([
            MathChallengeProvider::STATE_FIELD => $state,
            MathChallengeProvider::ANSWER_FIELD => $answer,
            ChallengeProviderInterface::PROVIDER_FIELD => $this->signName('a-retired-provider'),
        ]));
    }

    public function testASolutionVerifiedByTheWrongProviderIsRefused(): void
    {
        // A math answer posted under the reCAPTCHA rule's provider: the
        // claim is signed and resolvable, so the submission reaches
        // reCAPTCHA's verifier, which finds no token of its own to check.
        $firewall = Firewall::create([$this->config()]);
        [$state, $answer] = $this->mathState($firewall);

        $this->expectException(ChallengeRequiredException::class);
        $firewall->evaluate($this->submission([
            MathChallengeProvider::STATE_FIELD => $state,
            MathChallengeProvider::ANSWER_FIELD => $answer,
            ChallengeProviderInterface::PROVIDER_FIELD => $this->signName(self::RECAPTCHA_PROVIDER),
        ]));
    }

    // -------------------------------------------------------------------
    // When the pass-token check happens
    // -------------------------------------------------------------------

    public function testAHeldTokenStillSkipsTheBucketWhenNoPluginOverrides(): void
    {
        // The pre-existing ordering, and the reason it is kept: with one
        // provider serving every rule, a valid token covers all of them, so
        // there is nothing to learn from evaluating the bucket. Rules with
        // side effects — a rate limiter's counters, an AbuseIPDB lookup —
        // stay untouched for token holders exactly as before.
        $config = $this->countingConfig(false, 'counting_single.yml');
        $token = $this->solveMathAgainst($config);

        CountingChallengePlugin::$evaluations = 0;
        $this->assertTrue(Firewall::create([$config])->evaluate($this->visit('/counted', $token)));
        $this->assertSame(0, CountingChallengePlugin::$evaluations);
    }

    public function testTheBucketIsEvaluatedFirstOnceAPluginOverrides(): void
    {
        // Now a token is only worth what its holder solved, so which rule
        // matched has to be known before the token can be judged. Same
        // outcome for the visitor — the math token still opens the math
        // rule — but the bucket runs to establish it.
        $config = $this->countingConfig(true, 'counting_override.yml');
        $token = $this->solveMathAgainst($config);

        CountingChallengePlugin::$evaluations = 0;
        $this->assertTrue(Firewall::create([$config])->evaluate($this->visit('/counted', $token)));
        $this->assertSame(1, CountingChallengePlugin::$evaluations);
    }

    // -------------------------------------------------------------------
    // Upgrades and startup
    // -------------------------------------------------------------------

    public function testTokenMintedBeforeProviderScopingOpensOnlyTheDefaultRule(): void
    {
        // A live pre-upgrade token carries no `prv`. It can only have come
        // from `challenge.provider`, so it is honoured there — nobody is
        // re-challenged by the upgrade itself — and refused everywhere else.
        $config = $this->config();
        $request = $this->visit('/protected');
        $legacy = (new TokenManager(self::SECRET, 'math', 'math'))->mint($request, 600);

        $this->assertTrue(Firewall::create([$config])->evaluate($this->visit('/protected', $legacy)));

        $this->expectException(ChallengeRequiredException::class);
        Firewall::create([$config])->evaluate($this->visit('/admin', $legacy));
    }

    public function testAPluginNamingAMisspelledProviderFailsAtStartup(): void
    {
        $this->expectException(ConfigurationException::class);
        Firewall::create([$this->config('recapcha', [], 'misspelled.yml')]);
    }

    public function testAPluginNamingAProviderWithoutItsKeysFailsAtStartup(): void
    {
        // Turnstile refuses to construct without its key pair. Warming up
        // every named provider is what turns that into a startup failure
        // rather than a 500 for the first visitor to trip the rule.
        $this->expectException(ConfigurationException::class);
        Firewall::create([$this->config('turnstile', [], 'keyless.yml')]);
    }

    public function testFlatProviderOptionsAreNotBorrowedByAPluginNamedProvider(): void
    {
        // The flat block belongs to `challenge.provider`. Turnstile keys
        // sitting there must not be handed to the reCAPTCHA rule, so it
        // fails at startup for want of its own.
        $this->expectException(ConfigurationException::class);
        Firewall::create([
            $this->config(
                'recaptcha',
                [
                    'site_key' => '1x00000000000000000000AA',
                    'secret_key' => '1x0000000000000000000000000000000AA',
                ],
                'flat_options.yml'
            ),
        ]);
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    /**
     * Two challenge rules on one firewall, each with its own provider.
     *
     * @param string $recaptchaProvider
     *   What the `/admin` rule names in `metadata.challenge_provider`.
     * @param array<string, mixed> $flatOptions
     *   Options written flat rather than nested, i.e. belonging to
     *   `challenge.provider`.
     * @param string $filename
     *   Config filename, unique per case so the files do not collide.
     */
    private function config(
        string $recaptchaProvider = self::RECAPTCHA_PROVIDER,
        array $flatOptions = [],
        string $filename = 'per_plugin_config.yml'
    ): string {
        $providerOptions = $flatOptions;
        $providerOptions[self::RECAPTCHA_PROVIDER] = [
            'site_key' => self::RECAPTCHA_SITE_KEY,
            'secret_key' => self::RECAPTCHA_SECRET_KEY,
        ];

        return $this->writeConfig([
            'global' => ['mode' => 'exception'],
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\FileStorage',
                'config' => ['storage_file' => $this->tempDir . '/per-plugin-storage.data'],
            ],
            'challenge' => [
                'provider' => 'math',
                'secret' => self::SECRET,
                'cookie_name' => 'fw_challenge_pass',
                'header_name' => 'X-Firewall-Challenge',
                'path' => '/_firewall/challenge',
                'provider_options' => $providerOptions,
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
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\Url',
                    'response' => 'challenge',
                    'weight' => 10,
                    'enable' => true,
                    'metadata' => [
                        'default_expiration_time' => 600,
                        'challenge_provider' => $recaptchaProvider,
                    ],
                    'config' => ['path@starts_with:/admin'],
                ],
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\Url',
                    'response' => 'block',
                    'weight' => 20,
                    'enable' => true,
                    'config' => ['path@starts_with:/wp-admin'],
                ],
            ],
        ], $filename);
    }

    /**
     * A firewall whose only counted rule uses the global provider.
     *
     * @param bool $withOverride
     *   Add a second rule naming its own provider, which is what moves the
     *   pass-token check after evaluation.
     * @param string $filename
     *   Config filename, unique per case so the files do not collide.
     */
    private function countingConfig(bool $withOverride, string $filename): string
    {
        $plugins = [
            [
                'plugin' => CountingChallengePlugin::class,
                'response' => 'challenge',
                'weight' => 0,
                'enable' => true,
                'metadata' => ['default_expiration_time' => 600],
                'config' => [],
            ],
        ];

        if ($withOverride) {
            $plugins[] = [
                'plugin' => 'Kanopi\Firewall\Plugins\Url',
                'response' => 'challenge',
                'weight' => 10,
                'enable' => true,
                'metadata' => [
                    'default_expiration_time' => 600,
                    'challenge_provider' => self::RECAPTCHA_PROVIDER,
                ],
                'config' => ['path@starts_with:/admin'],
            ];
        }

        return $this->writeConfig([
            'global' => ['mode' => 'exception'],
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\FileStorage',
                'config' => ['storage_file' => $this->tempDir . '/counting-storage.data'],
            ],
            'challenge' => [
                'provider' => 'math',
                'secret' => self::SECRET,
                'cookie_name' => 'fw_challenge_pass',
                'header_name' => 'X-Firewall-Challenge',
                'path' => '/_firewall/challenge',
                'provider_options' => [
                    self::RECAPTCHA_PROVIDER => [
                        'site_key' => self::RECAPTCHA_SITE_KEY,
                        'secret_key' => self::RECAPTCHA_SECRET_KEY,
                    ],
                ],
            ],
            'plugins' => $plugins,
        ], $filename);
    }

    /**
     * Solve the math challenge against a given config file.
     */
    private function solveMathAgainst(string $config): string
    {
        return $this->solveMath(Firewall::create([$config]));
    }

    /**
     * A GET the challenge rules will judge, optionally carrying a pass token.
     */
    private function visit(string $path, string $token = ''): Request
    {
        $cookies = $token === '' ? [] : ['fw_challenge_pass' => $token];

        return Request::create($path, 'GET', [], $cookies, [], ['REMOTE_ADDR' => '10.0.0.70']);
    }

    /**
     * A POST to the challenge endpoint carrying the given form fields.
     *
     * @param array<string, string> $fields
     *   Provider-specific fields; the redirect and TTL are added here.
     */
    private function submission(array $fields): Request
    {
        return Request::create(
            '/_firewall/challenge',
            'POST',
            $fields + [
                ChallengeProviderInterface::REDIRECT_FIELD => '/protected',
                ChallengeProviderInterface::TTL_FIELD => '600',
            ],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.70']
        );
    }

    /**
     * Solve the math challenge and return the pass token it mints.
     */
    private function solveMath(Firewall $firewall): string
    {
        [$state, $answer] = $this->mathState($firewall);

        try {
            $firewall->evaluate($this->submission([
                MathChallengeProvider::STATE_FIELD => $state,
                MathChallengeProvider::ANSWER_FIELD => $answer,
                ChallengeProviderInterface::PROVIDER_FIELD => $this->signedProvider($firewall, 'math'),
            ]));
            $this->fail('Expected ChallengeSolvedException');
        } catch (ChallengeSolvedException $e) {
            return $e->getToken();
        }

        return ''; // Unreachable.
    }

    /**
     * Solve the reCAPTCHA challenge and return the pass token it mints.
     */
    private function solveRecaptcha(Firewall $firewall): string
    {
        try {
            $firewall->evaluate($this->submission([
                RecaptchaChallengeProvider::PAYLOAD_FIELD => 'a-token-google-likes',
                ChallengeProviderInterface::PROVIDER_FIELD => $this->signedProvider(
                    $firewall,
                    self::RECAPTCHA_PROVIDER
                ),
            ]));
            $this->fail('Expected ChallengeSolvedException');
        } catch (ChallengeSolvedException $e) {
            return $e->getToken();
        }

        return ''; // Unreachable.
    }

    /**
     * Render the math interstitial and pull out its signed state + answer.
     *
     * @return array{0: string, 1: string}
     */
    private function mathState(Firewall $firewall): array
    {
        $provider = $this->registry($firewall)->get('math');
        $this->assertInstanceOf(MathChallengeProvider::class, $provider);

        $html = $provider->renderInterstitial($this->visit('/protected'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => '/protected',
            'ttl' => '600',
            'header_name' => 'X-Firewall-Challenge',
        ]);

        preg_match(
            '/name="' . preg_quote(MathChallengeProvider::STATE_FIELD, '/') . '" value="([^"]+)"/',
            $html,
            $match
        );
        $this->assertNotEmpty($match, 'state hidden input missing');

        [$data, ] = explode('.', $match[1], 2);
        [$answer, ] = explode('|', $data, 2);

        return [$match[1], $answer];
    }

    /**
     * A signed provider claim still resolves when no registry was built.
     *
     * The registry is only assembled when config names more than one provider.
     * Without it there is a single provider and nothing to look a name up in,
     * so a claim that verifies resolves to that one — rather than being
     * refused because the lookup table happens not to exist.
     */
    public function testSignedProviderResolvesWithoutARegistry(): void
    {
        $firewall = Firewall::create([$this->config()]);

        // Stand the firewall up as a single-provider deployment.
        $registry = new \ReflectionProperty($firewall, 'challengeProviderRegistry');
        $registry->setValue($firewall, null);

        $signed = $this->signedProvider($firewall, 'math');
        $this->assertNotSame('', $signed, 'The provider claim must be signable.');

        $request = Request::create('/', 'POST', [
            ChallengeProviderInterface::PROVIDER_FIELD => $signed,
        ], [], [], ['REMOTE_ADDR' => '203.0.113.9']);

        $method = new \ReflectionMethod($firewall, 'resolveSubmissionProvider');
        [$name, $provider] = $method->invoke($firewall, $request);

        $this->assertSame('math', $name);
        $this->assertNotNull($provider, 'The single configured provider answers the claim.');
    }

    /**
     * The provider registry the firewall built from config.
     */
    private function registry(Firewall $firewall): ChallengeProviderRegistry
    {
        $registry = (new \ReflectionProperty($firewall, 'challengeProviderRegistry'))->getValue($firewall);
        $this->assertInstanceOf(ChallengeProviderRegistry::class, $registry);

        return $registry;
    }

    /**
     * Ask the firewall for the value it would render into the hidden field.
     */
    private function signedProvider(Firewall $firewall, string $provider): string
    {
        $method = new \ReflectionMethod($firewall, 'signProviderName');

        return (string) $method->invoke($firewall, $provider);
    }

    /**
     * Sign a provider name from outside the firewall.
     *
     * Reads the domain-separation prefix off the class rather than
     * duplicating the literal, so this keeps testing the real wire format
     * if that value is ever changed.
     */
    private function signName(string $provider): string
    {
        $prefix = (string) (new \ReflectionClassConstant(Firewall::class, 'PROVIDER_SIGNATURE_PREFIX'))->getValue();

        return $provider . '.' . (new TokenManager(self::SECRET))->sign($prefix . $provider);
    }

    /**
     * Pull the posted provider value back out of a rendered interstitial.
     */
    private function postedProviderValue(string $html): string
    {
        preg_match(
            '/name="' . preg_quote(ChallengeProviderInterface::PROVIDER_FIELD, '/') . '" value="([^"]+)"/',
            $html,
            $match
        );
        $this->assertNotEmpty($match, 'provider hidden input missing');

        return $match[1];
    }

    /**
     * @param array<string, mixed> $config
     */
    private function writeConfig(array $config, string $filename): string
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

        foreach (array_diff(scandir($directory), ['.', '..']) as $file) {
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
