<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration;

use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Utility\ChallengePasses;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * Withdrawing a pass, through the firewall that issued it (#368).
 *
 * The unit tests cover the token arithmetic. These are the operational claim:
 * a pass earned legitimately can be taken away without rotating the secret and
 * re-challenging everybody else holding one.
 */
class ChallengePassRevocationTest extends TestCase
{
    private const SECRET = 'revocation-integration-secret-value';

    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();
        putenv('FIREWALL_BYPASS_CLI=1');

        $this->tempDir = sys_get_temp_dir() . '/firewall_revoke_' . uniqid();
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
     * The whole point, in one test: one pass withdrawn, another untouched.
     */
    public function testARevokedPassIsChallengedAgainAndOthersAreNot(): void
    {
        $config = $this->config(['revocable' => true]);
        $firewall = Firewall::create([$config]);

        $revoked = $this->solve($firewall, '10.0.0.50');
        $kept = $this->solve($firewall, '10.0.0.51');

        $this->assertTrue($firewall->evaluate($this->withPass($revoked, '10.0.0.50')));
        $this->assertTrue($firewall->evaluate($this->withPass($kept, '10.0.0.51')));

        $passes = new ChallengePasses([$config]);
        $claims = (array) $passes->inspect($revoked);
        $this->assertTrue($passes->revoke((string) $claims['nonce'], (int) $claims['exp'], 'abusing it'));

        // A new instance, because a real revocation is issued from a terminal
        // while the site keeps serving — the store is what carries it across.
        $serving = Firewall::create([$config]);

        $this->assertTrue($this->isChallenged($serving, $revoked, '10.0.0.50'), 'The revoked pass was still accepted');
        $this->assertFalse($this->isChallenged($serving, $kept, '10.0.0.51'), 'Revoking one pass withdrew another');
    }

    /**
     * Off by default, and off means off: nothing is consulted, so a record
     * written while it is off does nothing.
     */
    public function testWithoutRevocableTheListIsNotConsulted(): void
    {
        $config = $this->config([]);
        $firewall = Firewall::create([$config]);
        $token = $this->solve($firewall, '10.0.0.50');

        $passes = new ChallengePasses([$config]);
        $claims = (array) $passes->inspect($token);
        $passes->revoke((string) $claims['nonce'], (int) $claims['exp']);

        $this->assertTrue(
            Firewall::create([$config])->evaluate($this->withPass($token, '10.0.0.50')),
            'A revocation was honoured without challenge.revocable being on'
        );
    }

    /**
     * The lever that costs nothing: one config value, no storage, and every
     * pass issued before it stops being accepted.
     */
    public function testACutoffWithdrawsEveryPassIssuedBeforeIt(): void
    {
        $token = $this->solve(Firewall::create([$this->config([])]), '10.0.0.50');

        $this->assertTrue(
            Firewall::create([$this->config([], 'a.yml')])->evaluate($this->withPass($token, '10.0.0.50'))
        );

        $withCutoff = Firewall::create([
            $this->config(['passes_valid_from' => time() + 1], 'cutoff.yml'),
        ]);

        $this->assertTrue($this->isChallenged($withCutoff, $token, '10.0.0.50'));
    }

    /**
     * Written the way an operator reaches for it in a hurry, rather than as a
     * number they had to compute.
     */
    #[DataProvider('cutoffFormatProvider')]
    public function testACutoffIsReadFromEitherAnEpochOrADate(mixed $declared): void
    {
        $token = $this->solve(Firewall::create([$this->config([])]), '10.0.0.50');
        $firewall = Firewall::create([$this->config(['passes_valid_from' => $declared], 'cutoff.yml')]);

        $this->assertTrue($this->isChallenged($firewall, $token, '10.0.0.50'));
    }

    /**
     * @return array<string, array{0: mixed}>
     */
    public static function cutoffFormatProvider(): array
    {
        return [
            'an epoch' => [time() + 3600],
            'an epoch as a string' => [(string) (time() + 3600)],
            'a date' => ['2099-01-01 00:00:00 UTC'],
            'a relative expression' => ['+1 hour'],
        ];
    }

    public function testNoCutoffIsTheDefaultAndCostsNothing(): void
    {
        $token = $this->solve(Firewall::create([$this->config([])]), '10.0.0.50');

        foreach ([null, 0, ''] as $declared) {
            $this->assertTrue(
                Firewall::create([$this->config(['passes_valid_from' => $declared], 'off.yml')])
                    ->evaluate($this->withPass($token, '10.0.0.50')),
                sprintf('%s should mean no cutoff', var_export($declared, true))
            );
        }
    }

    /**
     * A cutoff that cannot be read is a startup failure. The operator set it
     * believing outstanding passes were withdrawn; silently not withdrawing
     * them is the worst of both.
     */
    #[DataProvider('unreadableCutoffProvider')]
    public function testACutoffThatCannotBeReadIsAStartupFailure(mixed $declared, string $expected): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($expected);

        Firewall::create([$this->config(['passes_valid_from' => $declared], 'bad.yml')]);
    }

    /**
     * @return array<string, array{0: mixed, 1: string}>
     */
    public static function unreadableCutoffProvider(): array
    {
        return [
            'prose' => ['last tuesday-ish', 'challenge.passes_valid_from is not a moment in time'],
            'a list' => [['2026-01-01'], 'must be a unix timestamp or a date string, array given'],
            'a boolean' => [true, 'must be a unix timestamp or a date string, boolean given'],
        ];
    }

    /**
     * The nonce and the expiry are what a revocation needs, and grepping the
     * accepted-solution line by address is how an operator gets them without
     * having to retrieve a token out of somebody's browser.
     */
    public function testTheAcceptedSolutionLogCarriesWhatARevocationNeeds(): void
    {
        // After Firewall::create(), which installs the logger the config
        // declares and would otherwise replace this one.
        $firewall = Firewall::create([$this->config([])]);
        $testHandler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$testHandler]));

        try {
            $this->solve($firewall, '10.0.0.50');
        } finally {
            LoggingFactory::setLogger(LoggingFactory::create([]));
        }

        $accepted = array_values(array_filter(
            $testHandler->getRecords(),
            static fn(LogRecord $record): bool => $record->message === 'Challenge solution accepted'
        ));

        $this->assertCount(1, $accepted);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', (string) $accepted[0]->context['pass_nonce']);
        $this->assertIsInt($accepted[0]->context['pass_expires']);
    }

    /**
     * Whether a pass is refused, expressed as a question rather than an
     * expectation, so one test can assert both directions.
     */
    private function isChallenged(Firewall $firewall, string $token, string $ip): bool
    {
        try {
            $firewall->evaluate($this->withPass($token, $ip));
        } catch (ChallengeRequiredException) {
            return true;
        }

        return false;
    }

    private function withPass(string $token, string $ip): Request
    {
        return Request::create(
            '/protected',
            'GET',
            [],
            ['fw_challenge_pass' => $token],
            [],
            ['REMOTE_ADDR' => $ip]
        );
    }

    /**
     * Drive one full challenge cycle and return the minted pass.
     */
    private function solve(Firewall $firewall, string $ip): string
    {
        $provider = (new \ReflectionProperty($firewall, 'challengeProvider'))->getValue($firewall);
        $this->assertInstanceOf(MathChallengeProvider::class, $provider);

        $html = $provider->renderInterstitial(
            Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $ip]),
            ['submit_url' => '/_firewall/challenge', 'redirect_to' => '/protected', 'ttl' => '600']
        );

        preg_match('/name="' . preg_quote(MathChallengeProvider::STATE_FIELD, '/') . '" value="([^"]+)"/', $html, $match);
        $this->assertNotEmpty($match, 'state hidden input missing');
        [$data] = explode('.', $match[1], 2);
        [$answer] = explode('|', $data, 2);

        $request = Request::create(
            '/_firewall/challenge',
            'POST',
            [
                MathChallengeProvider::STATE_FIELD => $match[1],
                MathChallengeProvider::ANSWER_FIELD => $answer,
                MathChallengeProvider::REDIRECT_FIELD => '/protected',
            ],
            [],
            [],
            ['REMOTE_ADDR' => $ip]
        );

        try {
            $firewall->evaluate($request);
            $this->fail('Expected ChallengeSolvedException');
        } catch (ChallengeSolvedException $challengeSolvedException) {
            return $challengeSolvedException->getToken();
        }

        return ''; // Unreachable.
    }

    /**
     * @param array<string, mixed> $challenge
     */
    private function config(array $challenge, string $filename = 'revoke.yml'): string
    {
        $file = $this->tempDir . '/' . $filename;

        file_put_contents($file, Yaml::dump([
            'global' => ['mode' => 'exception'],
            'challenge' => $challenge + ['provider' => 'math', 'secret' => self::SECRET, 'ttl' => 900],
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\FileStorage',
                'config' => ['storage_file' => $this->tempDir . '/blocked.data'],
            ],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'challenge',
                    'weight' => 0,
                    'enable' => true,
                    'metadata' => ['name' => 'gate'],
                    'config' => ['10.0.0.50', '10.0.0.51'],
                ],
            ],
        ], 6, 2));

        return $file;
    }
}
