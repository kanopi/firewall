<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration;

use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Diagnostics\ConfigLinter;
use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Event\ChallengeSolved;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Firewall;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * `challenge.ttl` as the default pass lifetime and the ceiling on it (#367).
 *
 * The lifetime that signs a pass token arrives in the interstitial's POST body, so
 * before this it was chosen by whoever posted it. `max(0, …)` put a floor under the
 * value and nothing put a ceiling on it: solve one math problem, post a large `ttl`,
 * and hold a valid pass for decades.
 *
 * These walk the real flow rather than calling the clamp directly — the value has to
 * survive the round trip through the form to be worth anything.
 */
class ChallengeTtlCeilingTest extends TestCase
{
    private const SECRET = 'ttl-ceiling-test-secret-value';

    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();
        putenv('FIREWALL_BYPASS_CLI=1');

        $this->tempDir = sys_get_temp_dir() . '/firewall_ttl_' . uniqid();
        if (!mkdir($this->tempDir, 0777, true)) {
            throw new \RuntimeException('Failed to create temp directory: ' . $this->tempDir);
        }
    }

    protected function tearDown(): void
    {
        $this->recursiveRemoveDirectory($this->tempDir);
        parent::tearDown();
    }

    /**
     * The bug, stated as a test: a client cannot mint itself a decade.
     */
    public function testPostedLifetimeIsClampedToTheConfiguredCeiling(): void
    {
        $firewall = Firewall::create([$this->config(['ttl' => 900])]);

        $lifetime = $this->solveAndReadLifetime($firewall, '999999999');

        $this->assertEqualsWithDelta(900, $lifetime, 1, 'The posted lifetime was honoured above the ceiling');
    }

    /**
     * Without `challenge.ttl`, the ceiling is the hour that was hard-coded before it
     * existed. Adding the key changes nothing for a config that does not set it.
     */
    public function testCeilingFallsBackToAnHourWhenNothingIsConfigured(): void
    {
        $firewall = Firewall::create([$this->config([])]);

        $this->assertEqualsWithDelta(3600, $this->solveAndReadLifetime($firewall, '999999999'), 1);
    }

    /**
     * Asking for less is asking for less exposure, and is honoured.
     */
    public function testALifetimeBelowTheCeilingIsHonoured(): void
    {
        $firewall = Firewall::create([$this->config(['ttl' => 7200])]);

        $this->assertEqualsWithDelta(300, $this->solveAndReadLifetime($firewall, '300'), 1);
    }

    /**
     * Zero, negative and absent all mean "none given", and take the configured
     * default rather than the built-in one.
     */
    #[DataProvider('emptyLifetimeProvider')]
    public function testAnAbsentOrNonPositiveLifetimeTakesTheConfiguredDefault(?string $posted): void
    {
        $firewall = Firewall::create([$this->config(['ttl' => 1800])]);

        $this->assertEqualsWithDelta(1800, $this->solveAndReadLifetime($firewall, $posted), 1);
    }

    /**
     * @return array<string, array{0: ?string}>
     */
    public static function emptyLifetimeProvider(): array
    {
        return [
            'field absent' => [null],
            'empty string' => [''],
            'zero' => ['0'],
            'negative' => ['-600'],
            'not a number' => ['forever'],
        ];
    }

    /**
     * `ttl: "one hour"` is treated as absent rather than cast to zero, so the
     * firewall lands on the fallback instead of on something nonsensical.
     */
    public function testANonNumericCeilingIsTreatedAsAbsent(): void
    {
        $firewall = Firewall::create([$this->config(['ttl' => 'one hour'])]);

        $this->assertEqualsWithDelta(3600, $this->solveAndReadLifetime($firewall, '999999999'), 1);
    }

    /**
     * The ergonomic half: a rule that names no lifetime inherits the global one,
     * and the interstitial is rendered with it.
     */
    public function testARuleWithNoLifetimeInheritsTheGlobalOne(): void
    {
        $firewall = Firewall::create([$this->config(['ttl' => 1200], null)]);

        $this->assertSame('1200', $this->renderedLifetime($firewall));
    }

    /**
     * A rule declaring more than the ceiling is clamped where the form is built, so
     * the number in the page and the number in the token are the same number.
     */
    public function testARuleAskingForMoreThanTheCeilingIsClampedAtRenderTime(): void
    {
        $firewall = Firewall::create([$this->config(['ttl' => 900], 86400)]);

        $this->assertSame('900', $this->renderedLifetime($firewall));
    }

    /**
     * A rule below the ceiling keeps what it asked for — the global is a limit, not
     * an override.
     */
    public function testARuleBelowTheCeilingKeepsItsOwnLifetime(): void
    {
        $firewall = Firewall::create([$this->config(['ttl' => 3600], 600)]);

        $this->assertSame('600', $this->renderedLifetime($firewall));
    }

    /**
     * The rejected-solution path re-renders the clamped value. Echoing the posted one
     * back hands the over-long request straight to the next submission.
     */
    public function testARejectedSolutionIsRerenderedWithTheClampedLifetime(): void
    {
        $firewall = Firewall::create([$this->config(['ttl' => 900])]);

        [$state, $answer] = $this->solvedState($firewall);

        $request = $this->submission([
            MathChallengeProvider::STATE_FIELD => $state,
            MathChallengeProvider::ANSWER_FIELD => (string) ((int) $answer + 1),
            MathChallengeProvider::TTL_FIELD => '999999999',
        ]);

        try {
            $firewall->evaluate($request);
            $this->fail('Expected ChallengeRequiredException');
        } catch (ChallengeRequiredException $challengeRequiredException) {
            $this->assertSame('900', $challengeRequiredException->getRenderContext()['ttl']);
        }
    }

    /**
     * `mode: exception` delivers the token to the host, which sets the cookie itself,
     * so the clamp has to happen before the event is dispatched or a host trusting
     * `ChallengeSolved::$ttl` writes a cookie the firewall will not honour.
     */
    public function testTheSolvedEventCarriesTheClampedLifetime(): void
    {
        $seen = [];
        $dispatcher = new class ($seen) implements EventDispatcherInterface {
            /**
             * @param array<int, int> $seen
             */
            public function __construct(public array &$seen)
            {
            }

            public function dispatch(object $event): object
            {
                if ($event instanceof ChallengeSolved) {
                    $this->seen[] = $event->getTtl();
                }

                return $event;
            }
        };

        $firewall = Firewall::create([$this->config(['ttl' => 450])], [], $dispatcher);

        $this->solveAndReadLifetime($firewall, '999999999');

        $this->assertSame([450], $seen);
    }

    /**
     * The runtime clamp is one request at a time on a running site. CI can see it
     * before the deploy.
     */
    public function testTheLinterReportsARuleAboveTheCeiling(): void
    {
        $findings = (new ConfigLinter([$this->config(['ttl' => 900], 86400)]))->run();

        $this->assertSame(
            ['Rule "over-long" asks for a longer challenge pass than `challenge.ttl` allows'],
            $this->titles($findings, Diagnosis::WARNING)
        );
        $this->assertStringContainsString('so its passes last 900', $this->detailFor($findings, 'over-long'));
    }

    public function testTheLinterReportsACeilingThatIsNotANumber(): void
    {
        $findings = (new ConfigLinter([$this->config(['ttl' => 'one hour'])]))->run();

        $this->assertSame(
            ['`challenge.ttl` is not a number'],
            $this->titles($findings, Diagnosis::WARNING)
        );
    }

    /**
     * `default_expiration_time` on a block or record rule is a ban length. Reporting
     * it against a challenge ceiling would be a confident warning about a rule that
     * is fine.
     */
    public function testTheLinterIgnoresBanLengthsOnRulesThatAreNotChallenges(): void
    {
        $config = $this->configArray(['ttl' => 900], 86400);
        $config['plugins'][0]['response'] = 'record';

        $findings = (new ConfigLinter([$this->writeConfig($config, 'record.yml')]))->run();

        $this->assertSame([], $this->titles($findings, Diagnosis::WARNING));
    }

    public function testTheLinterPassesARuleWithinTheCeiling(): void
    {
        $findings = (new ConfigLinter([$this->config(['ttl' => 3600], 600)]))->run();

        $this->assertSame([], $this->titles($findings, Diagnosis::WARNING));
    }

    /**
     * Solve the challenge, post `$ttl`, and report how long the minted token lasts.
     */
    private function solveAndReadLifetime(Firewall $firewall, ?string $ttl): int
    {
        [$state, $answer] = $this->solvedState($firewall);

        $fields = [
            MathChallengeProvider::STATE_FIELD => $state,
            MathChallengeProvider::ANSWER_FIELD => $answer,
        ];

        if ($ttl !== null) {
            $fields[MathChallengeProvider::TTL_FIELD] = $ttl;
        }

        $before = time();

        try {
            $firewall->evaluate($this->submission($fields));
            $this->fail('Expected ChallengeSolvedException');
        } catch (ChallengeSolvedException $challengeSolvedException) {
            [$payload] = explode('.', $challengeSolvedException->getToken(), 2);
            $decoded = json_decode(
                (string) base64_decode(strtr($payload, '-_', '+/'), true),
                true
            );
            $this->assertIsArray($decoded);

            // The token records an absolute expiry, so the lifetime is a
            // subtraction against the clock read just before the request. The
            // clock can only have advanced across that boundary, so the answer
            // is the lifetime or one more than it -- hence the delta at every
            // call site rather than an exact match here.
            return (int) $decoded['exp'] - $before;
        }

        return -1; // Unreachable.
    }

    /**
     * The lifetime the firewall writes into the interstitial it serves.
     */
    private function renderedLifetime(Firewall $firewall): string
    {
        try {
            $firewall->evaluate(Request::create('/protected', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.50']));
            $this->fail('Expected ChallengeRequiredException');
        } catch (ChallengeRequiredException $challengeRequiredException) {
            return (string) $challengeRequiredException->getRenderContext()['ttl'];
        }

        return ''; // Unreachable.
    }

    /**
     * Render the interstitial and pull the signed state and its answer out of it.
     *
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

    /**
     * @param array<int, Diagnosis> $findings
     *
     * @return array<int, string>
     */
    private function titles(array $findings, string $status): array
    {
        return array_values(array_map(
            static fn(Diagnosis $diagnosis): string => $diagnosis->title,
            array_filter($findings, static fn(Diagnosis $diagnosis): bool => $diagnosis->status === $status)
        ));
    }

    /**
     * @param array<int, Diagnosis> $findings
     */
    private function detailFor(array $findings, string $ruleName): string
    {
        foreach ($findings as $finding) {
            if (str_contains($finding->title, $ruleName)) {
                return (string) $finding->detail;
            }
        }

        return '';
    }

    /**
     * @param array<string, mixed> $challenge
     */
    private function config(array $challenge, ?int $ruleTtl = 600): string
    {
        return $this->writeConfig($this->configArray($challenge, $ruleTtl));
    }

    /**
     * @param array<string, mixed> $challenge
     *
     * @return array<string, mixed>
     */
    private function configArray(array $challenge, ?int $ruleTtl = 600): array
    {
        $metadata = ['name' => $ruleTtl === null ? 'no-lifetime' : 'over-long'];
        if ($ruleTtl !== null) {
            $metadata['default_expiration_time'] = $ruleTtl;
        }

        return [
            'global' => ['mode' => 'exception'],
            'challenge' => $challenge + ['provider' => 'math', 'secret' => self::SECRET],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'challenge',
                    'weight' => 0,
                    'enable' => true,
                    'metadata' => $metadata,
                    'config' => ['10.0.0.50'],
                ],
            ],
        ];
    }

    private function recursiveRemoveDirectory(string $directory): void
    {
        foreach ((array) glob($directory . '/*') as $entry) {
            if (is_string($entry)) {
                unlink($entry);
            }
        }

        if (is_dir($directory)) {
            rmdir($directory);
        }
    }

    /**
     * @param array<string, mixed> $config
     */
    private function writeConfig(array $config, string $filename = 'ttl_config.yml'): string
    {
        $file = $this->tempDir . '/' . uniqid() . '_' . $filename;
        if (file_put_contents($file, Yaml::dump($config, 6, 2)) === false) {
            throw new \RuntimeException('Failed to write config: ' . $file);
        }

        return $file;
    }
}
