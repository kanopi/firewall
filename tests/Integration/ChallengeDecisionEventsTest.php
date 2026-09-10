<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration;

use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Event\ChallengeFailed;
use Kanopi\Firewall\Event\ChallengeSolved;
use Kanopi\Firewall\Event\RequestAllowed;
use Kanopi\Firewall\Event\RequestChallenged;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Event\RecordingDispatcher;
use Kanopi\Firewall\Traits\FileTrait;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * The challenge half of the decision events (#218).
 *
 * Driven through the real flow rather than with mocked buckets, because the
 * facts these events carry -- which provider served the challenge, why a
 * submission was refused -- only exist once the provider, the token manager
 * and the signed provider claim are all actually wired together.
 *
 * The pair of `RequestChallenged` and `ChallengeSolved` is the reason this
 * matters: a challenge nobody solves is one that is too hard, and until now
 * the only way to notice was to count two log messages.
 */
class ChallengeDecisionEventsTest extends TestCase
{
    use FileTrait;

    private const SECRET = 'integration-test-secret-value';

    private string $tempDir;

    private RecordingDispatcher $dispatcher;

    protected function setUp(): void
    {
        parent::setUp();
        putenv('FIREWALL_BYPASS_CLI=1');

        $this->tempDir = sys_get_temp_dir() . '/firewall_events_' . uniqid();

        if (!mkdir($this->tempDir, 0777, true)) {
            throw new \RuntimeException('Failed to create temp directory: ' . $this->tempDir);
        }

        $this->dispatcher = new RecordingDispatcher();
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tempDir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->tempDir);
        parent::tearDown();
    }

    /**
     * A challenge rule matching announces which rule and which provider.
     *
     * The provider is a separate fact from the rule now that a rule can name
     * its own, and a listener measuring solve rates has to know what was put
     * in front of the client.
     */
    public function testServingAChallengeAnnouncesTheRuleAndProvider(): void
    {
        $firewall = $this->firewall();

        try {
            $firewall->evaluate($this->challengedRequest());
            $this->fail('Expected ChallengeRequiredException.');
        } catch (ChallengeRequiredException) {
            $this->addToAssertionCount(1);
        }

        $this->assertSame(['RequestChallenged'], $this->dispatcher->names());

        $event = $this->dispatcher->events[0];
        $this->assertInstanceOf(RequestChallenged::class, $event);
        $this->assertSame('IP Address', $event->getPlugin()->getName());
        $this->assertSame('math', $event->getProvider());
        $this->assertTrue($event->isEnforced());
    }

    /**
     * A correct solution announces the provider it was scoped to and how long
     * the pass token lasts -- the second is what tells a listener when the
     * client will be back.
     */
    public function testASolvedChallengeIsAnnounced(): void
    {
        $firewall = $this->firewall();

        try {
            $firewall->evaluate($this->submission($firewall));
            $this->fail('Expected ChallengeSolvedException.');
        } catch (ChallengeSolvedException) {
            $this->addToAssertionCount(1);
        }

        $this->assertSame(['ChallengeSolved'], $this->dispatcher->names());

        $event = $this->dispatcher->events[0];
        $this->assertInstanceOf(ChallengeSolved::class, $event);
        $this->assertSame('math', $event->getProvider());
        $this->assertSame(600, $event->getTtl());
    }

    /**
     * A wrong answer announces why, and the reason is worth reading rather
     * than counting: an ordinary wrong answer and a replayed correct one are
     * different problems.
     */
    public function testAFailedChallengeAnnouncesTheReason(): void
    {
        $firewall = $this->firewall();

        $request = $this->submission($firewall);
        $request->request->set(MathChallengeProvider::ANSWER_FIELD, '-1');

        try {
            $firewall->evaluate($request);
            $this->fail('Expected ChallengeRequiredException on a wrong answer.');
        } catch (ChallengeRequiredException) {
            $this->addToAssertionCount(1);
        }

        $this->assertSame(['ChallengeFailed'], $this->dispatcher->names());

        $event = $this->dispatcher->events[0];
        $this->assertInstanceOf(ChallengeFailed::class, $event);
        $this->assertSame('math', $event->getProvider());
        $this->assertSame('invalid_solution', $event->getReason());
        $this->assertTrue($event->isEnforced());
    }

    /**
     * A held pass token announces an allow, not a challenge.
     *
     * Nothing was asked of the client, so counting it would report a solve
     * rate above 100%.
     */
    public function testAHeldTokenAnnouncesAnAllowRatherThanAChallenge(): void
    {
        $firewall = $this->firewall();

        $token = $this->mintToken($firewall);

        $this->dispatcher->events = [];

        $request = Request::create(
            '/protected',
            'GET',
            [],
            ['fw_challenge_pass' => $token],
            [],
            ['REMOTE_ADDR' => '10.0.0.50']
        );

        $this->assertTrue($firewall->evaluate($request));
        $this->assertSame(['RequestAllowed'], $this->dispatcher->names());

        $event = $this->dispatcher->events[0];
        $this->assertInstanceOf(RequestAllowed::class, $event);
        $this->assertNull($event->getPlugin(), 'A held token is not a bypass rule');
    }

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    /**
     * `mode: log` is not exercised here on purpose: it short-circuits under
     * the CLI SAPI, so this test process cannot reach the branch at all and an
     * assertion here would pass on the early return instead. Declining that
     * bypass needs a subclass, and the mocked-bucket suite already has one --
     * see `DecisionEventsTest::testLogModeAnnouncesAnUnenforcedChallenge()`.
     */
    private function firewall(string $mode = 'exception'): Firewall
    {
        $file = $this->tempDir . '/challenge.yml';

        file_put_contents($file, Yaml::dump([
            'global' => ['mode' => $mode],
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
        ], 6, 2));

        return Firewall::create([$file], [], $this->dispatcher);
    }

    private function challengedRequest(): Request
    {
        return Request::create('/protected', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.50']);
    }

    /**
     * Build a POST carrying a correct solution.
     */
    private function submission(Firewall $firewall): Request
    {
        [$state, $answer] = $this->solvedState($firewall);

        return Request::create(
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
    }

    private function mintToken(Firewall $firewall): string
    {
        try {
            $firewall->evaluate($this->submission($firewall));
            $this->fail('Expected ChallengeSolvedException.');
        } catch (ChallengeSolvedException $challengeSolvedException) {
            return $challengeSolvedException->getToken();
        }
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function solvedState(Firewall $firewall): array
    {
        $providerRef = new \ReflectionProperty($firewall, 'challengeProvider');
        $provider = $providerRef->getValue($firewall);
        $this->assertInstanceOf(MathChallengeProvider::class, $provider);

        $html = $provider->renderInterstitial(
            Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.50']),
            [
                'submit_url' => '/_firewall/challenge',
                'redirect_to' => '/protected',
                'ttl' => '600',
                'cookie_name' => 'fw_challenge_pass',
                'header_name' => 'X-Firewall-Challenge',
            ]
        );

        preg_match(
            '/name="' . preg_quote(MathChallengeProvider::STATE_FIELD, '/') . '" value="([^"]+)"/',
            $html,
            $stateMatch
        );

        $this->assertNotEmpty($stateMatch, 'state hidden input missing');

        [$data] = explode('.', $stateMatch[1], 2);
        [$answer] = explode('|', $data, 2);

        return [$stateMatch[1], $answer];
    }
}
