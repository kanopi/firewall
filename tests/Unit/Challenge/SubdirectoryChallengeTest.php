<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * A challenge on a host served from a subdirectory (#358).
 *
 * `challenge.path` was doing two incompatible jobs. It is the value compared
 * against `getPathInfo()`, which has the base path stripped, **and** the form
 * action the interstitial renders with, which needs it. On `example.com/` the
 * two are the same string and nothing is wrong; on `example.com/app/` they
 * differ, and configuring either one broke the other.
 *
 * The consequence is the worst shape a challenge can fail in: the form posted
 * to the web server root, the answer never reached the firewall, no pass token
 * was minted, and the visitor was challenged again forever — so the rule
 * refused **every human who tried to satisfy it** while a bot that ignored the
 * interstitial was unaffected.
 *
 * Reported from `drupal/basic_firewall`, whose end-to-end test passed locally
 * and failed on drupal.org CI, which serves from a subdirectory.
 */
final class SubdirectoryChallengeTest extends AbstractTestCase
{
    /**
     * The secret has to be long enough for the firewall to start.
     */
    private const SECRET = 'a-secret-long-enough-to-sign-pass-tokens-with';

    /**
     * The form posts inside the application, not to the server root.
     */
    public function testTheFormActionCarriesTheBasePath(): void
    {
        $this->assertSame('/app/_firewall/challenge', $this->submitUrlFor('/app/gated', '/app'));
    }

    /**
     * And a root-served host is unchanged, which is most deployments.
     */
    public function testARootServedHostIsUnaffected(): void
    {
        $this->assertSame('/_firewall/challenge', $this->submitUrlFor('/gated', null));
    }

    /**
     * The matched path keeps its own job.
     *
     * The fix works precisely because these are now two values. If the base
     * path had been added to `challenge.path` instead, the submission would
     * post to the right place and then fail to be recognised as a submission —
     * which is the same bug with the halves swapped.
     */
    public function testASubmissionFromASubdirectoryIsStillRecognised(): void
    {
        $firewall = $this->firewall();
        $request = Request::create(
            'http://example.com/app/_firewall/challenge',
            'POST',
            ['not-a-real-solution' => '1'],
            [],
            [],
            $this->subdirectoryServer('/app') + ['REMOTE_ADDR' => '203.0.113.5']
        );

        // Recognised as a submission, and rejected on its merits rather than
        // ignored: a request that was not recognised would fall through to the
        // challenge rule and raise ChallengeRequiredException with a fresh
        // challenge instead.
        $this->expectException(ChallengeRequiredException::class);
        $this->expectExceptionMessage('Invalid challenge solution');

        $firewall->evaluate($request);
    }

    /**
     * The rejected-solution path renders the same corrected action.
     *
     * Two call sites build a render context, and this is the one a visitor
     * meets second — after getting the answer wrong, which is exactly when a
     * form that posts nowhere is least likely to be noticed.
     */
    public function testTheRejectedSolutionFormAlsoCarriesTheBasePath(): void
    {
        $firewall = $this->firewall();
        $request = Request::create(
            'http://example.com/app/_firewall/challenge',
            'POST',
            ['not-a-real-solution' => '1'],
            [],
            [],
            $this->subdirectoryServer('/app') + ['REMOTE_ADDR' => '203.0.113.5']
        );

        try {
            $firewall->evaluate($request);
            $this->fail('An invalid solution must be rejected.');
        } catch (ChallengeRequiredException $challengeRequiredException) {
            $this->assertSame('/app/_firewall/challenge', $challengeRequiredException->getRenderContext()['submit_url']);
        }
    }

    /**
     * An explicit `submit_url` wins over both.
     *
     * For a deployment behind a proxy that rewrites paths, where the browser's
     * view and the application's differ by something the request cannot work
     * out on its own.
     */
    public function testAnExplicitSubmitUrlWins(): void
    {
        $this->assertSame(
            'https://edge.example.com/challenge',
            $this->submitUrlFor('/app/gated', '/app', ['submit_url' => 'https://edge.example.com/challenge'])
        );
    }

    /**
     * `redirect_to` is next to it and was already correct.
     *
     * Asserted rather than assumed: the two lines are adjacent, both are about
     * paths, and it would have been easy to "fix" the wrong one.
     * `getRequestUri()` includes the base path, which is what a browser
     * redirect needs.
     */
    public function testTheRedirectTargetAlreadyCarriedTheBasePath(): void
    {
        $firewall = $this->firewall();
        $request = Request::create(
            'http://example.com/app/gated',
            'GET',
            [],
            [],
            [],
            $this->subdirectoryServer('/app') + ['REMOTE_ADDR' => '203.0.113.5']
        );

        try {
            $firewall->evaluate($request);
            $this->fail('The rule must challenge.');
        } catch (ChallengeRequiredException $challengeRequiredException) {
            $this->assertSame('/app/gated', $challengeRequiredException->getRenderContext()['redirect_to']);
        }
    }

    /**
     * The `submit_url` a challenged request would be rendered with.
     *
     * @param string $path
     *   The request path, including any base path.
     * @param string|null $basePath
     *   The subdirectory the application is served from, or NULL for the root.
     * @param array<string, mixed> $challenge
     *   Extra `challenge:` configuration.
     */
    private function submitUrlFor(string $path, ?string $basePath, array $challenge = []): string
    {
        $server = ($basePath === null ? [] : $this->subdirectoryServer($basePath)) + ['REMOTE_ADDR' => '203.0.113.5'];
        $request = Request::create('http://example.com' . $path, 'GET', [], [], [], $server);

        try {
            $this->firewall($challenge)->evaluate($request);
        } catch (ChallengeRequiredException $challengeRequiredException) {
            return (string) $challengeRequiredException->getRenderContext()['submit_url'];
        } catch (ChallengeSolvedException) {
            $this->fail('Nothing was solved.');
        }

        $this->fail('The rule must challenge.');
    }

    /**
     * The server variables a front controller in a subdirectory produces.
     *
     * @param string $basePath
     *   The subdirectory, with a leading slash.
     *
     * @return array<string, string>
     *   Server variables.
     */
    private function subdirectoryServer(string $basePath): array
    {
        return [
            'SCRIPT_NAME' => $basePath . '/index.php',
            'PHP_SELF' => $basePath . '/index.php',
            'SCRIPT_FILENAME' => '/var/www' . $basePath . '/index.php',
        ];
    }

    /**
     * A firewall with one rule that challenges.
     *
     * @param array<string, mixed> $challenge
     *   Extra `challenge:` configuration.
     */
    private function firewall(array $challenge = []): Firewall
    {
        return Firewall::create([[
            'global' => ['mode' => 'exception', 'behind_proxy' => false],
            'challenge' => $challenge + [
                'provider' => 'math',
                'secret' => self::SECRET,
                'path' => '/_firewall/challenge',
            ],
            'plugins' => [[
                'plugin' => \Kanopi\Firewall\Plugins\Url::class,
                'response' => 'challenge',
                'enable' => true,
                'config' => ['path:/gated'],
            ]],
        ]]);
    }
}
