<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\ReputationUnavailableException;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\AbuseIpdb;
use Kanopi\Firewall\Plugins\Reputation;
use Kanopi\Firewall\Reputation\ReputationProviderInterface;
use Kanopi\Firewall\Reputation\ReputationVerdict;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Level;
use Monolog\Logger;
use Symfony\Component\HttpFoundation\Request;

/**
 * The rule around a reputation provider (#204).
 *
 * `AbuseIpdbTest` covers the same code through the AbuseIPDB rule, because that
 * is the one already in production configurations. This file is what the
 * extraction added: a provider that is not AbuseIPDB, a failure policy, and the
 * cache entries an upgrade inherits.
 */
final class ReputationTest extends AbstractTestCase
{
    /**
     * Per-test cache directory, removed on tear-down.
     */
    private string $cacheDir;

    protected function setUp(): void
    {
        parent::setUp();

        $this->cacheDir = sys_get_temp_dir() . '/reputation-test-' . bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        foreach ((array) glob($this->cacheDir . '/*') as $file) {
            @unlink((string) $file);
        }

        @rmdir($this->cacheDir);

        parent::tearDown();
    }

    /**
     * A verdict at or above the threshold matches, on any provider's scale.
     */
    public function testAScoreAtTheThresholdMatches(): void
    {
        $rule = $this->rule(['threshold' => 0.8], [new ReputationVerdict(0.8)]);

        $this->assertTrue($rule->evaluate($this->getRequest('203.0.113.5')));
    }

    /**
     * And a fractional score under it does not.
     *
     * The pair is what says the threshold is compared as a number rather than
     * an integer: read as ints, 0.79 and 0.8 are both 0, and every verdict
     * from a provider scoring 0-1 would match.
     */
    public function testAFractionalScoreUnderTheThresholdDoesNotMatch(): void
    {
        $rule = $this->rule(['threshold' => 0.8], [new ReputationVerdict(0.79)]);

        $this->assertFalse($rule->evaluate($this->getRequest('203.0.113.5')));
    }

    /**
     * A provider that vouches for an address beats the score.
     */
    public function testATrustedAddressNeverMatches(): void
    {
        $rule = $this->rule(['threshold' => 50], [new ReputationVerdict(100.0, true)]);

        $this->assertFalse($rule->evaluate($this->getRequest('203.0.113.5')));
    }

    /**
     * An unconfigured provider makes the rule inert rather than dangerous.
     */
    public function testAnUnconfiguredProviderMatchesNothing(): void
    {
        $rule = $this->rule(['problem' => 'no credential configured'], [new ReputationVerdict(100.0)]);

        $this->assertFalse($rule->evaluate($this->getRequest('203.0.113.5')));
    }

    /**
     * A failure fails open, and says so at warning level.
     */
    public function testAFailedLookupFailsOpenLoudly(): void
    {
        $handler = $this->captureLogs();
        $rule = $this->rule([], [new ReputationUnavailableException('the service is down', 503)]);

        $this->assertFalse($rule->evaluate($this->getRequest('203.0.113.5')));
        $this->assertTrue($handler->hasWarningContaining('lookup failed - allowing the request through'));
    }

    /**
     * `on_error: last_known_good` reuses an expired verdict for that address.
     *
     * The point of the alternative policy, and the limit of it: it is a verdict
     * this firewall already fetched for this address and would otherwise throw
     * away for being old. Nothing is ever refused on an answer the provider did
     * not give.
     */
    public function testLastKnownGoodReusesAnExpiredVerdict(): void
    {
        $request = $this->getRequest('203.0.113.5');
        $rule = $this->rule(
            ['threshold' => 75, 'cache_ttl' => 0, 'on_error' => 'last_known_good'],
            [new ReputationVerdict(100.0), new ReputationUnavailableException('the service is down', 503)]
        );

        // First pass fetches and caches; `cache_ttl: 0` expires it immediately.
        $this->assertTrue($rule->evaluate($request));

        $handler = $this->captureLogs();

        $this->assertTrue(
            $rule->evaluate($request),
            'With the service down, the expired verdict for this address is still the best answer there is.'
        );
        $this->assertTrue($handler->hasWarningContaining('using the last known verdict'));
    }

    /**
     * The default is the other way: an outage stops the rule matching.
     *
     * Same script as above without `on_error`, so the difference is the policy
     * and nothing else.
     */
    public function testFailOpenIsTheDefault(): void
    {
        $request = $this->getRequest('203.0.113.5');
        $rule = $this->rule(
            ['threshold' => 75, 'cache_ttl' => 0],
            [new ReputationVerdict(100.0), new ReputationUnavailableException('the service is down', 503)]
        );

        $this->assertTrue($rule->evaluate($request));
        $this->assertFalse($rule->evaluate($request));
    }

    /**
     * `last_known_good` with nothing known falls open like anything else.
     */
    public function testLastKnownGoodWithNothingCachedStillFailsOpen(): void
    {
        $rule = $this->rule(
            ['on_error' => 'last_known_good'],
            [new ReputationUnavailableException('the service is down', 503)]
        );

        $this->assertFalse($rule->evaluate($this->getRequest('203.0.113.5')));
    }

    /**
     * It reaches the stale verdict through a cached failure too.
     *
     * The second request inside `error_cache_ttl` never calls the provider --
     * that is the whole point of caching a failure -- so a policy that only
     * applied on a live failure would work for one request in five minutes.
     */
    public function testLastKnownGoodAppliesWhileTheFailureIsStillCached(): void
    {
        $request = $this->getRequest('203.0.113.5');
        $rule = $this->rule(
            ['threshold' => 75, 'cache_ttl' => 0, 'on_error' => 'last_known_good'],
            [
                new ReputationVerdict(100.0),
                new ReputationUnavailableException('the service is down', 503),
                new ReputationUnavailableException('the test scripted no further results'),
            ]
        );

        $this->assertTrue($rule->evaluate($request));
        $this->assertTrue($rule->evaluate($request));
        $this->assertTrue($rule->evaluate($request), 'The third request is served from the cached failure.');
    }

    /**
     * An `on_error` nobody recognises fails open, and says which values exist.
     *
     * Silently accepting it would leave somebody believing they had configured
     * a policy they had not.
     */
    public function testAnUnknownErrorPolicyWarnsAndFailsOpen(): void
    {
        $handler = $this->captureLogs();
        $rule = $this->rule(
            ['on_error' => 'abort'],
            [new ReputationUnavailableException('the service is down', 503)]
        );

        $this->assertFalse($rule->evaluate($this->getRequest('203.0.113.5')));
        $this->assertTrue($handler->hasWarningContaining('on_error is not a policy this rule has'));
    }

    /**
     * Two providers asked about one address never read each other's verdicts.
     *
     * Their scales mean different things: 4 out of 100 is clean and 4 out of 5
     * is not.
     */
    public function testVerdictsAreCachedPerProvider(): void
    {
        $request = $this->getRequest('203.0.113.5');

        $first = $this->rule(['threshold' => 75, 'slug' => 'service-a'], [new ReputationVerdict(100.0)]);
        $second = $this->rule(['threshold' => 75, 'slug' => 'service-b'], [new ReputationVerdict(0.0)]);

        $this->assertTrue($first->evaluate($request));
        $this->assertFalse($second->evaluate($request), 'The second service has its own cache namespace.');
    }

    /**
     * A rule with no `provider` named uses the generic HTTP one.
     */
    public function testTheDefaultProviderIsTheGenericHttpOne(): void
    {
        $rule = new Reputation([], [
            'url' => 'https://reputation.example.com/v1/score?ip={ip}',
            'score_path' => 'data.score',
            'cache_dir' => $this->cacheDir,
        ]);

        $this->assertSame('Reputation', $rule->getName());
        $this->assertStringContainsString('reputation service', $rule->getDescription());

        // Private space, so the generic provider's own `knowsAbout()` answers
        // no and the rule returns without opening a socket -- having resolved
        // `http` on the way past, which is what this is asserting.
        $this->assertFalse($rule->evaluate($this->getRequest('10.0.0.4')));
    }

    /**
     * A cache lifetime that is not a number degrades to the provider's default.
     *
     * Reputation is corroborating evidence: `cache_ttl: "a day"` is not a
     * reason to stop serving. It is still said out loud, because a silently
     * ignored setting is an afternoon spent wondering why it did nothing.
     */
    public function testAnUnusableCacheLifetimeWarnsAndUsesTheDefault(): void
    {
        $handler = $this->captureLogs();
        $request = $this->getRequest('203.0.113.5');
        $rule = $this->rule(
            ['threshold' => 75, 'cache_ttl' => 'a day'],
            [new ReputationVerdict(100.0)]
        );

        $this->assertTrue($rule->evaluate($request));
        $this->assertTrue($rule->evaluate($request), 'The default lifetime still caches the verdict.');
        $this->assertTrue($handler->hasWarningContaining('cache_ttl is not a number'));
    }

    /**
     * A provider that cannot be built surfaces as a rule that is not running.
     *
     * `Firewall::getFailedRules()` reports a rule whose construction throws,
     * and building the provider lazily is what routes an unusable `provider:`
     * or `url:` into that report rather than into a warning per request.
     */
    public function testAnUnusableProviderStopsTheRule(): void
    {
        $rule = new Reputation([], ['provider' => 'spamhaus']);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/resolves to no class/');

        $rule->evaluate($this->getRequest('203.0.113.5'));
    }

    /**
     * A verdict cached by an earlier release is still a verdict.
     *
     * Entries written before 2.27.0 have the shape AbuseIPDB's own cache used,
     * under the same file names. Ignoring them would make an upgrade re-ask
     * about every address the firewall had already paid to learn about -- 1,000
     * checks a day is not a budget to spend twice, and a cache miss storm is
     * the kind of slow morning nobody diagnoses.
     */
    public function testAVerdictCachedByAnEarlierReleaseIsStillRead(): void
    {
        mkdir($this->cacheDir, 0775, true);

        file_put_contents(
            $this->cacheDir . '/abuseipdb-' . sha1('203.0.113.5') . '.json',
            (string) json_encode(['report' => [
                'abuse_confidence_score' => 100,
                'is_whitelisted' => false,
                'total_reports' => 42,
                'country_code' => 'RU',
            ]])
        );

        $rule = new AbuseIpdb([], [
            'api_key' => 'k',
            'threshold' => 75,
            'cache_dir' => $this->cacheDir,
        ]);

        $this->assertTrue(
            $rule->evaluate($this->getRequest('203.0.113.5')),
            'An entry written before the shared cache existed must still be usable.'
        );
    }

    /**
     * An old entry that says nothing usable is a miss, not a clean verdict.
     */
    public function testAnUnreadableLegacyEntryIsAMiss(): void
    {
        mkdir($this->cacheDir, 0775, true);

        file_put_contents(
            $this->cacheDir . '/abuseipdb-' . sha1('203.0.113.5') . '.json',
            (string) json_encode(['report' => ['something' => 'else']])
        );

        $rule = new class ([], ['api_key' => 'k', 'threshold' => 75, 'cache_dir' => $this->cacheDir]) extends AbuseIpdb {
            public function exposedRead(string $ip): ?ReputationVerdict
            {
                return $this->readCache($ip);
            }
        };

        $this->assertNull($rule->exposedRead('203.0.113.5'));
    }

    /**
     * The generic rule reads nothing from before it existed.
     *
     * Only AbuseIPDB had a cache to inherit, so only AbuseIPDB reads the old
     * shape -- a generic rule finding one would be reading a score on a scale
     * it knows nothing about.
     */
    public function testTheGenericRuleDoesNotReadLegacyEntries(): void
    {
        mkdir($this->cacheDir, 0775, true);

        $rule = new class ([], [
            'provider' => 'http',
            'url' => 'https://reputation.example.com/v1/score?ip={ip}',
            'score_path' => 'data.score',
            'cache_dir' => $this->cacheDir,
        ]) extends Reputation {
            public function exposedRead(string $ip): ?ReputationVerdict
            {
                return $this->readCache($ip);
            }

            public function exposedPath(string $ip): ?string
            {
                return $this->cachePath($ip);
            }
        };

        file_put_contents((string) $rule->exposedPath('203.0.113.5'), (string) json_encode([
            'report' => ['abuse_confidence_score' => 100],
        ]));

        $this->assertNull($rule->exposedRead('203.0.113.5'));
    }

    /**
     * Collect log records for the duration of a test.
     */
    private function captureLogs(): TestLogHandler
    {
        $handler = new TestLogHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        return $handler;
    }

    /**
     * Build the rule around a scripted provider.
     *
     * @param array<string, mixed> $config
     *   Rule config. `cache_dir` is filled in with this test's directory.
     * @param array<int, ReputationVerdict|ReputationUnavailableException> $results
     *   Results for successive lookups, in order.
     */
    private function rule(array $config, array $results): Reputation
    {
        $config['cache_dir'] ??= $this->cacheDir;

        $provider = new class ($config, $results) implements ReputationProviderInterface {
            /**
             * @param array<string, mixed> $config
             * @param array<int, ReputationVerdict|ReputationUnavailableException> $scripted
             */
            public function __construct(private readonly array $config, private array $scripted)
            {
            }

            public function getName(): string
            {
                return 'Test service';
            }

            public function getSlug(): string
            {
                return is_string($this->config['slug'] ?? null) ? $this->config['slug'] : 'test-service';
            }

            public function getConfigurationProblem(): ?string
            {
                return is_string($this->config['problem'] ?? null) ? $this->config['problem'] : null;
            }

            public function knowsAbout(string $ip): bool
            {
                return true;
            }

            public function check(string $ip): ReputationVerdict
            {
                $next = array_shift($this->scripted);

                if ($next === null) {
                    throw new ReputationUnavailableException('the test scripted no further results');
                }

                if ($next instanceof ReputationUnavailableException) {
                    throw $next;
                }

                return $next;
            }

            public function getDefaultCacheTtl(): int
            {
                return 3600;
            }

            public function getDefaultErrorCacheTtl(): int
            {
                return 300;
            }
        };

        return new class ([], $config, $provider) extends Reputation {
            /**
             * @param array<int|string, mixed> $metadata
             * @param array<int|string, mixed> $config
             */
            public function __construct(array $metadata, array $config, private readonly ReputationProviderInterface $scripted)
            {
                parent::__construct($metadata, $config);
            }

            /**
             * {@inheritdoc}
             */
            protected function provider(): ReputationProviderInterface
            {
                return $this->scripted;
            }
        };
    }
}
