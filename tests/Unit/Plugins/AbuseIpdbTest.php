<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Exception\ReputationUnavailableException;
use Kanopi\Firewall\Plugins\AbuseIpdb;
use Kanopi\Firewall\Reputation\AbuseIpdbProvider;
use Kanopi\Firewall\Reputation\ReputationProviderInterface;
use Kanopi\Firewall\Reputation\ReputationVerdict;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Tests for the AbuseIPDB reputation plugin.
 *
 * The network call is the one thing these tests replace: the rule's provider is
 * a real `AbuseIpdbProvider` with `check()` scripted, counting how often it was
 * asked. Everything else — the threshold comparison, the cache, the fail-open
 * path, the routable-address check — is the shipped code.
 *
 * The seam moved from the plugin's own `fetch()` to the provider when the
 * provider interface was extracted (#204). What it stands for did not: this
 * file is still the AbuseIPDB rule's decisions, and `AbuseIpdbTransportTest` is
 * still everything inside the call.
 *
 * Call counting is load-bearing rather than incidental. The free tier allows
 * 1,000 checks a day, so "how many times did this call the API" is a
 * correctness property of the plugin, not an optimisation detail.
 */
class AbuseIpdbTest extends AbstractTestCase
{
    /**
     * Per-test cache directory, removed on tear-down.
     */
    private string $cacheDir;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->cacheDir = sys_get_temp_dir() . '/abuseipdb-test-' . bin2hex(random_bytes(6));
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        foreach ((array) glob($this->cacheDir . '/*') as $file) {
            @unlink((string) $file);
        }
        @rmdir($this->cacheDir);

        parent::tearDown();
    }

    public function testMissingApiKeyMatchesNothingAndCallsNoApi(): void
    {
        $plugin = $this->plugin(['api_key' => null, 'threshold' => 75], [self::report(100)]);

        $this->assertFalse(
            $plugin->evaluate($this->getRequest('203.0.113.5')),
            'With no api_key the plugin must be inert. Matching here would block every request for someone who added the plugin before provisioning a key.',
        );
        $this->assertSame(0, $plugin->fetchCount(), 'An unconfigured plugin must not call the API.');
    }

    public function testPrivateAddressIsNotLookedUp(): void
    {
        $plugin = $this->plugin([], [self::report(100)]);

        $this->assertFalse($plugin->evaluate($this->getRequest('10.0.0.5')));
        $this->assertSame(0, $plugin->fetchCount(), 'Private space cannot be in AbuseIPDB — looking it up spends quota to learn nothing.');
    }

    public function testReservedAddressIsNotLookedUp(): void
    {
        $plugin = $this->plugin([], [self::report(100)]);

        $this->assertFalse($plugin->evaluate($this->getRequest('127.0.0.1')));
        $this->assertSame(0, $plugin->fetchCount());
    }

    public function testScoreAtTheThresholdMatches(): void
    {
        $plugin = $this->plugin(['threshold' => 75], [self::report(75)]);

        $this->assertTrue(
            $plugin->evaluate($this->getRequest('203.0.113.5')),
            'The threshold is inclusive — a score equal to it must match.',
        );
    }

    public function testScoreOneUnderTheThresholdDoesNotMatch(): void
    {
        $plugin = $this->plugin(['threshold' => 75], [self::report(74)]);

        $this->assertFalse($plugin->evaluate($this->getRequest('203.0.113.5')));
    }

    public function testWhitelistedAddressNeverMatchesEvenAtFullConfidence(): void
    {
        $plugin = $this->plugin(['threshold' => 75], [self::report(100, true)]);

        $this->assertFalse(
            $plugin->evaluate($this->getRequest('203.0.113.5')),
            'AbuseIPDB whitelists known-good infrastructure such as search-engine crawlers. Blocking one because it also carries reports would take out legitimate traffic.',
        );
    }

    public function testLookupFailureAllowsTheRequestThrough(): void
    {
        $plugin = $this->plugin([], [self::failure('AbuseIPDB daily quota is exhausted', 429)]);

        $this->assertFalse(
            $plugin->evaluate($this->getRequest('203.0.113.5')),
            'The plugin fails open: a spent quota or an outage must not become a block.',
        );
    }

    public function testVerdictIsCachedSoRepeatVisitsCostNoQuota(): void
    {
        $plugin = $this->plugin(['threshold' => 75], [self::report(100)]);
        $request = $this->getRequest('203.0.113.5');

        $this->assertTrue($plugin->evaluate($request));
        $this->assertTrue($plugin->evaluate($request), 'The cached verdict must produce the same decision.');
        $this->assertSame(1, $plugin->fetchCount(), 'A second request from the same address must be served from cache.');
    }

    public function testDifferentAddressesEachCostOneLookup(): void
    {
        $plugin = $this->plugin(['threshold' => 75], [self::report(100), self::report(0)]);

        $this->assertTrue($plugin->evaluate($this->getRequest('203.0.113.5')));
        $this->assertFalse($plugin->evaluate($this->getRequest('203.0.113.6')));
        $this->assertSame(2, $plugin->fetchCount(), 'The cache is keyed per address, so a new address is a new lookup.');
    }

    public function testExpiredVerdictIsRefetched(): void
    {
        $plugin = $this->plugin(['cache_ttl' => 0, 'threshold' => 75], [self::report(100), self::report(0)]);

        $this->assertTrue($plugin->evaluate($this->getRequest('203.0.113.5')));
        $this->assertFalse(
            $plugin->evaluate($this->getRequest('203.0.113.5')),
            'With the TTL expired the second call must consult the API again and use its fresher answer.',
        );
        $this->assertSame(2, $plugin->fetchCount());
    }

    public function testFailureIsCachedSoAnOutageDoesNotCostEveryRequestATimeout(): void
    {
        $plugin = $this->plugin(
            ['threshold' => 75],
            [self::failure('could not reach the AbuseIPDB API', null), self::report(100)],
        );
        $request = $this->getRequest('203.0.113.5');

        $this->assertFalse($plugin->evaluate($request));
        $this->assertFalse($plugin->evaluate($request));
        $this->assertSame(
            1,
            $plugin->fetchCount(),
            'A failure must be remembered briefly. Retrying on every request would make each one wait the full timeout, which is a slowdown wearing fail-open as a disguise.',
        );
    }

    public function testCachedFailureExpiresSoRecoveryIsPickedUp(): void
    {
        $plugin = $this->plugin(
            ['error_cache_ttl' => 0, 'threshold' => 75],
            [self::failure('could not reach the AbuseIPDB API', null), self::report(100)],
        );
        $request = $this->getRequest('203.0.113.5');

        $this->assertFalse($plugin->evaluate($request));
        $this->assertTrue(
            $plugin->evaluate($request),
            'Once the short failure window lapses the plugin must try again rather than staying blind.',
        );
        $this->assertSame(2, $plugin->fetchCount());
    }

    public function testCorruptCacheEntryIsRefetchedRatherThanTrusted(): void
    {
        $plugin = $this->plugin(['threshold' => 75], [self::report(100)]);
        $path = $plugin->exposedCachePath('203.0.113.5');

        $this->assertNotNull($path);
        file_put_contents((string) $path, '{ this is not json');

        $this->assertTrue(
            $plugin->evaluate($this->getRequest('203.0.113.5')),
            'A truncated or hand-edited entry must count as a miss, not as a clean verdict.',
        );
        $this->assertSame(1, $plugin->fetchCount());
    }

    public function testCacheFileNameDoesNotContainTheAddress(): void
    {
        $plugin = $this->plugin([], []);
        $path = (string) $plugin->exposedCachePath('203.0.113.5');

        $this->assertStringNotContainsString('203.0.113.5', $path, 'Client addresses should not be readable from a directory listing.');
        $this->assertStringContainsString(sha1('203.0.113.5'), $path);
    }

    public function testNonNumericThresholdFallsBackToTheDefault(): void
    {
        $plugin = $this->plugin(['threshold' => 'very high'], [self::report(80)]);

        $this->assertTrue(
            $plugin->evaluate($this->getRequest('203.0.113.5')),
            'An unusable threshold must degrade to the documented default of 75, not disable the plugin or block everything.',
        );
    }

    public function testBlockStatusAndDurationAreConfigurable(): void
    {
        $plugin = $this->plugin(['block_status' => 429, 'block_duration' => 60], []);

        $this->assertSame(429, $plugin->getStatusCode());
        $this->assertSame(60, $plugin->getExpirationTime());
    }

    public function testBlockStatusAndDurationHaveDefaults(): void
    {
        $plugin = $this->plugin([], []);

        $this->assertSame(403, $plugin->getStatusCode());
        $this->assertSame(3600, $plugin->getExpirationTime());
    }



    public function testNameAndDescriptionAreReported(): void
    {
        $plugin = $this->plugin([], []);

        $this->assertSame('AbuseIPDB', $plugin->getName());
        $this->assertStringContainsString('AbuseIPDB', $plugin->getDescription());
    }

    /**
     * A scripted verdict.
     *
     * @param int $score
     *   The abuse confidence score.
     * @param bool $whitelisted
     *   Whether AbuseIPDB vouches for the address.
     *
     * @return ReputationVerdict
     *   What the provider would have returned.
     */
    private static function report(int $score, bool $whitelisted = false): ReputationVerdict
    {
        return new ReputationVerdict((float) $score, $whitelisted, [
            'abuse_confidence_score' => $score,
            'total_reports' => $score > 0 ? 7 : 0,
            'country_code' => 'RU',
        ]);
    }

    /**
     * A scripted failure.
     *
     * @param string $error
     *   What the provider could not do.
     * @param int|null $status
     *   The status behind it, when there was one.
     *
     * @return ReputationUnavailableException
     *   What the provider would have thrown.
     */
    private static function failure(string $error, ?int $status): ReputationUnavailableException
    {
        return new ReputationUnavailableException($error, $status);
    }

    /**
     * Build the rule with the network replaced by scripted results.
     *
     * `api_key` defaults to a placeholder because most cases want a configured
     * rule; the unconfigured case omits it explicitly.
     *
     * @param array<string, mixed> $config
     *   Plugin config. `cache_dir` is filled in with this test's directory.
     * @param array<int, ReputationVerdict|ReputationUnavailableException> $results
     *   Results for successive lookups, in order.
     */
    private function plugin(array $config, array $results): AbuseIpdb
    {
        $config['cache_dir'] ??= $this->cacheDir;

        // Most cases want a configured rule. Pass an explicit
        // `'api_key' => null` to exercise the unconfigured path.
        if (!array_key_exists('api_key', $config)) {
            $config['api_key'] = 'test-key';
        }

        // A real provider with only the call replaced, so the api_key check
        // and the routable-address check under test are the shipped ones.
        $provider = new class ($config, $results) extends AbuseIpdbProvider {
            /**
             * How many times the API was asked.
             */
            public int $calls = 0;

            /**
             * @param array<int|string, mixed> $config
             * @param array<int, ReputationVerdict|ReputationUnavailableException> $scripted
             */
            public function __construct(array $config, private array $scripted)
            {
                parent::__construct($config);
            }

            /**
             * {@inheritdoc}
             */
            public function check(string $ip): ReputationVerdict
            {
                $this->calls++;

                $next = array_shift($this->scripted);

                if ($next === null) {
                    throw new ReputationUnavailableException('the test scripted no further results');
                }

                if ($next instanceof ReputationUnavailableException) {
                    throw $next;
                }

                return $next;
            }
        };

        return new class ([], $config, $provider) extends AbuseIpdb {
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

            /**
             * How many times the API was asked.
             */
            public function fetchCount(): int
            {
                /** @phpstan-ignore-next-line — the double this test supplies. */
                return $this->scripted->calls;
            }

            /**
             * Expose cachePath() for assertions.
             */
            public function exposedCachePath(string $ip): ?string
            {
                return $this->cachePath($ip);
            }
        };
    }
}
