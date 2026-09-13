<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Reputation;

require_once __DIR__ . '/../../Traits/ReputationNamespaceOverrides.php';

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\ReputationUnavailableException;
use Kanopi\Firewall\Reputation\HttpReputationProvider;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Pointing the firewall at somebody's own scoring endpoint (#204).
 *
 * This is the provider nobody writes PHP for, so its configuration is the thing
 * most likely to be wrong, and wrong in ways that are silent: a URL that never
 * varies, a path that stopped resolving after the endpoint changed shape, a
 * token in a query string reaching a log file. Each of those has a test.
 *
 * The stream wrapper is shimmed, so no socket is opened -- see
 * tests/Traits/ReputationNamespaceOverrides.php.
 */
final class HttpReputationProviderTest extends AbstractTestCase
{
    protected function tearDown(): void
    {
        // Process-global. A leaked flag would feed a canned HTTP response to
        // every later test in the run.
        $GLOBALS['fake_reputation_http_response'] = null;
        $GLOBALS['fake_reputation_http_handles'] = [];
        $GLOBALS['fake_reputation_http_urls'] = [];

        parent::tearDown();
    }

    /**
     * A JSON body with a score in it becomes a verdict.
     */
    public function testAScoreAtTheConfiguredPathBecomesAVerdict(): void
    {
        $this->fakeResponse(200, (string) json_encode(['data' => ['score' => 82, 'allowlisted' => false]]));

        $verdict = $this->provider()->check('203.0.113.5');

        $this->assertSame(82.0, $verdict->score);
        $this->assertFalse($verdict->trusted);
    }

    /**
     * The address reaches the endpoint, encoded.
     *
     * IPv6 has colons in it, which belong to a URL's authority rather than its
     * query, so an unencoded address is how this would break on exactly the
     * addresses hardest to test with.
     */
    public function testTheAddressIsSubstitutedAndEncoded(): void
    {
        $this->fakeResponse(200, (string) json_encode(['data' => ['score' => 1]]));

        $this->provider()->check('2001:db8::1');

        $this->assertSame(
            ['https://reputation.example.com/v1/score?ip=2001%3Adb8%3A%3A1'],
            $GLOBALS['fake_reputation_http_urls']
        );
    }

    /**
     * `trusted_path` is read the way people write booleans in JSON.
     *
     * @param mixed $value
     *   What the endpoint returned at the trusted path.
     * @param bool $expected
     *   Whether the address should count as vouched for.
     */
    #[DataProvider('trustedValues')]
    public function testTrustedIsReadFromItsOwnPath(mixed $value, bool $expected): void
    {
        $this->fakeResponse(200, (string) json_encode(['data' => ['score' => 99, 'allowlisted' => $value]]));

        $this->assertSame($expected, $this->provider(['trusted_path' => 'data.allowlisted'])->check('203.0.113.5')->trusted);
    }

    /**
     * @return array<string, array{mixed, bool}>
     *   Keyed by what the endpoint returned.
     */
    public static function trustedValues(): array
    {
        return [
            'true' => [true, true],
            'the string true' => ['true', true],
            'the string yes' => ['yes', true],
            'one' => [1, true],
            'false' => [false, false],
            'the string false' => ['false', false],
            'zero' => [0, false],
            'absent' => [null, false],
        ];
    }

    /**
     * Without `trusted_path`, nothing is trusted.
     */
    public function testNoTrustedPathMeansNothingIsTrusted(): void
    {
        $this->fakeResponse(200, (string) json_encode(['data' => ['score' => 99, 'allowlisted' => true]]));

        $this->assertFalse($this->provider()->check('203.0.113.5')->trusted);
    }

    /**
     * A score that is not there is a failure, not a zero.
     *
     * The important test in this file. An endpoint that changed its shape, or
     * that answers `{"error": "..."}` with a 200, would otherwise score every
     * address at zero -- protection switched off, with a service that looks
     * healthy behind it. Failing instead means the rule fails open loudly.
     */
    public function testAMissingScoreIsAFailureRatherThanAZero(): void
    {
        $this->fakeResponse(200, (string) json_encode(['error' => 'unknown address']));

        $this->expectException(ReputationUnavailableException::class);
        $this->expectExceptionMessageMatches('/no score at `data\.score`/');

        $this->provider()->check('203.0.113.5');
    }

    /**
     * Everything a response can be that is not a verdict.
     *
     * @param int $status
     *   The status to answer with.
     * @param string $body
     *   The body to answer with.
     * @param string $expected
     *   Text the operator-facing message has to contain.
     */
    #[DataProvider('unusableResponses')]
    public function testAnUnusableResponseIsAFailure(int $status, string $body, string $expected): void
    {
        $this->fakeResponse($status, $body);

        $this->expectException(ReputationUnavailableException::class);
        $this->expectExceptionMessageMatches('/' . preg_quote($expected, '/') . '/');

        $this->provider()->check('203.0.113.5');
    }

    /**
     * @return array<string, array{int, string, string}>
     *   Keyed by what the endpoint did.
     */
    public static function unusableResponses(): array
    {
        return [
            'rejected the credentials' => [401, '{}', 'rejected the credentials'],
            'forbade it' => [403, '{}', 'rejected the credentials'],
            'has no such endpoint' => [404, '{}', 'does not know that endpoint'],
            'is rate limiting us' => [429, '{}', 'rate limiting this firewall'],
            'fell over' => [503, '{}', 'returned HTTP 503'],
            'said nothing' => [200, '', 'empty body'],
            'said something that is not JSON' => [200, '<html>maintenance</html>', 'not JSON'],
        ];
    }

    /**
     * A response with no status line at all is a failure in its own right.
     */
    public function testAResponseWithNoStatusLineIsAFailure(): void
    {
        $GLOBALS['fake_reputation_http_response'] = [
            'headers' => ['Content-Type: application/json'],
            'body' => (string) json_encode(['data' => ['score' => 99]]),
        ];

        $this->expectException(ReputationUnavailableException::class);
        $this->expectExceptionMessageMatches('/no parseable status/');

        $this->provider()->check('203.0.113.5');
    }

    /**
     * A host that cannot be reached says so without saying the credential.
     *
     * `query` auth puts the token in the URL, and this message reaches a log
     * line. Redaction is `SourceAuth`'s, the same one every rule source uses.
     */
    public function testAnUnreachableEndpointIsReportedWithoutItsCredential(): void
    {
        $GLOBALS['fake_reputation_http_response'] = false;

        $provider = $this->provider([
            'url' => 'https://reputation.example.com/v1/score?token=s3cret&ip={ip}',
        ]);

        try {
            $provider->check('203.0.113.5');
            $this->fail('An unreachable endpoint must throw.');
        } catch (ReputationUnavailableException $reputationUnavailableException) {
            $this->assertStringContainsString('could not reach', $reputationUnavailableException->getMessage());
            $this->assertStringNotContainsString('s3cret', $reputationUnavailableException->getMessage());
        }
    }

    /**
     * Bearer auth reaches the endpoint as a header.
     */
    public function testBearerAuthIsSentAsAHeader(): void
    {
        $this->fakeResponse(200, (string) json_encode(['data' => ['score' => 5]]));

        $provider = $this->provider(['auth' => ['type' => 'bearer', 'token' => 'abc123']]);

        // The shim cannot read request headers back, so this asserts the half
        // it can: a bearer credential does not end up in the URL, which is
        // where it would be logged, cached by a proxy and kept in an access
        // log for a year.
        $provider->check('203.0.113.5');

        $this->assertStringNotContainsString('abc123', (string) ($GLOBALS['fake_reputation_http_urls'][0] ?? ''));
    }

    /**
     * Query auth reaches the endpoint in the URL, because that is what it is.
     */
    public function testQueryAuthIsAppendedToTheUrl(): void
    {
        $this->fakeResponse(200, (string) json_encode(['data' => ['score' => 5]]));

        $this->provider(['auth' => ['type' => 'query', 'name' => 'key', 'value' => 'abc123']])->check('203.0.113.5');

        $this->assertStringContainsString('key=abc123', (string) ($GLOBALS['fake_reputation_http_urls'][0] ?? ''));
    }

    /**
     * A URL that does not name the address is refused at construction.
     *
     * It would return the same body for every visitor: a reputation check that
     * cannot fail and cannot help. Discovering that from a log line saying
     * every address scores 4 is the alternative.
     */
    public function testAUrlWithoutTheAddressIsRefused(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/does not contain `\{ip\}`/');

        new HttpReputationProvider(['url' => 'https://reputation.example.com/v1/score', 'score_path' => 'score']);
    }

    /**
     * And a refusal does not repeat the credential it was given.
     */
    public function testTheRefusalDoesNotEchoACredential(): void
    {
        try {
            new HttpReputationProvider([
                'url' => 'https://reputation.example.com/v1/score?token=s3cret',
                'score_path' => 'score',
            ]);
            $this->fail('A URL without {ip} must be refused.');
        } catch (ConfigurationException $configurationException) {
            $this->assertStringNotContainsString('s3cret', $configurationException->getMessage());
        }
    }

    /**
     * Everything else the configuration can be missing.
     *
     * @param array<string, mixed> $config
     *   The rule's config.
     * @param string $expected
     *   Text the message has to contain.
     */
    #[DataProvider('unusableConfigurations')]
    public function testAnUnusableConfigurationIsRefused(array $config, string $expected): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/' . preg_quote($expected, '/') . '/');

        new HttpReputationProvider($config);
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     *   Keyed by what is missing.
     */
    public static function unusableConfigurations(): array
    {
        return [
            'no url' => [['score_path' => 'score'], 'needs a `url`'],
            'a url that is not a string' => [['url' => 42, 'score_path' => 'score'], 'needs a `url`'],
            'no score_path' => [['url' => 'https://example.com/?ip={ip}'], 'needs a `score_path`'],
            'an auth that is not a map' => [
                ['url' => 'https://example.com/?ip={ip}', 'score_path' => 'score', 'auth' => 'bearer abc'],
                '`auth` must be a map',
            ],
            'an auth with no type' => [
                ['url' => 'https://example.com/?ip={ip}', 'score_path' => 'score', 'auth' => ['token' => 'abc']],
                'auth.type must be one of',
            ],
        ];
    }

    /**
     * Private space is skipped by default, and reachable when it is the point.
     *
     * A third-party service has nothing to say about `10.0.0.4`. A service on
     * your own network may be the only thing that does.
     */
    public function testPrivateSpaceIsSkippedUnlessTheServiceIsInternal(): void
    {
        $this->assertFalse($this->provider()->knowsAbout('10.0.0.4'));
        $this->assertTrue($this->provider()->knowsAbout('203.0.113.5'));

        $internal = $this->provider(['public_only' => false]);

        $this->assertTrue($internal->knowsAbout('10.0.0.4'));
        $this->assertFalse($internal->knowsAbout('not-an-address'));
    }

    /**
     * Two services never read each other's cached verdicts.
     *
     * Their scores are on different scales and mean different things, so the
     * slug that namespaces the cache is derived from the endpoint rather than
     * shared by every `http` provider.
     */
    public function testTheSlugIsDerivedFromTheEndpoint(): void
    {
        $this->assertSame('http-reputation-example-com', $this->provider()->getSlug());

        $this->assertSame(
            'http-scores-internal',
            $this->provider(['url' => 'https://scores.internal/?ip={ip}'])->getSlug()
        );
    }

    /**
     * A rule can name the service, so a log line says which one answered.
     */
    public function testTheProviderCanBeNamed(): void
    {
        $this->assertSame('Reputation service', $this->provider()->getName());
        $this->assertSame('Spamhaus', $this->provider(['provider_name' => ' Spamhaus '])->getName());
    }

    /**
     * It is ready as soon as it is built, because construction checks it.
     */
    public function testItIsConfiguredOnceItConstructs(): void
    {
        $this->assertNull($this->provider()->getConfigurationProblem());
    }

    /**
     * Its TTLs are its own: shorter than a service with a daily quota.
     */
    public function testItsCacheLifetimesAreItsOwn(): void
    {
        $this->assertSame(3600, $this->provider()->getDefaultCacheTtl());
        $this->assertSame(300, $this->provider()->getDefaultErrorCacheTtl());
    }

    /**
     * A provider pointed at the fixture endpoint.
     *
     * @param array<string, mixed> $config
     *   Overrides for the defaults.
     */
    private function provider(array $config = []): HttpReputationProvider
    {
        return new HttpReputationProvider($config + [
            'url' => 'https://reputation.example.com/v1/score?ip={ip}',
            'score_path' => 'data.score',
        ]);
    }

    /**
     * Answer the next call with this.
     */
    private function fakeResponse(int $status, string $body): void
    {
        $GLOBALS['fake_reputation_http_urls'] = [];
        $GLOBALS['fake_reputation_http_response'] = [
            'headers' => ['HTTP/1.1 ' . $status . ' ' . ($status === 200 ? 'OK' : 'Error')],
            'body' => $body,
        ];
    }
}
