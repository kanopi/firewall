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
        $GLOBALS['fake_reputation_http_requests'] = [];

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
            'said something that is not JSON' => [200, '<html>maintenance</html>', 'is not json'],
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
            'upstream' => 'https://reputation.example.com/v1/score?token=s3cret&ip={ip}',
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

        $provider = $this->provider([
            'upstream' => [
                'url' => 'https://reputation.example.com/v1/score?ip={ip}',
                'auth' => ['type' => 'bearer', 'token' => 'abc123'],
            ],
        ]);

        $provider->check('203.0.113.5');

        $this->assertContains('Authorization: Bearer abc123', $GLOBALS['fake_reputation_http_requests'][0]['header']);

        // And nowhere near the URL, which is where it would be logged, cached
        // by a proxy, and kept in an access log for a year.
        $this->assertStringNotContainsString('abc123', (string) ($GLOBALS['fake_reputation_http_urls'][0] ?? ''));
    }

    /**
     * Query auth reaches the endpoint in the URL, because that is what it is.
     */
    public function testQueryAuthIsAppendedToTheUrl(): void
    {
        $this->fakeResponse(200, (string) json_encode(['data' => ['score' => 5]]));

        $this->provider(['upstream' => [
            'url' => 'https://reputation.example.com/v1/score?ip={ip}',
            'auth' => ['type' => 'query', 'name' => 'key', 'value' => 'abc123'],
        ]])->check('203.0.113.5');

        $this->assertStringContainsString('key=abc123', (string) ($GLOBALS['fake_reputation_http_urls'][0] ?? ''));
    }

    /**
     * A POST, with the address in the body.
     *
     * The reason `upstream:` is the whole SourceUpstream block rather than a
     * `url:` of its own: a service that takes a JSON body needed `method`,
     * `body` and a content type, and every one of those already existed.
     */
    public function testItCanPostTheAddressInABody(): void
    {
        $this->fakeResponse(200, (string) json_encode(['data' => ['score' => 91]]));

        $provider = $this->provider([
            'upstream' => [
                'url' => 'https://reputation.example.com/v1/score',
                'method' => 'POST',
                'body' => '{"ip": "{ip}"}',
                'headers' => ['X-Tenant' => 'acme'],
            ],
        ]);

        $this->assertSame(91.0, $provider->check('203.0.113.5')->score);

        // The URL is the one configured -- no query string grew out of the
        // substitution -- and the address went in the body instead.
        $this->assertSame(
            ['https://reputation.example.com/v1/score'],
            $GLOBALS['fake_reputation_http_urls']
        );

        $sent = $GLOBALS['fake_reputation_http_requests'][0];

        $this->assertSame('POST', $sent['method']);
        $this->assertSame('{"ip": "203.0.113.5"}', $sent['content']);
        $this->assertContains('X-Tenant: acme', $sent['header']);
        $this->assertContains('Content-Type: application/json', $sent['header']);
    }

    /**
     * A body carrying an address is still valid JSON afterwards.
     *
     * `{ip}` inside a quoted string means the substitution has to be escaped
     * the way JSON escapes a string, or an address with a quote in it -- which
     * is not an address, but is what somebody would send at a firewall that
     * trusts a forwarded header -- would break the document or inject a field
     * into it.
     */
    public function testAnAddressSubstitutedIntoABodyIsEscaped(): void
    {
        $this->fakeResponse(200, (string) json_encode(['data' => ['score' => 1]]));

        $this->provider([
            'upstream' => [
                'url' => 'https://reputation.example.com/v1/score',
                'method' => 'POST',
                'body' => '{"ip": "{ip}", "tenant": "acme"}',
            ],
        ])->check('203.0.113.5" , "tenant": "someone-else');

        $sent = (string) ($GLOBALS['fake_reputation_http_requests'][0]['content'] ?? '');
        $decoded = json_decode($sent, true);

        $this->assertIsArray($decoded, 'The body must still be JSON: ' . $sent);
        $this->assertSame('acme', $decoded['tenant'], 'The address must not be able to overwrite a field.');
        $this->assertSame('203.0.113.5" , "tenant": "someone-else', $decoded['ip']);
    }

    /**
     * A score read out of plain text, by pattern.
     *
     * `score_path` addresses structure; a service answering `risk=82 reason=proxy`
     * has none. The pattern reads the raw body, so `format:` does not have to
     * mean anything for it.
     */
    public function testAScoreCanBeReadFromTextByPattern(): void
    {
        $this->fakeResponse(200, "risk=82 reason=open-proxy\n");

        $provider = $this->provider(['score_pattern' => '/risk=(\d+)/', 'score_path' => null]);

        $this->assertSame(82.0, $provider->check('203.0.113.5')->score);
    }

    /**
     * A pattern that does not match is a failure, not a zero.
     *
     * The same rule as a `score_path` that resolves to nothing, and for the
     * same reason: reading "no match" as a clean score turns a service that
     * changed its output into protection that is silently off.
     */
    public function testAPatternThatDoesNotMatchIsAFailure(): void
    {
        $this->fakeResponse(200, 'service unavailable, try later');

        $this->expectException(ReputationUnavailableException::class);
        $this->expectExceptionMessageMatches('/returned no score/');

        $this->provider(['score_pattern' => '/risk=(\d+)/', 'score_path' => null])->check('203.0.113.5');
    }

    /**
     * A line-oriented body is a list of lines, so a path still addresses it.
     *
     * This is the decoder registry doing the work: `txt` produces the same
     * list of records a rule source gets, and `score_path: 0` is the first of
     * them. No new concept for "the response is just the number".
     */
    public function testATextBodyIsDecodedIntoLines(): void
    {
        $this->fakeResponse(200, "82\n");

        $this->assertSame(82.0, $this->provider(['format' => 'txt', 'score_path' => '0'])->check('203.0.113.5')->score);
    }

    /**
     * XML, addressed with the same dot path as everything else.
     *
     * Attributes land under `@attributes`, which is SimpleXML's shape and the
     * one an API's own documentation will match.
     */
    public function testAnXmlBodyIsAddressedWithTheSamePath(): void
    {
        $this->fakeResponse(200, '<response><data score="77"/></response>');

        $verdict = $this->provider([
            'format' => 'xml',
            'score_path' => 'data.@attributes.score',
        ])->check('203.0.113.5');

        $this->assertSame(77.0, $verdict->score);
    }

    /**
     * An XML body carrying a DOCTYPE is refused rather than parsed.
     *
     * A response body is bytes somebody else's server produced. Every familiar
     * way of weaponising one -- an entity pointing at `file:///etc/passwd` or
     * an internal URL, or entities that expand to gigabytes -- starts with a
     * DOCTYPE, and nothing that publishes a score sends one.
     *
     * The refusal reaches the rule as a failed lookup, so the request is
     * allowed through rather than 500ing on a hostile response.
     */
    public function testAnXmlDoctypeIsRefused(): void
    {
        $this->fakeResponse(
            200,
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r><score>&x;</score></r>'
        );

        try {
            $this->provider(['format' => 'xml', 'score_path' => 'score'])->check('203.0.113.5');
            $this->fail('A DOCTYPE must be refused.');
        } catch (ReputationUnavailableException $reputationUnavailableException) {
            $this->assertStringContainsString('DOCTYPE', $reputationUnavailableException->getMessage());
            $this->assertStringNotContainsString('root:', $reputationUnavailableException->getMessage());
        }
    }

    /**
     * A body in a format the rule did not declare is a failure.
     */
    public function testABodyInAnotherFormatIsAFailure(): void
    {
        $this->fakeResponse(200, 'score: 82');

        $this->expectException(ReputationUnavailableException::class);
        $this->expectExceptionMessageMatches('/is not json/');

        $this->provider()->check('203.0.113.5');
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
        $this->expectExceptionMessageMatches('/never mentions `\{ip\}`/');

        new HttpReputationProvider(['upstream' => 'https://reputation.example.com/v1/score', 'score_path' => 'score']);
    }

    /**
     * And a refusal does not repeat the credential it was given.
     */
    public function testTheRefusalDoesNotEchoACredential(): void
    {
        try {
            new HttpReputationProvider([
                'upstream' => 'https://reputation.example.com/v1/score?token=s3cret',
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
            'no upstream' => [['score_path' => 'score'], 'needs an `upstream`'],
            'an upstream that is neither a string nor a map' => [
                ['upstream' => 42, 'score_path' => 'score'],
                'must be a URL string or a map',
            ],
            'an upstream with no url' => [
                ['upstream' => ['method' => 'POST'], 'score_path' => 'score'],
                'needs a non-empty "url"',
            ],
            'no way of finding a score' => [
                ['upstream' => 'https://example.com/?ip={ip}'],
                'needs either a `score_path`',
            ],
            'a method nothing can send' => [
                ['upstream' => ['url' => 'https://example.com/?ip={ip}', 'method' => 'DELETE'], 'score_path' => 'score'],
                'upstream.method must be one of',
            ],
            'an auth that is not a map' => [
                ['upstream' => ['url' => 'https://example.com/?ip={ip}', 'auth' => 'bearer abc'], 'score_path' => 'score'],
                'auth must be a map',
            ],
            'an auth with no type' => [
                ['upstream' => ['url' => 'https://example.com/?ip={ip}', 'auth' => ['token' => 'abc']], 'score_path' => 'score'],
                'auth.type must be one of',
            ],
            'a credential over plain http' => [
                [
                    'upstream' => ['url' => 'http://example.com/?ip={ip}', 'auth' => ['type' => 'bearer', 'token' => 'x']],
                    'score_path' => 'score',
                ],
                'refusing to send credentials over plain http',
            ],
            'a format nothing decodes' => [
                ['upstream' => 'https://example.com/?ip={ip}', 'score_path' => 'score', 'format' => 'protobuf'],
                'No decoder registered for format',
            ],
            'a pattern that does not compile' => [
                ['upstream' => 'https://example.com/?ip={ip}', 'score_pattern' => '/risk=(/'],
                'not a usable regular expression',
            ],
            'a pattern that captures nothing' => [
                ['upstream' => 'https://example.com/?ip={ip}', 'score_pattern' => '/risk=\\d+/'],
                'has no capturing group',
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
            $this->provider(['upstream' => 'https://scores.internal/?ip={ip}'])->getSlug()
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
            'upstream' => 'https://reputation.example.com/v1/score?ip={ip}',
            'score_path' => 'data.score',
        ]);
    }

    /**
     * Answer the next call with this.
     */
    private function fakeResponse(int $status, string $body): void
    {
        $GLOBALS['fake_reputation_http_urls'] = [];
        $GLOBALS['fake_reputation_http_requests'] = [];
        $GLOBALS['fake_reputation_http_response'] = [
            'headers' => ['HTTP/1.1 ' . $status . ' ' . ($status === 200 ? 'OK' : 'Error')],
            'body' => $body,
        ];
    }
}
