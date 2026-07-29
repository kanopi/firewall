<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Plugins\AbuseIpdb;
use Kanopi\Firewall\Plugins\Crs;
use Kanopi\Firewall\Plugins\IpAddress;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Plugins\RateLimit;
use Kanopi\Firewall\Plugins\Url;
use Kanopi\Firewall\Plugins\UserAgent;
use Kanopi\Firewall\Plugins\VulnerabilityScore;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Contract test for the polarity of PluginInterface::evaluate().
 *
 * Every plugin must answer the same question the same way: TRUE means "my
 * rules matched this request, apply my `response:`", FALSE means "not mine,
 * keep going". PluginManager::evaluate() is the only consumer and it treats
 * a truthy return as a match.
 *
 * A plugin that inverts this is worse than useless — with `response: block`
 * it rejects benign traffic and waves attacks through. That shipped once
 * (issue #89, the CRS plugin), because each plugin's own test file was free
 * to encode whichever convention its author assumed. This file gives the
 * convention a single home: add a plugin, add a row, and an inverted
 * implementation cannot pass.
 *
 * Each case supplies one request that must match and one that must not.
 *
 * GeoLocation and Asn are absent deliberately — both need MaxMind .mmdb
 * databases that are not available in a plain unit-test run. Their polarity
 * is covered by the integration suite.
 */
class PluginPolarityTest extends AbstractTestCase
{
    /**
     * Address the AbuseIPDB case pre-scores above the threshold.
     */
    private const ABUSEIPDB_REPORTED_IP = '203.0.113.66';

    /**
     * Address the AbuseIPDB case pre-scores at zero.
     */
    private const ABUSEIPDB_CLEAN_IP = '203.0.113.77';

    /**
     * @return array<string, array{callable(): PluginInterface, callable(): Request, callable(): Request}>
     */
    public static function pluginProvider(): array
    {
        return [
            'IpAddress' => [
                fn (): PluginInterface => new IpAddress([], ['203.0.113.10', '198.51.100.0/24']),
                fn (): Request => self::browserRequest('/', ['REMOTE_ADDR' => '203.0.113.10']),
                fn (): Request => self::browserRequest('/', ['REMOTE_ADDR' => '192.0.2.55']),
            ],
            'Url' => [
                fn (): PluginInterface => new Url([], ['path@starts_with:/admin']),
                fn (): Request => self::browserRequest('/admin/users'),
                fn (): Request => self::browserRequest('/about'),
            ],
            'UserAgent' => [
                fn (): PluginInterface => new UserAgent([], ['bot:true']),
                fn (): Request => self::browserRequest('/', [
                    'HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                ]),
                fn (): Request => self::browserRequest('/'),
            ],
            'VulnerabilityScore' => [
                fn (): PluginInterface => new VulnerabilityScore([], [
                    'scoring' => [
                        'patterns' => [
                            [
                                'pattern'   => '/union.*select/i',
                                'score'     => 60,
                                'type'      => 'regex',
                                'locations' => ['uri', 'query_string'],
                            ],
                        ],
                    ],
                    'risk_levels' => [
                        'low'  => ['threshold' => 0,  'block' => false],
                        'high' => ['threshold' => 50, 'block' => true],
                    ],
                ]),
                fn (): Request => self::browserRequest('/?id=1 UNION SELECT password FROM users'),
                fn (): Request => self::browserRequest('/?id=42'),
            ],
            'RateLimit' => [
                fn (): PluginInterface => new RateLimit(
                    ['default_rate' => 1, 'default_sample' => 60],
                    [['path' => '/*', 'rate' => 1, 'sample' => 60]],
                ),
                // The first call inside the test consumes the single allowed
                // request, so the assertion below sees the limit exceeded.
                fn (): Request => self::browserRequest('/burst'),
                fn (): Request => self::browserRequest('/quiet'),
            ],
            'Crs' => [
                fn (): PluginInterface => new Crs([], ['paranoia' => 1, 'mode' => 'block']),
                fn (): Request => self::browserRequest('/?id=1 UNION SELECT password FROM users'),
                fn (): Request => self::browserRequest('/?q=hello world'),
            ],
            // Seeded through the cache rather than a stubbed subclass, so this
            // exercises the shipped class and never touches the network: one
            // address pre-scored above the threshold, one below.
            'AbuseIpdb' => [
                fn (): PluginInterface => new AbuseIpdb([], [
                    'api_key'   => 'polarity-test-key',
                    'threshold' => 75,
                    'cache_dir' => self::seedAbuseIpdbCache(),
                ]),
                fn (): Request => self::browserRequest('/', ['REMOTE_ADDR' => self::ABUSEIPDB_REPORTED_IP]),
                fn (): Request => self::browserRequest('/', ['REMOTE_ADDR' => self::ABUSEIPDB_CLEAN_IP]),
            ],
        ];
    }

    /**
     * Write the two AbuseIPDB cache entries the polarity case relies on.
     *
     * @return string
     *   The cache directory to hand the plugin.
     */
    private static function seedAbuseIpdbCache(): string
    {
        $directory = sys_get_temp_dir() . '/abuseipdb-polarity';
        if (!is_dir($directory)) {
            mkdir($directory, 0775, true);
        }

        $entries = [
            self::ABUSEIPDB_REPORTED_IP => 100,
            self::ABUSEIPDB_CLEAN_IP    => 0,
        ];

        foreach ($entries as $ip => $score) {
            file_put_contents(
                $directory . '/abuseipdb-' . sha1((string) $ip) . '.json',
                (string) json_encode(['report' => [
                    'abuse_confidence_score' => $score,
                    'is_whitelisted'         => false,
                    'total_reports'          => $score > 0 ? 42 : 0,
                    'country_code'           => 'RU',
                ]]),
            );
        }

        return $directory;
    }

    /**
     * A request the plugin's rules cover must return TRUE.
     *
     * @param callable(): PluginInterface $makePlugin
     * @param callable(): Request $makeMatching
     * @param callable(): Request $makeNonMatching
     */
    #[DataProvider('pluginProvider')]
    public function testMatchingRequestReturnsTrue(
        callable $makePlugin,
        callable $makeMatching,
        callable $makeNonMatching,
    ): void {
        $this->skipIfUnavailable($makePlugin);
        $plugin = $makePlugin();
        $request = $makeMatching();

        // RateLimit only matches once its window is already full, so prime it.
        if ($plugin instanceof RateLimit) {
            $plugin->evaluate($request);
        }

        $this->assertTrue(
            $plugin->evaluate($request),
            sprintf(
                '%s::evaluate() must return TRUE for a request its rules match. '
                . 'Returning FALSE inverts the plugin: with `response: block` it '
                . 'would let this request through and block everything else.',
                $plugin::class,
            ),
        );
    }

    /**
     * A request outside the plugin's rules must return FALSE.
     *
     * @param callable(): PluginInterface $makePlugin
     * @param callable(): Request $makeMatching
     * @param callable(): Request $makeNonMatching
     */
    #[DataProvider('pluginProvider')]
    public function testNonMatchingRequestReturnsFalse(
        callable $makePlugin,
        callable $makeMatching,
        callable $makeNonMatching,
    ): void {
        $this->skipIfUnavailable($makePlugin);
        $plugin = $makePlugin();

        $this->assertFalse(
            $plugin->evaluate($makeNonMatching()),
            sprintf(
                '%s::evaluate() must return FALSE for a request its rules do not '
                . 'match, so evaluation continues to the next plugin.',
                $plugin::class,
            ),
        );
    }

    /**
     * Every shipped plugin should appear in the provider.
     *
     * Keeps the contract from silently going stale: a new plugin added to
     * src/Plugins/ without a polarity case fails here rather than shipping
     * unverified.
     */
    public function testEveryShippedPluginIsCovered(): void
    {
        $exempt = [
            // Need MaxMind .mmdb databases — covered in the integration suite.
            'GeoLocation',
            'Asn',
        ];

        $shipped = [];
        foreach ((array) glob(__DIR__ . '/../../../src/Plugins/*.php') as $file) {
            $name = basename((string) $file, '.php');
            if (str_starts_with($name, 'Abstract') || str_ends_with($name, 'Interface') || $name === 'PluginManager') {
                continue;
            }
            $shipped[] = $name;
        }

        $covered = array_merge(array_keys(self::pluginProvider()), $exempt);
        $missing = array_diff($shipped, $covered);

        $this->assertSame([], array_values($missing), sprintf(
            'These plugins have no polarity case: %s. Add one to '
            . 'PluginPolarityTest::pluginProvider() so an inverted evaluate() '
            . 'cannot ship (see issue #89).',
            implode(', ', $missing),
        ));
    }

    /**
     * Skip a case whose backing engine is not installed in this environment.
     */
    private function skipIfUnavailable(callable $makePlugin): void
    {
        $plugin = $makePlugin();
        if ($plugin instanceof Crs
            && !is_file(__DIR__ . '/../../../vendor/kanopi/crs-engine/rules/compiled.php')) {
            $this->markTestSkipped('CRS engine rules not available — run `composer install` to pull them.');
        }
    }

    /**
     * Build a browser-shaped request so CRS protocol rules do not fire on the
     * scaffolding rather than the payload under test.
     *
     * @param array<string, string> $serverOverrides
     */
    private static function browserRequest(string $uri, array $serverOverrides = []): Request
    {
        [$path, $rawQuery] = array_pad(explode('?', $uri, 2), 2, '');
        parse_str($rawQuery, $query);

        // Re-encode the query string. A raw space in REQUEST_URI is an invalid
        // request line and trips CRS protocol-enforcement rules, which would
        // make a "non-matching" case match for a reason the test never intended.
        $requestUri = $query === [] ? $path : $path . '?' . http_build_query($query);

        return new Request(
            query: $query,
            server: array_merge([
                'REMOTE_ADDR'          => '203.0.113.10',
                'REQUEST_METHOD'       => 'GET',
                'REQUEST_URI'          => $requestUri,
                'SERVER_PROTOCOL'      => 'HTTP/1.1',
                'HTTP_HOST'            => 'example.com',
                'HTTP_USER_AGENT'      => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
                'HTTP_ACCEPT'          => 'text/html,application/xhtml+xml',
                'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.5',
            ], $serverOverrides),
        );
    }
}
