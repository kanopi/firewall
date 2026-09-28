<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Plugins\RateLimit;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Composable rate-limit keys (#200).
 *
 * The counts were always stored under `rate:{client_ip}:{rule_pattern}`, and neither half
 * was configurable. Three things followed, and each has a test here:
 *
 * 1. **The identity half was always the IP.** Credential stuffing across 10,000 addresses
 *    at three attempts each stays under a 10-per-5-minutes rule on every bucket, and the
 *    account is gone. A whole office behind one NAT shares one bucket.
 * 2. **The path half was the rule pattern, not the request path.** `/api/*` at 100/min was
 *    100 across every endpoint under it, combined.
 * 3. **Everything unmatched shared one bucket per visitor.**
 */
class ComposableRateKeyTest extends AbstractTestCase
{
    /**
     * @param array<string, mixed> $metadata
     */
    private function plugin(array $metadata = []): object
    {
        return new class($metadata, []) extends RateLimit {
            /**
             * @param array<string, mixed> $rule
             */
            public function key(Request $request, array $rule): string
            {
                return $this->buildRateKey($request, $rule);
            }
        };
    }

    /**
     * @param array<string, string> $post
     * @param array<string, string> $server
     */
    private function request(
        string $path = '/login',
        array $post = [],
        string $ip = '203.0.113.1',
        array $server = []
    ): Request {
        return Request::create($path, $post === [] ? 'GET' : 'POST', $post, [], [], ['REMOTE_ADDR' => $ip] + $server);
    }

    /**
     * Declaring nothing produces the key every release before 2.27.0 produced,
     * byte for byte.
     *
     * Not "an equivalent key" — the same string. A hashed default would have reset every
     * counter on every install at the moment they upgraded, which is a window nobody asked
     * for on a firewall.
     */
    public function testTheDefaultKeyIsUnchanged(): void
    {
        $this->assertSame(
            'rate:203.0.113.1:/login',
            $this->plugin()->key($this->request(), ['path' => '/login'])
        );
    }

    /**
     * Declaring the default explicitly is still the default.
     */
    public function testDeclaringTheDefaultExplicitlyChangesNothing(): void
    {
        $this->assertSame(
            'rate:203.0.113.1:/login',
            $this->plugin()->key($this->request(), ['path' => '/login', 'key' => ['client_ip', 'rule_pattern']])
        );
    }

    /**
     * Consequence 1: count by account, across every address.
     */
    public function testCountingByAccountIgnoresTheAddress(): void
    {
        $plugin = $this->plugin();
        $rule = ['path' => '/login', 'key' => ['post.name']];

        $this->assertSame(
            $plugin->key($this->request(post: ['name' => 'alice'], ip: '203.0.113.1'), $rule),
            $plugin->key($this->request(post: ['name' => 'alice'], ip: '198.51.100.9'), $rule),
            'A botnet is 10,000 addresses attacking one account. They must share a bucket.'
        );

        $this->assertNotSame(
            $plugin->key($this->request(post: ['name' => 'alice']), $rule),
            $plugin->key($this->request(post: ['name' => 'bob']), $rule),
            'Two accounts from one address must not.'
        );
    }

    /**
     * Consequence 2: count per endpoint, not per rule.
     */
    public function testCountingByRequestPathSeparatesEndpoints(): void
    {
        $plugin = $this->plugin();
        $rule = ['path' => '/api/*', 'key' => ['client_ip', 'path']];

        $this->assertNotSame(
            $plugin->key($this->request('/api/users'), $rule),
            $plugin->key($this->request('/api/orders'), $rule),
            '`/api/*` at 100/min should be 100 per endpoint when asked for, not 100 across all of them.'
        );
    }

    /**
     * And `rule_pattern` still collapses them, which is the old behaviour and
     * sometimes the wanted one.
     */
    public function testCountingByRulePatternCollapsesEndpoints(): void
    {
        $plugin = $this->plugin();
        $rule = ['path' => '/api/*', 'key' => ['client_ip', 'rule_pattern']];

        $this->assertSame(
            $plugin->key($this->request('/api/users'), $rule),
            $plugin->key($this->request('/api/orders'), $rule)
        );
    }

    /**
     * **A credential never reaches the backend.**
     *
     * A composed key can name `post.password` or `header.authorization`, and a rate limit
     * is not a reason to write either into Redis, a database, or a file on disk.
     *
     * @param array<int, string> $key
     *   The declared key.
     * @param array<string, string> $post
     *   POST fields.
     * @param string $secret
     *   The value that must not appear.
     */
    #[DataProvider('sensitiveKeys')]
    public function testASecretNeverAppearsInTheStoredKey(array $key, array $post, string $secret): void
    {
        $stored = $this->plugin()->key(
            $this->request(post: $post, server: ['HTTP_AUTHORIZATION' => 'Bearer sk-live-1234']),
            ['path' => '/login', 'key' => $key]
        );

        $this->assertStringNotContainsString($secret, $stored);
        $this->assertStringStartsWith('rate:', $stored);
    }

    /**
     * @return array<string, array{array<int, string>, array<string, string>, string}>
     */
    public static function sensitiveKeys(): array
    {
        return [
            'a username' => [['post.name'], ['name' => 'alice@example.com'], 'alice@example.com'],
            'a password' => [['post.password'], ['password' => 'hunter2'], 'hunter2'],
            'a bearer token' => [['header.authorization'], [], 'sk-live-1234'],
        ];
    }

    /**
     * A component that resolves to nothing is still counted as a position.
     *
     * Dropping it would put a request missing the field in the same bucket as one whose
     * field is genuinely empty, and shift every later component along.
     */
    public function testAnAbsentFieldIsAPositionNotAGap(): void
    {
        $plugin = $this->plugin();

        $absent = $plugin->key($this->request(), ['path' => '/x', 'key' => ['header.x-api-key', 'client_ip']]);
        $shifted = $plugin->key($this->request(), ['path' => '/x', 'key' => ['client_ip', 'header.x-api-key']]);

        $this->assertNotSame($absent, $shifted, 'Position must matter, or components collapse into each other.');
    }

    /**
     * Two different keys cannot collide by concatenation.
     */
    public function testComponentsCannotCollideByConcatenation(): void
    {
        $plugin = $this->plugin();

        $this->assertNotSame(
            $plugin->key($this->request(post: ['a' => 'x', 'b' => 'yz']), ['path' => '/p', 'key' => ['post.a', 'post.b']]),
            $plugin->key($this->request(post: ['a' => 'xy', 'b' => 'z']), ['path' => '/p', 'key' => ['post.a', 'post.b']])
        );
    }

    /**
     * `metadata.default_key` applies to rules that declare none.
     */
    public function testTheDefaultKeyCanBeSetForEveryRule(): void
    {
        $plugin = $this->plugin(['default_key' => ['client_ip', 'path']]);

        $this->assertNotSame(
            $plugin->key($this->request('/api/users'), ['path' => '/api/*']),
            $plugin->key($this->request('/api/orders'), ['path' => '/api/*'])
        );
    }

    /**
     * And a rule's own key beats it.
     */
    public function testARuleKeyBeatsTheDefault(): void
    {
        $plugin = $this->plugin(['default_key' => ['client_ip', 'path']]);
        $rule = ['path' => '/api/*', 'key' => ['client_ip', 'rule_pattern']];

        $this->assertSame(
            $plugin->key($this->request('/api/users'), $rule),
            $plugin->key($this->request('/api/orders'), $rule)
        );
    }

    /**
     * A malformed key falls back rather than producing a bucket nobody meant.
     *
     * @param mixed $declared
     *   What `key:` held.
     */
    #[DataProvider('malformedKeys')]
    public function testAMalformedKeyFallsBackToTheDefault(mixed $declared): void
    {
        $this->assertSame(
            'rate:203.0.113.1:/login',
            $this->plugin()->key($this->request(), ['path' => '/login', 'key' => $declared])
        );
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function malformedKeys(): array
    {
        return [
            'a string' => ['post.name'],
            'empty' => [[]],
            'only blanks' => [['', '   ']],
            'only non-strings' => [[7, null, true]],
            'null' => [null],
        ];
    }

    /**
     * An unknown component resolves to empty rather than erroring, so a typo
     * narrows the bucket instead of taking the site down.
     */
    public function testAnUnknownComponentIsEmptyNotFatal(): void
    {
        $key = $this->plugin()->key($this->request(), ['path' => '/x', 'key' => ['nonsense', 'client_ip']]);

        $this->assertStringStartsWith('rate:', $key);
    }

    /**
     * `rule_pattern` in a *composed* key resolves through the same path as
     * every other component.
     *
     * `['client_ip', 'rule_pattern']` is the default and short-circuits to the legacy key,
     * so it never exercises that branch — which is how it went untested until coverage said
     * so.
     */
    public function testRulePatternResolvesInAComposedKey(): void
    {
        $plugin = $this->plugin();

        $this->assertNotSame(
            $plugin->key($this->request(), ['path' => '/a/*', 'key' => ['rule_pattern']]),
            $plugin->key($this->request(), ['path' => '/b/*', 'key' => ['rule_pattern']])
        );
    }

    /**
     * A rule with no readable pattern resolves it to empty rather than failing.
     *
     * `matchRule()` will not return such a rule, but `buildRateKey()` is `protected` and
     * documented as the subclassing seam, so it is reachable from host code.
     */
    public function testAnUnreadableRulePatternIsEmpty(): void
    {
        $key = $this->plugin()->key($this->request(), ['key' => ['rule_pattern', 'client_ip']]);

        $this->assertStringStartsWith('rate:', $key);
    }

    /**
     * A component that splits to nothing resolves to empty.
     */
    public function testAComponentThatSplitsToNothingIsEmpty(): void
    {
        $key = $this->plugin()->key($this->request(), ['path' => '/x', 'key' => ['.', 'client_ip']]);

        $this->assertStringStartsWith('rate:', $key);
    }

    /**
     * Case and whitespace in a component name are forgiven.
     */
    public function testComponentNamesAreNormalised(): void
    {
        $plugin = $this->plugin();

        $this->assertSame(
            $plugin->key($this->request(), ['path' => '/x', 'key' => ['client_ip', 'path']]),
            $plugin->key($this->request(), ['path' => '/x', 'key' => ['  CLIENT_IP ', 'Path']])
        );
    }

    /**
     * POST, cookie and query names keep their case, because the request does
     * (#412).
     *
     * They were lower-cased with everything else, so `post.userName` read a
     * field that is never there: every request resolved to the same empty value
     * and shared one counter, and the limit refused everybody at once.
     *
     * @param string $component
     *   The declared component.
     * @param \Closure(string): Request $request
     *   Builds a request carrying the given value under that name.
     */
    #[DataProvider('caseSensitiveComponents')]
    public function testCaseSensitiveNamesResolve(string $component, \Closure $request): void
    {
        $plugin = $this->plugin();
        $rule = ['path' => '/login', 'key' => [$component]];

        $this->assertNotSame(
            $plugin->key($request('alice'), $rule),
            $plugin->key($request('bob'), $rule),
            sprintf('Two values of %s must not share a counter.', $component)
        );

        $this->assertNotSame(
            $plugin->key($request('alice'), $rule),
            $plugin->key($this->request(), $rule),
            sprintf('A request carrying %s must not share a counter with one that does not.', $component)
        );
    }

    /**
     * @return array<string, array{string, \Closure(string): Request}>
     */
    public static function caseSensitiveComponents(): array
    {
        return [
            'post' => [
                'post.userName',
                static fn(string $v): Request => Request::create(
                    '/login',
                    'POST',
                    ['userName' => $v],
                    [],
                    [],
                    ['REMOTE_ADDR' => '203.0.113.1']
                ),
            ],
            'cookie' => [
                'cookie.sessionId',
                static fn(string $v): Request => Request::create(
                    '/login',
                    'GET',
                    [],
                    ['sessionId' => $v],
                    [],
                    ['REMOTE_ADDR' => '203.0.113.1']
                ),
            ],
            'query' => [
                'query.userId',
                static fn(string $v): Request => Request::create(
                    '/login?userId=' . $v,
                    'GET',
                    [],
                    [],
                    [],
                    ['REMOTE_ADDR' => '203.0.113.1']
                ),
            ],
            'the prefix is still forgiven' => [
                'POST.userName',
                static fn(string $v): Request => Request::create(
                    '/login',
                    'POST',
                    ['userName' => $v],
                    [],
                    [],
                    ['REMOTE_ADDR' => '203.0.113.1']
                ),
            ],
        ];
    }

    /**
     * Header names are still case-insensitive, and a key that worked before
     * this change hashes to the same counter after it.
     *
     * The component name is part of the hashed material, so preserving the
     * case of `header.User-Agent` would have reset that counter on upgrade for
     * no gain.
     */
    public function testHeaderNamesStayCaseInsensitive(): void
    {
        $plugin = $this->plugin();
        $request = $this->request(server: ['HTTP_USER_AGENT' => 'curl/8.0']);

        $this->assertSame(
            $plugin->key($request, ['path' => '/login', 'key' => ['header.user-agent']]),
            $plugin->key($request, ['path' => '/login', 'key' => ['Header.User-Agent']])
        );

        $this->assertSame(
            'rate:' . hash('xxh128', 'header.user-agent=curl/8.0'),
            $plugin->key($request, ['path' => '/login', 'key' => ['Header.User-Agent']]),
            'The stored key for a header must be the one earlier releases wrote.'
        );
    }

    /**
     * A lower-case key that worked before hashes exactly as it did.
     */
    public function testAnUnaffectedKeyHashesAsBefore(): void
    {
        $this->assertSame(
            'rate:' . hash('xxh128', "client_ip=203.0.113.1\0post.name=alice"),
            $this->plugin()->key(
                $this->request(post: ['name' => 'alice']),
                ['path' => '/login', 'key' => [' Client_IP ', 'post.name']]
            )
        );
    }
}
