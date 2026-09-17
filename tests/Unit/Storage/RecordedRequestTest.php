<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Kanopi\Firewall\Storage\RecordedRequest;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * What a block record keeps about the request that caused it (#375).
 */
class RecordedRequestTest extends AbstractTestCase
{
    /**
     * The bug, stated as a test.
     */
    public function testACredentialTheVisitorSentIsNotKept(): void
    {
        $record = RecordedRequest::fromConfig(null)->serialize($this->loadedRequest());

        $this->assertSame([], $record['cookies'], 'The session cookie was kept');
        $this->assertArrayNotHasKey('authorization', $record['headers']);
        $this->assertArrayNotHasKey('cookie', $record['headers']);
        $this->assertSame([], $record['request'], 'The submitted password was kept');
    }

    /**
     * And the forensic value survives, because a record nobody can read tells
     * nobody anything.
     */
    public function testWhatMakesTheRecordUsefulSurvives(): void
    {
        $record = RecordedRequest::fromConfig(null)->serialize($this->loadedRequest());

        $this->assertSame('POST', $record['method']);
        $this->assertSame('/wp-login.php', $record['path']);
        $this->assertSame('sqlmap/1.7', $record['headers']['user-agent']);
        $this->assertSame('https://example.org/', $record['headers']['referer']);
    }

    /**
     * For the commonest case — a scanner — the query string *is* the attack, so
     * redacting it by default would gut the record for the thing it is most
     * often read about.
     */
    public function testTheQueryStringIsKeptByDefault(): void
    {
        $request = Request::create('/?id=1%20OR%201=1', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']);

        $this->assertSame(['id' => '1 OR 1=1'], RecordedRequest::fromConfig(null)->serialize($request)['query']);
    }

    /**
     * `getUri()` carries the query string, so narrowing `query` while copying
     * the original URI would be a setting that silently does nothing — a reset
     * token redacted out of one field and left in the one beside it.
     */
    public function testNarrowingTheQueryAlsoNarrowsTheUri(): void
    {
        $request = Request::create('/reset?token=SECRET&id=9', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']);
        $record = RecordedRequest::fromConfig(['query' => ['id']])->serialize($request);

        $this->assertSame(['id' => '9'], $record['query']);
        $this->assertStringNotContainsString('SECRET', $record['uri']);
        $this->assertStringContainsString('id=9', $record['uri']);
    }

    public function testDroppingEveryQueryParameterLeavesABareUri(): void
    {
        $request = Request::create('/reset?token=SECRET', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']);
        $record = RecordedRequest::fromConfig(['query' => []])->serialize($request);

        $this->assertSame([], $record['query']);
        $this->assertSame('http://localhost/reset', $record['uri']);
    }

    /**
     * Keeping everything is left exactly as it was, because rebuilding a URI
     * that nothing was removed from is a chance to change it by accident.
     */
    public function testAnUntouchedQueryLeavesTheUriAlone(): void
    {
        $request = Request::create('/a?b=1&c=2', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']);

        $this->assertSame(
            $request->getUri(),
            RecordedRequest::fromConfig(['query' => ['b', 'c']])->serialize($request)['uri']
        );
    }

    public function testAnAllowlistKeepsOnlyWhatItNames(): void
    {
        $record = RecordedRequest::fromConfig([
            'cookies' => ['locale'],
            'headers' => ['user-agent'],
            'body' => ['log'],
        ])->serialize($this->loadedRequest());

        $this->assertSame(['locale' => 'en_GB'], $record['cookies']);
        $this->assertSame(['user-agent' => 'sqlmap/1.7'], $record['headers']);
        $this->assertSame(['log' => 'admin'], $record['request']);
    }

    /**
     * For a deployment that has decided it wants the forensics and understood
     * what that means.
     */
    public function testTheWildcardOptsEverythingBackIn(): void
    {
        $record = RecordedRequest::fromConfig([
            'cookies' => ['*'],
            'headers' => ['*'],
            'body' => ['*'],
        ])->serialize($this->loadedRequest());

        $this->assertSame('a-live-session', $record['cookies']['PHPSESSID']);
        $this->assertSame('Bearer sk-live-1234', $record['headers']['authorization']);
        $this->assertSame('hunter2', $record['request']['pwd']);
    }

    public function testEverythingIsWhatTheFirewallUsedToKeep(): void
    {
        $record = RecordedRequest::everything()->serialize($this->loadedRequest());

        $this->assertTrue(RecordedRequest::everything()->keepsEverything());
        $this->assertFalse(RecordedRequest::fromConfig(null)->keepsEverything());
        $this->assertSame('a-live-session', $record['cookies']['PHPSESSID']);
    }

    /**
     * Headers are matched case-insensitively because HTTP says they are.
     * Everything else is the application's own naming, where `Token` and
     * `token` are two different fields.
     */
    public function testHeaderNamesAreCaseInsensitiveAndTheRestAreNot(): void
    {
        $request = Request::create('/', 'POST', ['Token' => 'a', 'token' => 'b'], [], [], [
            'REMOTE_ADDR' => '203.0.113.9',
            'HTTP_X_CUSTOM' => 'kept',
        ]);

        $record = RecordedRequest::fromConfig([
            'headers' => ['X-CUSTOM'],
            'body' => ['token'],
        ])->serialize($request);

        $this->assertSame(['x-custom' => 'kept'], $record['headers']);
        $this->assertSame(['token' => 'b'], $record['request']);
    }

    /**
     * Symfony hands back a list per header, which is faithful and awkward to
     * read in a record — but a genuinely repeated header must not quietly lose
     * everything after the first.
     */
    public function testASingleHeaderIsUnwrappedAndARepeatedOneIsNot(): void
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_ACCEPT' => 'text/html']);
        $request->headers->set('X-Multi', ['one', 'two']);

        $record = RecordedRequest::fromConfig(['headers' => ['accept', 'x-multi']])->serialize($request);

        $this->assertSame('text/html', $record['headers']['accept']);
        $this->assertSame(['one', 'two'], $record['headers']['x-multi']);
    }

    /**
     * Storage is constructed on the request path. A strict read here fails a
     * site to start because somebody typed a list where a map goes; a lenient
     * one keeps *less* than intended, which is the safe direction and is
     * visible in the next record anybody looks at.
     *
     * @param mixed $declared
     */
    #[DataProvider('malformedProvider')]
    public function testAMalformedPolicyFallsBackToTheDefaults(mixed $declared): void
    {
        $record = RecordedRequest::fromConfig($declared)->serialize($this->loadedRequest());

        $this->assertSame([], $record['cookies']);
        $this->assertArrayNotHasKey('authorization', $record['headers']);
    }

    /**
     * @return array<string, array{0: mixed}>
     */
    public static function malformedProvider(): array
    {
        return [
            'null' => [null],
            'a string' => ['everything'],
            'a list' => [['cookies', 'headers']],
            'buckets of the wrong type' => [['cookies' => 42, 'headers' => false]],
            'names of the wrong type' => [['cookies' => [42, null], 'headers' => [[]]]],
        ];
    }

    /**
     * One name is the shorthand somebody will write, and `"*"` is the shorthand
     * for the wildcard. Both are obvious enough to accept rather than refuse.
     */
    public function testABareStringIsReadAsOneName(): void
    {
        $record = RecordedRequest::fromConfig(['cookies' => 'locale', 'headers' => '*'])
            ->serialize($this->loadedRequest());

        $this->assertSame(['locale' => 'en_GB'], $record['cookies']);
        $this->assertArrayHasKey('authorization', $record['headers']);
    }

    /**
     * Nothing here authenticates anybody, which is the rule the list was
     * chosen by — and a regression that added one would be invisible.
     */
    public function testNoDefaultHeaderCanBeReplayedToBecomeSomebody(): void
    {
        $dangerous = ['cookie', 'authorization', 'proxy-authorization', 'x-api-key', 'x-auth-token', 'x-csrf-token', 'x-session-token'];

        $this->assertSame([], array_intersect($dangerous, RecordedRequest::DEFAULT_HEADERS));
    }

    /**
     * A visitor holding a session, an API token and a challenge pass, being
     * blocked for something else entirely.
     */
    private function loadedRequest(): Request
    {
        return Request::create(
            '/wp-login.php',
            'POST',
            ['log' => 'admin', 'pwd' => 'hunter2'],
            ['PHPSESSID' => 'a-live-session', 'fw_challenge_pass' => 'a.pass', 'locale' => 'en_GB'],
            [],
            [
                'REMOTE_ADDR' => '203.0.113.9',
                'HTTP_USER_AGENT' => 'sqlmap/1.7',
                'HTTP_REFERER' => 'https://example.org/',
                'HTTP_AUTHORIZATION' => 'Bearer sk-live-1234',
                'HTTP_X_API_KEY' => 'sk-live-5678',
            ]
        );
    }
}
