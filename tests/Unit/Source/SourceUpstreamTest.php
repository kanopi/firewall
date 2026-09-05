<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Source\SourceUpstream;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Tests both declaration forms of `upstream`.
 */
class SourceUpstreamTest extends AbstractTestCase
{
    /**
     * The string form is the common case and stays the shorthand.
     */
    public function testStringForm(): void
    {
        $upstream = SourceUpstream::fromDeclaration('https://example.org/list.txt', 'feed');

        $this->assertSame('https://example.org/list.txt', $upstream->url);
        $this->assertSame('GET', $upstream->method);
        $this->assertSame([], $upstream->headers);
        $this->assertNull($upstream->auth);
        $this->assertTrue($upstream->isRemote());
    }

    /**
     * The map form carries everything about making the request.
     */
    public function testMapForm(): void
    {
        $upstream = SourceUpstream::fromDeclaration([
            'url' => 'https://feeds.example.com/v1/list.json',
            'method' => 'post',
            'headers' => ['X-Account' => '12345'],
            'auth' => ['type' => 'bearer', 'token' => 's3cr3t'],
            'body' => '{"query":"all"}',
            'timeout' => 10,
            'max_redirects' => 2,
        ], 'feed');

        $this->assertSame('POST', $upstream->method, 'Method is normalised to upper case.');
        $this->assertSame('{"query":"all"}', $upstream->body);
        $this->assertSame(10.0, $upstream->timeout);
        $this->assertSame(2, $upstream->maxRedirects);
        $this->assertSame([
            'X-Account' => '12345',
            'Authorization' => 'Bearer s3cr3t',
        ], $upstream->requestHeaders());
    }

    /**
     * Both forms are accepted through a full source declaration.
     */
    public function testBothFormsThroughSourceDefinition(): void
    {
        $string = SourceDefinition::fromArray(['upstream' => 'https://example.org/a.json']);
        $map = SourceDefinition::fromArray(['upstream' => ['url' => 'https://example.org/a.json']]);

        $this->assertSame('json', $string->format, 'Format inference reads the map form too.');
        $this->assertSame('json', $map->format);
        $this->assertSame($string->upstream->url, $map->upstream->url);
    }

    /**
     * A name is still derived from the URL inside the map form.
     */
    public function testNameDerivedFromMapForm(): void
    {
        $definition = SourceDefinition::fromArray([
            'upstream' => ['url' => 'https://example.org/v1/tor-exit-nodes.txt'],
        ]);

        $this->assertSame('tor-exit-nodes', $definition->name);
    }

    /**
     * A missing or empty url is a configuration error.
     */
    #[DataProvider('badUrlProvider')]
    public function testUrlIsRequired(mixed $declaration): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('needs a non-empty "url"');

        SourceUpstream::fromDeclaration($declaration, 'feed');
    }

    /**
     * Declarations with no usable URL.
     */
    public static function badUrlProvider(): array
    {
        return [
            'empty map' => [[]],
            'empty string url' => [['url' => '  ']],
            'non-string url' => [['url' => 42]],
        ];
    }

    /**
     * A scalar that is not a string is rejected outright.
     */
    public function testNonStringNonMapDeclaration(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('must be a URL string or a map');

        SourceUpstream::fromDeclaration(42, 'feed');
    }

    /**
     * Only methods that make sense for fetching a list are allowed.
     */
    public function testMethodIsValidated(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('upstream.method must be one of');

        SourceUpstream::fromDeclaration(['url' => 'https://example.org/a', 'method' => 'DELETE'], 'feed');
    }

    /**
     * Header values are stripped of newlines, which would otherwise let an
     * injected value start a header of its own.
     */
    public function testHeaderInjectionIsStripped(): void
    {
        $upstream = SourceUpstream::fromDeclaration([
            'url' => 'https://example.org/a',
            'headers' => ['X-Account' => "12345\r\nX-Admin: true"],
        ], 'feed');

        $this->assertSame('12345X-Admin: true', $upstream->headers['X-Account']);
        $this->assertStringNotContainsString("\r", $upstream->headers['X-Account']);
        $this->assertStringNotContainsString("\n", $upstream->headers['X-Account']);
    }

    /**
     * Header declarations that are not a map of scalars are rejected.
     */
    #[DataProvider('badHeaderProvider')]
    public function testBadHeaders(mixed $headers, string $expected): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage($expected);

        SourceUpstream::fromDeclaration(['url' => 'https://example.org/a', 'headers' => $headers], 'feed');
    }

    /**
     * Malformed header declarations.
     */
    public static function badHeaderProvider(): array
    {
        return [
            'not a map' => ['Authorization: x', 'upstream.headers must be a map'],
            'numeric key' => [['x'], 'must be non-empty header names'],
            'array value' => [['X-A' => ['b']], 'must be a scalar value'],
        ];
    }

    /**
     * Numeric request options are range-checked.
     */
    #[DataProvider('badNumericProvider')]
    public function testBadNumericOptions(string $key, mixed $value, string $expected): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage($expected);

        SourceUpstream::fromDeclaration(['url' => 'https://example.org/a', $key => $value], 'feed');
    }

    /**
     * Request options and the values they refuse.
     */
    public static function badNumericProvider(): array
    {
        return [
            'zero timeout' => ['timeout', 0, 'timeout must be a positive number'],
            'negative timeout' => ['timeout', -1, 'timeout must be a positive number'],
            'non-numeric timeout' => ['timeout', 'soon', 'timeout must be a positive number'],
            'negative redirects' => ['max_redirects', -1, 'max_redirects must be a non-negative integer'],
        ];
    }

    /**
     * Sending a credential over plain http is refused: it would travel in
     * clear text, and doing that by accident is easy.
     */
    public function testCredentialsOverPlainHttpAreRefused(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('refusing to send credentials over plain http');

        SourceUpstream::fromDeclaration([
            'url' => 'http://internal.example/list.txt',
            'auth' => ['type' => 'bearer', 'token' => 's3cr3t'],
        ], 'feed');
    }

    /**
     * An operator on a trusted network can say so explicitly.
     */
    public function testInsecureCredentialsCanBeOptedInto(): void
    {
        $upstream = SourceUpstream::fromDeclaration([
            'url' => 'http://internal.example/list.txt',
            'auth' => ['type' => 'bearer', 'token' => 's3cr3t'],
            'allow_insecure' => true,
        ], 'feed');

        $this->assertSame(['Authorization' => 'Bearer s3cr3t'], $upstream->requestHeaders());
    }

    /**
     * Plain http without credentials is unaffected.
     */
    public function testPlainHttpWithoutCredentialsIsFine(): void
    {
        $upstream = SourceUpstream::fromDeclaration('http://internal.example/list.txt', 'feed');

        $this->assertSame('http://internal.example/list.txt', $upstream->url);
    }

    /**
     * Query auth reaches the request URL but never the displayed one.
     */
    public function testQueryAuthIsAppliedButNotDisplayed(): void
    {
        $upstream = SourceUpstream::fromDeclaration([
            'url' => 'https://example.org/list',
            'auth' => ['type' => 'query', 'name' => 'api_key', 'value' => 's3cr3t'],
        ], 'feed');

        $this->assertSame('https://example.org/list?api_key=s3cr3t', $upstream->requestUrl());
        $this->assertStringNotContainsString('s3cr3t', $upstream->display());
    }

    /**
     * Rotating a credential must not invalidate the cache: the token changed,
     * the list it fetches did not.
     */
    public function testCredentialsAreExcludedFromTheFingerprint(): void
    {
        $first = SourceDefinition::fromArray([
            'upstream' => [
                'url' => 'https://example.org/a.json',
                'auth' => ['type' => 'bearer', 'token' => 'old'],
            ],
        ]);
        $second = SourceDefinition::fromArray([
            'upstream' => [
                'url' => 'https://example.org/a.json',
                'auth' => ['type' => 'bearer', 'token' => 'rotated'],
            ],
        ]);

        $this->assertSame($first->fingerprint(), $second->fingerprint());
    }

    /**
     * Anything that can change what comes back does invalidate it.
     */
    #[DataProvider('fingerprintChangingProvider')]
    public function testRequestOptionsAffectTheFingerprint(array $overrides): void
    {
        $base = SourceDefinition::fromArray(['upstream' => ['url' => 'https://example.org/a.json']]);
        $changed = SourceDefinition::fromArray([
            'upstream' => ['url' => 'https://example.org/a.json'] + $overrides,
        ]);

        $this->assertNotSame($base->fingerprint(), $changed->fingerprint());
    }

    /**
     * Request options that change the response.
     */
    public static function fingerprintChangingProvider(): array
    {
        return [
            'method' => [['method' => 'POST']],
            'headers' => [['headers' => ['Accept-Language' => 'fr']]],
            'body' => [['body' => '{"q":1}']],
        ];
    }

    /**
     * A local path is not remote whichever form declares it.
     */
    public function testLocalPathIsNotRemote(): void
    {
        $this->assertFalse(SourceUpstream::fromDeclaration('/lists/a.txt', 'feed')->isRemote());
        $this->assertFalse(SourceUpstream::fromDeclaration(['url' => '/lists/a.txt'], 'feed')->isRemote());
    }
}
