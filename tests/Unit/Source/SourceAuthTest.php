<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\SourceAuth;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Tests credential handling and, more importantly, credential scrubbing.
 */
class SourceAuthTest extends AbstractTestCase
{
    /**
     * A bearer token becomes an Authorization header.
     */
    public function testBearer(): void
    {
        $auth = SourceAuth::fromArray(['type' => 'bearer', 'token' => 's3cr3t'], 'feed');

        $this->assertSame(['Authorization' => 'Bearer s3cr3t'], $auth->headers());
    }

    /**
     * Basic credentials are base64 encoded as the scheme requires.
     */
    public function testBasic(): void
    {
        $auth = SourceAuth::fromArray(
            ['type' => 'basic', 'username' => 'reader', 'password' => 'hunter2'],
            'feed'
        );

        $this->assertSame(
            ['Authorization' => 'Basic ' . base64_encode('reader:hunter2')],
            $auth->headers()
        );
    }

    /**
     * An arbitrary header carries the credential when a vendor wants its own.
     */
    public function testHeader(): void
    {
        $auth = SourceAuth::fromArray(
            ['type' => 'header', 'name' => 'X-API-Key', 'value' => 'abc123'],
            'feed'
        );

        $this->assertSame(['X-API-Key' => 'abc123'], $auth->headers());
    }

    /**
     * Query auth adds no headers and appends to the URL instead.
     */
    public function testQueryAppendsToUrl(): void
    {
        $auth = SourceAuth::fromArray(['type' => 'query', 'name' => 'api_key', 'value' => 'abc 123'], 'feed');

        $this->assertSame([], $auth->headers());
        $this->assertSame(
            'https://example.org/list?api_key=abc%20123',
            $auth->applyToUrl('https://example.org/list')
        );
    }

    /**
     * An existing query string is extended rather than replaced.
     */
    public function testQueryJoinsAnExistingQueryString(): void
    {
        $auth = SourceAuth::fromArray(['type' => 'query', 'name' => 'key', 'value' => 'v'], 'feed');

        $this->assertSame(
            'https://example.org/list?page=2&key=v',
            $auth->applyToUrl('https://example.org/list?page=2')
        );
    }

    /**
     * An unknown type names the ones that exist.
     */
    public function testUnknownType(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('auth.type must be one of');

        SourceAuth::fromArray(['type' => 'oauth'], 'feed');
    }

    /**
     * Each type states which fields it needs.
     */
    #[DataProvider('missingFieldProvider')]
    public function testMissingFields(array $declaration, string $expected): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage($expected);

        SourceAuth::fromArray($declaration, 'feed');
    }

    /**
     * Incomplete credential declarations.
     */
    public static function missingFieldProvider(): array
    {
        return [
            'bearer without token' => [['type' => 'bearer'], 'auth.token is required'],
            'basic without username' => [['type' => 'basic', 'password' => 'x'], 'auth.username is required'],
            'basic without password' => [['type' => 'basic', 'username' => 'x'], 'auth.password is required'],
            'header without name' => [['type' => 'header', 'value' => 'x'], 'auth.name is required'],
            'header without value' => [['type' => 'header', 'name' => 'x'], 'auth.value is required'],
            'query without value' => [['type' => 'query', 'name' => 'x'], 'auth.value is required'],
            'empty token' => [['type' => 'bearer', 'token' => ''], 'auth.token is required'],
        ];
    }

    /**
     * A description names the mechanism and never the secret.
     */
    public function testDescribeNeverLeaksTheSecret(): void
    {
        $bearer = SourceAuth::fromArray(['type' => 'bearer', 'token' => 's3cr3t'], 'feed');
        $header = SourceAuth::fromArray(['type' => 'header', 'name' => 'X-Key', 'value' => 's3cr3t'], 'feed');

        $this->assertSame('bearer', $bearer->describe());
        $this->assertStringNotContainsString('s3cr3t', $bearer->describe());
        $this->assertSame('header X-Key', $header->describe());
        $this->assertStringNotContainsString('s3cr3t', $header->describe());
    }

    /**
     * URLs are scrubbed before they reach a log line, an exception, or stdout.
     */
    #[DataProvider('redactionProvider')]
    public function testRedactUrl(string $url, string $expected): void
    {
        $this->assertSame($expected, SourceAuth::redactUrl($url));
    }

    /**
     * URLs and the form each is safe to show in.
     */
    public static function redactionProvider(): array
    {
        return [
            'nothing to hide' => [
                'https://example.org/v1/list.txt',
                'https://example.org/v1/list.txt',
            ],
            'userinfo' => [
                'https://reader:hunter2@example.org/list.txt',
                'https://***@example.org/list.txt',
            ],
            'username only' => [
                'https://reader@example.org/list.txt',
                'https://***@example.org/list.txt',
            ],
            'token parameter' => [
                'https://example.org/list?token=s3cr3t',
                'https://example.org/list?token=***',
            ],
            'api_key parameter' => [
                'https://example.org/list?api_key=s3cr3t&page=2',
                'https://example.org/list?api_key=***&page=2',
            ],
            'several credential parameters' => [
                'https://example.org/list?key=a&secret=b&page=2',
                'https://example.org/list?key=***&secret=***&page=2',
            ],
            'case-insensitive parameter name' => [
                'https://example.org/list?ACCESS_TOKEN=s3cr3t',
                'https://example.org/list?ACCESS_TOKEN=***',
            ],
            'innocent parameters survive' => [
                'https://example.org/list?region=us-east-1&page=2',
                'https://example.org/list?region=us-east-1&page=2',
            ],
            'port and path preserved' => [
                'https://example.org:8443/v1/list.txt?token=x',
                'https://example.org:8443/v1/list.txt?token=***',
            ],
            'local paths pass through untouched' => [
                '/srv/app/lists/tor.txt',
                '/srv/app/lists/tor.txt',
            ],
            'relative paths pass through untouched' => [
                'lists/tor.txt',
                'lists/tor.txt',
            ],
        ];
    }

    /**
     * Redaction covers a URL carrying a token even when no auth is declared —
     * somebody pasting a tokenised feed URL straight in is the common case.
     */
    public function testRedactionIsIndependentOfDeclaredAuth(): void
    {
        $this->assertStringNotContainsString(
            's3cr3t',
            SourceAuth::redactUrl('https://example.org/list?api_key=s3cr3t')
        );
    }
}
