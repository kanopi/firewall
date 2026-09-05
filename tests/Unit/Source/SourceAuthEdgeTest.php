<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Source\SourceAuth;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Covers the credential paths the main auth suite does not reach.
 */
class SourceAuthEdgeTest extends AbstractTestCase
{
    /**
     * Query auth describes itself by parameter name, never by value.
     */
    public function testQueryAuthDescribesItself(): void
    {
        $auth = SourceAuth::fromArray(['type' => 'query', 'name' => 'api_key', 'value' => 's3cr3t'], 'feed');

        $this->assertSame('query api_key', $auth->describe());
        $this->assertStringNotContainsString('s3cr3t', $auth->describe());
    }

    /**
     * An empty pair in a query string is skipped rather than mangling the rest.
     */
    public function testRedactionSkipsEmptyQueryPairs(): void
    {
        $this->assertSame(
            'https://example.org/list?a=1&token=***',
            SourceAuth::redactUrl('https://example.org/list?a=1&&token=s3cr3t')
        );
    }

    /**
     * A fragment survives redaction.
     */
    public function testRedactionPreservesAFragment(): void
    {
        $this->assertSame(
            'https://example.org/list?token=***#section',
            SourceAuth::redactUrl('https://example.org/list?token=s3cr3t#section')
        );
    }

    /**
     * A parameter with no value at all is left alone.
     */
    public function testRedactionHandlesValuelessParameters(): void
    {
        $this->assertSame(
            'https://example.org/list?debug',
            SourceAuth::redactUrl('https://example.org/list?debug')
        );
    }
}
