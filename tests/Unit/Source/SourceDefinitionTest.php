<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Tests parsing and validating a declared source.
 */
class SourceDefinitionTest extends AbstractTestCase
{
    /**
     * A full declaration round-trips into typed properties.
     */
    public function testFullDeclaration(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'aws-ec2-us',
            'upstream' => 'https://ip-ranges.amazonaws.com/ip-ranges.json',
            'format' => 'json',
            'select' => '{prefixes,ipv6_prefixes}.*',
            'where' => ['service:EC2'],
            'template' => '{value[ip_prefix]}',
            'validate' => 'cidr',
            'max_delta' => 0.25,
            'ttl' => 21600,
            'on_error' => 'abort',
            'required' => true,
        ]);

        $this->assertSame('aws-ec2-us', $definition->name);
        $this->assertSame('json', $definition->format);
        $this->assertSame('{prefixes,ipv6_prefixes}.*', $definition->select);
        $this->assertSame(['service:EC2'], $definition->where);
        $this->assertSame('cidr', $definition->validate);
        $this->assertSame(0.25, $definition->maxDelta);
        $this->assertSame(21600, $definition->ttl);
        $this->assertTrue($definition->required);
        $this->assertTrue($definition->isRemote());
        $this->assertTrue($definition->mustAbortOnError());
    }

    /**
     * A missing upstream is a configuration error.
     */
    public function testUpstreamIsRequired(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('missing an "upstream"');

        SourceDefinition::fromArray(['name' => 'nowhere']);
    }

    /**
     * Format is inferred from the upstream when not declared.
     */
    #[DataProvider('formatInferenceProvider')]
    public function testFormatInference(string $upstream, string $format, string $compression): void
    {
        $definition = SourceDefinition::fromArray(['upstream' => $upstream]);

        $this->assertSame($format, $definition->format);
        $this->assertSame($compression, $definition->compression);
    }

    /**
     * Upstreams and what each is taken to be.
     */
    public static function formatInferenceProvider(): array
    {
        return [
            'json' => ['https://example.org/ranges.json', 'json', 'none'],
            'ndjson' => ['/lists/feed.ndjson', 'ndjson', 'none'],
            'jsonl' => ['/lists/feed.jsonl', 'ndjson', 'none'],
            'yaml' => ['/lists/rules.yaml', 'yaml', 'none'],
            'yml' => ['/lists/rules.yml', 'yaml', 'none'],
            'csv' => ['/lists/asns.csv', 'csv', 'none'],
            'tsv' => ['/lists/asns.tsv', 'tsv', 'none'],
            'txt' => ['/lists/ips.txt', 'txt', 'none'],
            'no extension falls back to txt' => ['/lists/ips', 'txt', 'none'],
            'gzip is a separate axis' => ['/lists/ranges.json.gz', 'json', 'gzip'],
            'gzip over text' => ['/lists/ips.txt.gz', 'txt', 'gzip'],
            'query string ignored' => ['https://example.org/r.json?v=2', 'json', 'none'],
        ];
    }

    /**
     * An explicit format beats inference.
     */
    public function testExplicitFormatWins(): void
    {
        $definition = SourceDefinition::fromArray(['upstream' => '/lists/ips.txt', 'format' => 'csv']);

        $this->assertSame('csv', $definition->format);
    }

    /**
     * Unknown enumerated values are rejected with the allowed set named.
     */
    #[DataProvider('rejectedEnumProvider')]
    public function testRejectsUnknownEnumValues(string $key, string $value): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('must be one of');

        SourceDefinition::fromArray(['upstream' => '/x.txt', $key => $value]);
    }

    /**
     * Keys with a fixed set of legal values.
     */
    public static function rejectedEnumProvider(): array
    {
        return [
            'format' => ['format', 'toml'],
            'compression' => ['compression', 'brotli'],
            'on_error' => ['on_error', 'explode'],
            'validate' => ['validate', 'hostname'],
        ];
    }

    /**
     * A template must be a string or a map.
     */
    public function testTemplateMustBeStringOrMap(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('"template" must be a string or a map');

        SourceDefinition::fromArray(['upstream' => '/x.txt', 'template' => 42]);
    }

    /**
     * `where` must be a list of rules.
     */
    public function testWhereMustBeAList(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('"where" must be a list');

        SourceDefinition::fromArray(['upstream' => '/x.txt', 'where' => 'service:EC2']);
    }

    /**
     * Numeric options are range-checked.
     */
    #[DataProvider('badNumericProvider')]
    public function testRejectsBadNumericOptions(string $key, mixed $value, string $message): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage($message);

        SourceDefinition::fromArray(['upstream' => '/x.txt', $key => $value]);
    }

    /**
     * Numeric options and the values they refuse.
     */
    public static function badNumericProvider(): array
    {
        return [
            'negative delta' => ['max_delta', -1, 'non-negative number'],
            'non-numeric delta' => ['max_delta', 'lots', 'non-negative number'],
            'negative ttl' => ['ttl', -5, 'non-negative integer'],
            'non-numeric ttl' => ['ttl', 'soon', 'non-negative integer'],
        ];
    }

    /**
     * An undeclared name is derived from the upstream filename.
     */
    public function testNameDerivedFromUpstream(): void
    {
        $this->assertSame(
            'tor-exit-nodes',
            SourceDefinition::fromArray(['upstream' => 'https://example.org/v1/tor-exit-nodes.txt'])->name
        );
    }

    /**
     * A local path is not remote, and vice versa.
     */
    public function testRemoteDetection(): void
    {
        $this->assertTrue(SourceDefinition::fromArray(['upstream' => 'https://example.org/a.txt'])->isRemote());
        $this->assertFalse(SourceDefinition::fromArray(['upstream' => '/lists/a.txt'])->isRemote());
    }

    /**
     * `on_error: abort` aborts even without `required`.
     */
    public function testAbortPolicyImpliesAborting(): void
    {
        $definition = SourceDefinition::fromArray(['upstream' => '/x.txt', 'on_error' => 'abort']);

        $this->assertTrue($definition->mustAbortOnError());
    }

    /**
     * The default policy degrades rather than aborting.
     */
    public function testDefaultPolicyDegrades(): void
    {
        $definition = SourceDefinition::fromArray(['upstream' => '/x.txt']);

        $this->assertSame('last_known_good', $definition->onError);
        $this->assertFalse($definition->mustAbortOnError());
    }

    /**
     * The fingerprint changes when anything affecting the decoded result does,
     * so editing a select or template invalidates the cache on its own.
     */
    public function testFingerprintTracksPipelineOptions(): void
    {
        $base = SourceDefinition::fromArray(['upstream' => '/x.json', 'select' => 'a.*']);

        $this->assertNotSame(
            $base->fingerprint(),
            SourceDefinition::fromArray(['upstream' => '/x.json', 'select' => 'b.*'])->fingerprint()
        );

        $this->assertNotSame(
            $base->fingerprint(),
            SourceDefinition::fromArray([
                'upstream' => '/x.json',
                'select' => 'a.*',
                'template' => '{value[a]}',
            ])->fingerprint()
        );
    }

    /**
     * The fingerprint ignores options that cannot change the entries, so a
     * renamed source keeps its cache.
     */
    public function testFingerprintIgnoresNonPipelineOptions(): void
    {
        $this->assertSame(
            SourceDefinition::fromArray(['upstream' => '/x.txt', 'name' => 'one', 'ttl' => 60])->fingerprint(),
            SourceDefinition::fromArray(['upstream' => '/x.txt', 'name' => 'two', 'ttl' => 900])->fingerprint()
        );
    }
}
