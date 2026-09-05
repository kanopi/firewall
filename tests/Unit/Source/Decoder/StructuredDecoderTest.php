<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source\Decoder;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\Decoder\JsonDecoder;
use Kanopi\Firewall\Source\Decoder\NdjsonDecoder;
use Kanopi\Firewall\Source\Decoder\YamlDecoder;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Tests the structured decoders: json, ndjson, and yaml.
 */
class StructuredDecoderTest extends AbstractTestCase
{
    /**
     * Build a definition for a named format.
     */
    private function definition(string $format): SourceDefinition
    {
        return SourceDefinition::fromArray(['name' => 'feed', 'upstream' => '/tmp/feed', 'format' => $format]);
    }

    /**
     * A JSON document decodes to its structure intact.
     */
    public function testJsonDecodesDocument(): void
    {
        $decoded = (new JsonDecoder())->decode('{"prefixes":[{"ip_prefix":"1.2.3.0/24"}]}', $this->definition('json'));

        $this->assertSame([['ip_prefix' => '1.2.3.0/24']], $decoded['prefixes']);
    }

    /**
     * A JSON list decodes as a list.
     */
    public function testJsonDecodesList(): void
    {
        $this->assertSame(['a', 'b'], (new JsonDecoder())->decode('["a","b"]', $this->definition('json')));
    }

    /**
     * Malformed JSON is an error, not a silent empty list.
     */
    public function testJsonRejectsMalformedBody(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('not valid JSON');

        (new JsonDecoder())->decode('{"broken":', $this->definition('json'));
    }

    /**
     * A JSON scalar is rejected: there are no records in it.
     */
    public function testJsonRejectsScalarDocument(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('expected an object or array');

        (new JsonDecoder())->decode('"just a string"', $this->definition('json'));
    }

    /**
     * An empty JSON body decodes to nothing rather than failing.
     */
    public function testJsonEmptyBody(): void
    {
        $this->assertSame([], (new JsonDecoder())->decode('   ', $this->definition('json')));
    }

    /**
     * NDJSON decodes one document per line.
     */
    public function testNdjsonDecodesPerLine(): void
    {
        $body = "{\"ip\":\"1.1.1.1\"}\n\n{\"ip\":\"2.2.2.2\"}\n";

        $decoded = (new NdjsonDecoder())->decode($body, $this->definition('ndjson'));

        $this->assertSame([['ip' => '1.1.1.1'], ['ip' => '2.2.2.2']], $decoded);
    }

    /**
     * A broken NDJSON line names the line number, since the rest parsed fine.
     */
    public function testNdjsonReportsFailingLineNumber(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('line 2');

        (new NdjsonDecoder())->decode("{\"ip\":\"1.1.1.1\"}\n{oops", $this->definition('ndjson'));
    }

    /**
     * YAML decodes a sequence to a list.
     */
    public function testYamlDecodesSequence(): void
    {
        $decoded = (new YamlDecoder())->decode("- 1.2.3.4\n- 5.6.7.8", $this->definition('yaml'));

        $this->assertSame(['1.2.3.4', '5.6.7.8'], $decoded);
    }

    /**
     * YAML decodes a mapping to a map.
     */
    public function testYamlDecodesMapping(): void
    {
        $decoded = (new YamlDecoder())->decode("prefixes:\n  - a\n  - b", $this->definition('yaml'));

        $this->assertSame(['a', 'b'], $decoded['prefixes']);
    }

    /**
     * The trap this guard exists for: a newline-delimited IP list is valid
     * YAML — it folds into one scalar — so declaring it `format: yaml` would
     * otherwise produce nothing at all, silently.
     */
    public function testYamlRejectsFoldedNewlineList(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('declare it as format: txt');

        (new YamlDecoder())->decode("216.144.248.16/28\n69.162.124.224/28", $this->definition('yaml'));
    }

    /**
     * Malformed YAML is an error.
     */
    public function testYamlRejectsMalformedBody(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('not valid YAML');

        (new YamlDecoder())->decode("foo:\n  - bar\n bad indent", $this->definition('yaml'));
    }
}
