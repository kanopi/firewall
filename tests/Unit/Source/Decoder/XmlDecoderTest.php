<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source\Decoder;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\Decoder\DecoderRegistry;
use Kanopi\Firewall\Source\Decoder\XmlDecoder;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * XML, as a plain array (#204).
 *
 * Added for the reputation rule, and registered here because it is a decoder --
 * so a rule source can read an XML list with it too. Most of this file is the
 * refusals, because XML is the one format where parsing bytes somebody else
 * produced is itself the risk.
 */
final class XmlDecoderTest extends AbstractTestCase
{
    private function definition(): SourceDefinition
    {
        return SourceDefinition::fromArray(['name' => 'feed', 'upstream' => '/tmp/feed.xml']);
    }

    private function decode(string $body): array
    {
        return (new XmlDecoder())->decode($body, $this->definition());
    }

    /**
     * A document becomes the structure everything downstream expects.
     */
    public function testADocumentDecodesToItsStructure(): void
    {
        $decoded = $this->decode('<response><data><score>82</score></data></response>');

        $this->assertSame(['data' => ['score' => '82']], $decoded);
    }

    /**
     * Attributes keep SimpleXML's shape, which is what an API documents.
     */
    public function testAttributesLandUnderTheirOwnKey(): void
    {
        $decoded = $this->decode('<response><data score="82" listed="yes"/></response>');

        $this->assertSame(['score' => '82', 'listed' => 'yes'], $decoded['data']['@attributes']);
    }

    /**
     * Repeated elements decode as a list, so a source can iterate them.
     */
    public function testRepeatedElementsBecomeAList(): void
    {
        $decoded = $this->decode('<list><ip>1.2.3.4</ip><ip>5.6.7.8</ip></list>');

        $this->assertSame(['1.2.3.4', '5.6.7.8'], $decoded['ip']);
    }

    /**
     * CDATA is content, not markup.
     */
    public function testCdataIsRead(): void
    {
        $decoded = $this->decode('<response><note><![CDATA[open proxy]]></note></response>');

        $this->assertSame('open proxy', $decoded['note']);
    }

    /**
     * A DOCTYPE is refused before the parser sees it.
     *
     * The security test. An entity pointing at a local file is a file read out
     * of a response body, and one pointing at an internal URL is an SSRF; both
     * need a DOCTYPE, and nothing that publishes a list or a score sends one.
     *
     * Asserted on the outcome rather than the mechanism: whatever the parser
     * would have done, no file content is in the result, because there is no
     * result.
     */
    public function testADoctypeIsRefused(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessageMatches('/DOCTYPE/');

        $this->decode(
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r><ip>&x;</ip></r>'
        );
    }

    /**
     * Including the expansion attack, which needs no external entity at all.
     *
     * Billion laughs is nested internal entities: no file, no network, just a
     * document that decompresses into gigabytes of memory. Refusing the
     * declaration is what stops it, which is why the refusal is of DOCTYPE
     * rather than of external entities.
     */
    public function testAnEntityExpansionAttackIsRefused(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessageMatches('/DOCTYPE/');

        $this->decode(
            '<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY a "aaaaaaaaaa">'
            . '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            . '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><lol>&c;</lol>'
        );
    }

    /**
     * A nesting bomb is a parse failure, not a stack overflow.
     *
     * libxml refuses a document nested deeper than 256 elements on its own, so
     * a body built to exhaust memory during conversion never reaches the
     * conversion. Asserted because it is the reason there is no depth guard
     * in the decoder to go stale.
     */
    public function testADeeplyNestedDocumentIsRefused(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessageMatches('/not valid XML/');

        $this->decode('<r>' . str_repeat('<a>', 600) . 'x' . str_repeat('</a>', 600) . '</r>');
    }

    /**
     * A body that is not XML is reported as such.
     */
    public function testAMalformedBodyIsReported(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessageMatches('/not valid XML/');

        $this->decode('<response><data></response>');
    }

    /**
     * An empty body has nothing to read.
     */
    public function testAnEmptyBodyIsReported(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessageMatches('/body is empty/');

        $this->decode("  \n ");
    }

    /**
     * The registry knows it, so `format: xml` resolves.
     */
    public function testTheRegistryResolvesIt(): void
    {
        $this->assertInstanceOf(XmlDecoder::class, (new DecoderRegistry())->get('xml'));
    }

    /**
     * And a `.xml` upstream infers it without being told.
     */
    public function testAnXmlExtensionInfersTheFormat(): void
    {
        $this->assertSame('xml', $this->definition()->format);
    }

    /**
     * libxml's error state is left as it was found.
     *
     * The decoder collects parser errors instead of emitting them, which is
     * process-global: leaving it on would silently swallow warnings from the
     * host application's own XML handling for the rest of the request.
     */
    public function testTheParserErrorStateIsRestored(): void
    {
        $before = libxml_use_internal_errors(false);

        try {
            $this->decode('<r><a>1</a></r>');

            $this->assertFalse(libxml_use_internal_errors(), 'The decoder must put libxml back as it found it.');
        } finally {
            libxml_use_internal_errors($before);
        }
    }
}
