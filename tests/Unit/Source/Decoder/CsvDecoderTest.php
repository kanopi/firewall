<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source\Decoder;

use Kanopi\Firewall\Source\Decoder\CsvDecoder;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Tests delimiter-separated decoding for both csv and tsv.
 */
class CsvDecoderTest extends AbstractTestCase
{
    /**
     * Build a definition with delimiter options.
     */
    private function definition(string $format = 'csv', bool $headerRow = true, ?string $delimiter = null): SourceDefinition
    {
        return SourceDefinition::fromArray([
            'name' => 'rows',
            'upstream' => '/tmp/rows.csv',
            'format' => $format,
            'header_row' => $headerRow,
            'delimiter' => $delimiter,
        ]);
    }

    /**
     * With headers, each row decodes to a map keyed by column name.
     */
    public function testHeadersProduceKeyedRows(): void
    {
        $body = "asn,org,country\n13335,CLOUDFLARENET,US\n16509,AMAZON-02,US";

        $decoded = (new CsvDecoder())->decode($body, $this->definition());

        $this->assertSame(
            [
                ['asn' => '13335', 'org' => 'CLOUDFLARENET', 'country' => 'US'],
                ['asn' => '16509', 'org' => 'AMAZON-02', 'country' => 'US'],
            ],
            $decoded
        );
    }

    /**
     * Without a header row, rows stay numerically indexed so fields are positional.
     */
    public function testHeaderRowDisabledKeepsPositionalRows(): void
    {
        $decoded = (new CsvDecoder())->decode("13335,CLOUDFLARENET", $this->definition('csv', false));

        $this->assertSame([['13335', 'CLOUDFLARENET']], $decoded);
    }

    /**
     * TSV uses a tab delimiter without being told to.
     */
    public function testTsvUsesTabs(): void
    {
        $decoded = (new CsvDecoder())->decode("asn\torg\n13335\tCLOUDFLARENET", $this->definition('tsv'));

        $this->assertSame([['asn' => '13335', 'org' => 'CLOUDFLARENET']], $decoded);
    }

    /**
     * An explicit delimiter overrides the format default.
     */
    public function testExplicitDelimiter(): void
    {
        $decoded = (new CsvDecoder())->decode("asn;org\n13335;CLOUDFLARENET", $this->definition('csv', true, ';'));

        $this->assertSame([['asn' => '13335', 'org' => 'CLOUDFLARENET']], $decoded);
    }

    /**
     * Quoted fields may contain the delimiter.
     */
    public function testQuotedFieldContainingDelimiter(): void
    {
        $decoded = (new CsvDecoder())->decode("asn,org\n13335,\"CLOUDFLARE, INC\"", $this->definition());

        $this->assertSame([['asn' => '13335', 'org' => 'CLOUDFLARE, INC']], $decoded);
    }

    /**
     * A row shorter than the header row leaves the missing columns null.
     */
    public function testShortRowLeavesMissingColumnsNull(): void
    {
        $decoded = (new CsvDecoder())->decode("asn,org,country\n13335,CLOUDFLARENET", $this->definition());

        $this->assertSame([['asn' => '13335', 'org' => 'CLOUDFLARENET', 'country' => null]], $decoded);
    }

    /**
     * Comment rows and blank rows are skipped.
     */
    public function testCommentAndBlankRowsSkipped(): void
    {
        $body = "# generated\nasn,org\n\n13335,CLOUDFLARENET\n";

        $decoded = (new CsvDecoder())->decode($body, $this->definition());

        $this->assertSame([['asn' => '13335', 'org' => 'CLOUDFLARENET']], $decoded);
    }

    /**
     * A body with only a header row produces no records.
     */
    public function testHeaderOnlyBody(): void
    {
        $this->assertSame([], (new CsvDecoder())->decode("asn,org", $this->definition()));
    }

    /**
     * An empty body decodes to nothing.
     */
    public function testEmptyBody(): void
    {
        $this->assertSame([], (new CsvDecoder())->decode('', $this->definition()));
    }
}
