<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source\Decoder;

use Kanopi\Firewall\Source\Decoder\TxtDecoder;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Tests newline-delimited decoding, which is the shape most published lists use.
 */
class TxtDecoderTest extends AbstractTestCase
{
    /**
     * Build a definition with text-format options.
     */
    private function definition(string $comment = '#'): SourceDefinition
    {
        return SourceDefinition::fromArray([
            'name' => 'list',
            'upstream' => '/tmp/list.txt',
            'format' => 'txt',
            'comment' => $comment,
        ]);
    }

    /**
     * Plain lines decode one entry per line.
     */
    public function testPlainLines(): void
    {
        $decoded = (new TxtDecoder())->decode("1.2.3.4\n5.6.7.8", $this->definition());

        $this->assertSame(['1.2.3.4', '5.6.7.8'], $decoded);
    }

    /**
     * Banner comments, blank lines, and stray whitespace are stripped.
     */
    public function testComentsBlanksAndWhitespaceAreStripped(): void
    {
        $body = <<<TXT
        # UptimeRobot IPv4
        # updated 2026-09-04

          216.144.250.150

        69.162.124.224/28
        TXT;

        $decoded = (new TxtDecoder())->decode($body, $this->definition());

        $this->assertSame(['216.144.250.150', '69.162.124.224/28'], $decoded);
    }

    /**
     * A trailing label after the value is treated as a comment.
     */
    public function testTrailingLabelIsRemoved(): void
    {
        $decoded = (new TxtDecoder())->decode("1.2.3.4 # scanner\n5.6.7.8\t# probe", $this->definition());

        $this->assertSame(['1.2.3.4', '5.6.7.8'], $decoded);
    }

    /**
     * A marker that is part of a value survives, because only a marker
     * preceded by whitespace opens a comment.
     */
    public function testMarkerInsideValueIsKept(): void
    {
        $decoded = (new TxtDecoder())->decode('/path#fragment', $this->definition());

        $this->assertSame(['/path#fragment'], $decoded);
    }

    /**
     * The comment marker is configurable.
     */
    public function testCustomCommentMarker(): void
    {
        $decoded = (new TxtDecoder())->decode("; banner\n1.2.3.4 ; label", $this->definition(';'));

        $this->assertSame(['1.2.3.4'], $decoded);
    }

    /**
     * An empty marker disables comment handling entirely.
     */
    public function testCommentsCanBeDisabled(): void
    {
        $decoded = (new TxtDecoder())->decode("# not a comment", $this->definition(''));

        $this->assertSame(['# not a comment'], $decoded);
    }

    /**
     * Windows and classic Mac line endings decode the same as Unix.
     */
    public function testMixedLineEndings(): void
    {
        $decoded = (new TxtDecoder())->decode("1.1.1.1\r\n2.2.2.2\r3.3.3.3\n", $this->definition());

        $this->assertSame(['1.1.1.1', '2.2.2.2', '3.3.3.3'], $decoded);
    }

    /**
     * An empty body decodes to no entries rather than one empty one.
     */
    public function testEmptyBody(): void
    {
        $this->assertSame([], (new TxtDecoder())->decode("\n\n  \n", $this->definition()));
    }
}
