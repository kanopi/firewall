<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Source\TemplateRenderer;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Tests every documented way of shaping a record into a plugin entry.
 */
class TemplateRendererTest extends AbstractTestCase
{
    /**
     * The renderer under test.
     */
    private TemplateRenderer $renderer;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->renderer = new TemplateRenderer();
    }

    /**
     * No template passes the record through untouched, which is what a source
     * already publishing rules in our own shape needs.
     */
    public function testNullTemplatePassesRecordThrough(): void
    {
        $this->assertSame('1.2.3.4', $this->renderer->render('1.2.3.4', null));
        $this->assertSame(['a' => 'b'], $this->renderer->render(['a' => 'b'], null));
    }

    /**
     * Each documented reference form resolves against its record shape.
     */
    #[DataProvider('referenceFormProvider')]
    public function testDocumentedReferenceForms(mixed $record, string $template, mixed $expected): void
    {
        $this->assertSame($expected, $this->renderer->render($record, $template));
    }

    /**
     * The table from the class docblock, as executable cases.
     */
    public static function referenceFormProvider(): array
    {
        return [
            'scalar line' => [
                '1.2.3.4',
                '{value}',
                '1.2.3.4',
            ],
            'json object field' => [
                ['ip_prefix' => '3.5.140.0/22', 'service' => 'EC2'],
                '{value[ip_prefix]}',
                '3.5.140.0/22',
            ],
            'csv row by column name' => [
                ['asn' => '13335', 'org' => 'CLOUDFLARENET'],
                'asn:{value[asn]}',
                'asn:13335',
            ],
            'csv row by position' => [
                ['13335', 'CLOUDFLARENET'],
                'asn:{value[0]}',
                'asn:13335',
            ],
            'nested field' => [
                ['geo' => ['country' => 'US']],
                '{value[geo][country]}',
                'US',
            ],
            'alternation picks the key present' => [
                ['ipv6_prefix' => '2600:1f01::/40'],
                '{value[ip_prefix|ipv6_prefix]}',
                '2600:1f01::/40',
            ],
            'alternation prefers the first present' => [
                ['ip_prefix' => '1.2.3.0/24', 'ipv6_prefix' => '2600::/40'],
                '{value[ip_prefix|ipv6_prefix]}',
                '1.2.3.0/24',
            ],
            'brace alternation' => [
                ['ipv6_prefix' => '2600:1f01::/40'],
                '{value[{ip_prefix,ipv6_prefix}]}',
                '2600:1f01::/40',
            ],
            'text around the placeholder' => [
                'sqlmap',
                'client.name@contains:{value}',
                'client.name@contains:sqlmap',
            ],
            'several placeholders' => [
                ['name' => 'sqlmap', 'op' => 'contains'],
                'client.name@{value[op]}:{value[name]}',
                'client.name@contains:sqlmap',
            ],
        ];
    }

    /**
     * A template that is exactly one placeholder keeps the field's own type,
     * so a numeric column stays numeric instead of becoming a string.
     */
    public function testWholePlaceholderPreservesType(): void
    {
        $this->assertSame(443, $this->renderer->render(['port' => 443], '{value[port]}'));
        $this->assertTrue($this->renderer->render(['bot' => true], '{value[bot]}'));
    }

    /**
     * Interpolating into surrounding text is string concatenation, so booleans
     * render readably rather than as "1" and "".
     */
    public function testBooleansStringifyReadably(): void
    {
        $this->assertSame('bot:true', $this->renderer->render(['b' => true], 'bot:{value[b]}'));
        $this->assertSame('bot:false', $this->renderer->render(['b' => false], 'bot:{value[b]}'));
    }

    /**
     * A map template interpolates into its leaf strings, which is how grouped
     * rules — the shape Url and UserAgent accept — get built.
     */
    public function testMapTemplateRendersLeaves(): void
    {
        $rendered = $this->renderer->render(
            ['name' => 'sqlmap', 'is_bot' => true],
            [
                'type' => 'AND',
                'rules' => [
                    'client.name@contains:{value[name]}',
                    'bot:{value[is_bot]}',
                ],
            ]
        );

        $this->assertSame([
            'type' => 'AND',
            'rules' => ['client.name@contains:sqlmap', 'bot:true'],
        ], $rendered);
    }

    /**
     * Non-string leaves in a map template are carried through as-is.
     */
    public function testMapTemplateKeepsNonStringLeaves(): void
    {
        $rendered = $this->renderer->render(['v' => 'x'], ['negate' => true, 'value' => '{value[v]}']);

        $this->assertSame(['negate' => true, 'value' => 'x'], $rendered);
    }

    /**
     * An unresolvable placeholder drops the record rather than emitting a
     * half-built rule — a rule with a hole in it would match the wrong things.
     */
    #[DataProvider('unresolvableProvider')]
    public function testUnresolvablePlaceholderDropsRecord(mixed $record, string|array $template): void
    {
        $this->assertNull($this->renderer->render($record, $template));
    }

    /**
     * Records and templates that cannot produce an entry.
     */
    public static function unresolvableProvider(): array
    {
        return [
            'missing field' => [['a' => 1], '{value[missing]}'],
            'missing field mid-string' => [['a' => 1], 'asn:{value[missing]}'],
            'descend into scalar' => [['a' => 1], '{value[a][b]}'],
            'bare value on a map' => [['a' => 1], '{value}'],
            'array field mid-string' => [['a' => [1, 2]], 'asn:{value[a]}'],
            'map template with a bad leaf' => [['a' => 1], ['rules' => ['{value[missing]}']]],
            'nested map template with a bad leaf' => [['a' => 1], ['r' => ['n' => ['{value[missing]}']]]],
        ];
    }

    /**
     * Doubled braces produce literal braces, so a template can emit one.
     */
    public function testBracesCanBeEscaped(): void
    {
        $this->assertSame('{value}', $this->renderer->render('x', '{{value}}'));
        $this->assertSame('a{b}c', $this->renderer->render('x', 'a{{b}}c'));
    }

    /**
     * A template with no placeholders is a constant.
     */
    public function testTemplateWithoutPlaceholders(): void
    {
        $this->assertSame('bot:true', $this->renderer->render(['anything' => 1], 'bot:true'));
    }

    /**
     * A null field is treated as absent, dropping the record.
     */
    public function testNullFieldDropsRecord(): void
    {
        $this->assertNull($this->renderer->render(['a' => null], '{value[a]}'));
    }
}
