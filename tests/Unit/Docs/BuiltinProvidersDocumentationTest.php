<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Docs;

use Kanopi\Firewall\Utility\ReverseDns\BuiltinProviders;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Hold every built-in reverse DNS provider to a full documentation entry (#473).
 *
 * A provider is a third party that receives the reverse-DNS names of a site's visitors once
 * the site names it. The only place a site can learn who that is, what they say they keep,
 * and on what terms, is `docs/configuration/reverse-dns.md`. So a provider added to
 * `BuiltinProviders` without its section -- or with one missing a heading -- fails here
 * rather than shipping undocumented.
 */
class BuiltinProvidersDocumentationTest extends TestCase
{
    /**
     * The headings every provider's section has, in this order.
     *
     * @var list<string>
     */
    private const HEADINGS = [
        'Operator and jurisdiction',
        'Endpoint and connect address',
        'JSON API',
        'What is sent',
        'What the operator says it logs',
        'Terms',
        'Rate limits',
        'Quirks',
        'Last verified',
    ];

    private static function page(): string
    {
        return (string) file_get_contents(dirname(__DIR__, 3) . '/docs/configuration/reverse-dns.md');
    }

    /**
     * One provider's section: from its `###` heading to the next `##` or `###`.
     */
    private static function section(string $name): ?string
    {
        if (preg_match('/^### `' . preg_quote($name, '/') . '`\n(.*?)(?=^#{2,3} |\z)/ms', self::page(), $match) !== 1) {
            return null;
        }

        return $match[1];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function providers(): array
    {
        $providers = [];

        foreach (BuiltinProviders::names() as $name) {
            $providers[$name] = [$name];
        }

        return $providers;
    }

    #[DataProvider('providers')]
    public function testEveryProviderHasASection(string $name): void
    {
        $this->assertNotNull(self::section($name), sprintf('docs/configuration/reverse-dns.md has no "### `%s`" section', $name));
    }

    #[DataProvider('providers')]
    public function testEverySectionHasEveryHeadingInOrder(string $name): void
    {
        preg_match_all('/^#### (.+)$/m', (string) self::section($name), $matches);

        $this->assertSame(self::HEADINGS, $matches[1], sprintf('The `%s` section must have exactly these headings', $name));
    }

    #[DataProvider('providers')]
    public function testEveryProviderIsInTheComparisonTable(string $name): void
    {
        $this->assertStringContainsString(sprintf('| [`%s`](#%s) |', $name, $name), self::page());
    }

    #[DataProvider('providers')]
    public function testTheDocumentedEndpointIsTheShippedOne(string $name): void
    {
        $options = BuiltinProviders::ALL[$name]['options'];

        $this->assertStringContainsString('`' . $options['endpoint'] . '`', (string) self::section($name));
        $this->assertStringContainsString('`' . $options['address'] . '`', (string) self::section($name));
    }

    #[DataProvider('providers')]
    public function testEverySectionSaysWhenItWasLastVerified(string $name): void
    {
        $this->assertMatchesRegularExpression('/^#### Last verified\n\n\d{4}-\d{2}-\d{2}/m', (string) self::section($name));
    }
}
