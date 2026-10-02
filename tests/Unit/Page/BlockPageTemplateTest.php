<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Page;

use Kanopi\Firewall\Diagnostics\ConfigLinter;
use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallLockdownException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Page\BlockPage;
use Kanopi\Firewall\Plugins\Url;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * An operator's own document for the block and lockdown pages (#456).
 *
 * The built-in page stays the default. A `template` replaces the document, and the page's
 * other keys fill its placeholders.
 */
final class BlockPageTemplateTest extends AbstractTestCase
{
    private const TEMPLATE = <<<'HTML'
<!DOCTYPE html>
<html lang="{{page.lang}}">
<head><title>{{page.title}} · Example Co.</title></head>
<body>
  <main class="panel">
    <h1>{{page.heading}}</h1>
    {{page.message}}
    <p class="meta">Status {{block.status}} · Reference <code>{{request.id}}</code> · {{request.method}} {{request.path}}</p>
    <a title="{{request.header.X-Probe}}" href="/help">Help</a>
  </main>
</body>
</html>
HTML;

    /**
     * @param array<string, mixed> $global
     * @param array<string, mixed> $metadata
     *   The blocking rule's metadata.
     */
    private function firewall(array $global = [], array $metadata = []): Firewall
    {
        return Firewall::create([[
            'global' => $global + ['mode' => 'exception'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'plugins' => [[
                'plugin' => Url::class,
                'response' => 'block',
                'enable' => true,
                'metadata' => $metadata + ['name' => 'no-admin', 'status_code' => 403],
                'config' => ['path:/admin'],
            ]],
        ]]);
    }

    /**
     * @param array<string, string> $headers
     */
    private function blocked(Firewall $firewall, array $headers = [], string $path = '/admin'): FirewallBlockedException
    {
        $request = Request::create($path, 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']);
        $request->headers->add($headers);

        try {
            $firewall->evaluate($request);
        } catch (FirewallBlockedException $exception) {
            return $exception;
        }

        $this->fail('Expected a block.');
    }

    /**
     * The template is the document, filled from the page's keys and the request.
     */
    public function testTheTemplateIsTheDocument(): void
    {
        $exception = $this->blocked($this->firewall(['block_page' => [
            'template' => self::TEMPLATE,
            'lang' => 'fr',
            'heading' => 'Accès refusé',
            'message' => "Cette requête a été bloquée.\nRéférence : {{request.id}}",
        ]]));
        $html = $exception->getMessage();

        $this->assertSame(1, preg_match('/[0-9A-F]{32}/', $html, $id));

        $this->assertSame('text/html; charset=utf-8', $exception->getContentType());
        $this->assertStringStartsWith('<!DOCTYPE html>', $html);
        $this->assertStringContainsString('<html lang="fr">', $html);
        $this->assertStringContainsString('<title>Request blocked · Example Co.</title>', $html, 'An unset title is the built-in one.');
        $this->assertStringContainsString('<h1>Accès refusé</h1>', $html);
        $this->assertStringContainsString("<p>Cette requête a été bloquée.</p>\n<p>Référence : " . $id[0] . '</p>', $html);
        $this->assertStringContainsString('Status 403 · Reference <code>' . $id[0] . '</code> · GET /admin', $html);
        $this->assertStringNotContainsString('<main class="card">', $html, 'Not the built-in document.');
        $this->assertStringNotContainsString('{{', $html);
    }

    /**
     * Without a template, the built-in page is unchanged.
     */
    public function testWithoutATemplateTheBuiltInPageIsServed(): void
    {
        $this->assertStringContainsString('<main class="card">', $this->blocked($this->firewall(['block_page' => true]))->getMessage());
    }

    /**
     * Every substitution is escaped, in text and in an attribute, and the message is the
     * firewall's escaped paragraphs.
     */
    public function testSubstitutionsAreEscaped(): void
    {
        $html = $this->blocked(
            $this->firewall(['block_page' => [
                'template' => self::TEMPLATE,
                'heading' => 'Hi {{request.header.X-Probe}}',
                'message' => 'You sent {{request.header.X-Probe}}',
            ]]),
            ['X-Probe' => '"><script>alert(1)</script>']
        )->getMessage();

        $escaped = '&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;';

        $this->assertStringNotContainsString('<script>', $html);
        $this->assertStringContainsString('<h1>Hi ' . $escaped . '</h1>', $html);
        $this->assertStringContainsString('<p>You sent ' . $escaped . '</p>', $html);
        $this->assertStringContainsString('<a title="' . $escaped . '" href="/help">', $html);
        $this->assertStringNotContainsString('&amp;quot;', $html, 'Escaped once.');
    }

    /**
     * What a client sends is substituted once and never read as a placeholder itself --
     * not even as `{{page.message}}`.
     */
    public function testAClientCannotExpandAPlaceholder(): void
    {
        $html = $this->blocked(
            $this->firewall(['block_page' => ['template' => self::TEMPLATE, 'message' => 'Blocked.']]),
            ['X-Probe' => '{{page.message}} {{request.cookie.session}}']
        )->getMessage();

        $this->assertStringContainsString('<a title="{{page.message}} {{request.cookie.session}}"', $html);
        $this->assertSame(1, substr_count($html, '<p>Blocked.</p>'));
    }

    /**
     * Placeholders are as case-insensitive as the request's always were.
     */
    public function testPagePlaceholdersIgnoreCase(): void
    {
        $html = $this->blocked($this->firewall(['block_page' => [
            'template' => '<html><body><h1>{{ Page.Heading }}</h1>{{PAGE.MESSAGE}}<p>{{Block.Status}}</p></body></html>',
            'heading' => 'H',
            'message' => 'M',
        ]]))->getMessage();

        $this->assertSame('<html><body><h1>H</h1><p>M</p><p>403</p></body></html>', $html);
    }

    /**
     * An unknown placeholder is left as written, so a typo shows.
     */
    public function testAnUnknownPlaceholderIsLeftAsWritten(): void
    {
        $html = $this->blocked($this->firewall(['block_page' => [
            'template' => '<html><body>{{page.mesage}}</body></html>',
        ]]))->getMessage();

        $this->assertSame('<html><body>{{page.mesage}}</body></html>', $html);
    }

    /**
     * A rule's message lands in the global template, and a rule can bring its own.
     */
    public function testARuleFillsOrReplacesTheTemplate(): void
    {
        $html = $this->blocked($this->firewall(
            ['block_page' => ['template' => self::TEMPLATE, 'message' => 'Global.']],
            ['block_page' => ['message' => 'Not this path.']]
        ))->getMessage();

        $this->assertStringContainsString('<p>Not this path.</p>', $html);
        $this->assertStringContainsString('class="panel"', $html);

        $own = $this->blocked($this->firewall(
            ['block_page' => ['template' => self::TEMPLATE]],
            ['block_page' => ['template' => '<html><body>Rule: {{page.message}}</body></html>', 'message' => 'Own.']]
        ))->getMessage();

        $this->assertSame('<html><body>Rule: <p>Own.</p></body></html>', $own);
    }

    /**
     * A page with no message of its own shows `banning_message` in the template too.
     */
    public function testTheTemplateFallsBackToTheBanningMessage(): void
    {
        $html = $this->blocked($this->firewall([
            'block_page' => ['template' => '<html><body>{{page.message}}</body></html>'],
            'banning_message' => 'Refused ({{block.status}}).',
        ]))->getMessage();

        $this->assertSame('<html><body><p>Refused (403).</p></body></html>', $html);
    }

    public function testALockdownTemplate(): void
    {
        try {
            $this->firewall([
                'lockdown' => true,
                'lockdown_allow' => [],
                'lockdown_page' => ['template' => '<html><body><h1>{{page.heading}}</h1>{{page.message}}</body></html>'],
            ])->evaluate(Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']));
            $this->fail('Expected a lockdown.');
        } catch (FirewallLockdownException $exception) {
            $this->assertSame('text/html; charset=utf-8', $exception->getContentType());
            $this->assertSame(
                '<html><body><h1>Temporarily closed</h1><p>This site is temporarily closed to visitors. Please try again shortly.</p></body></html>',
                $exception->getMessage()
            );
        }
    }

    /**
     * JSON still wins for a client that prefers it.
     */
    public function testAJsonClientStillGetsJson(): void
    {
        $exception = $this->blocked(
            $this->firewall(['banning_json' => true, 'block_page' => ['template' => self::TEMPLATE]]),
            ['Accept' => 'application/json']
        );

        $this->assertSame('application/json; charset=utf-8', $exception->getContentType());
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    /**
     * @return array<string, array{array<string, mixed>, array<string, mixed>, string}>
     */
    public static function unusable(): array
    {
        $template = '<html><body>{{page.message}}</body></html>';

        return [
            'a fragment' => [['block_page' => ['template' => '<p>{{page.message}}</p>']], [], 'global.block_page: template must be an HTML document'],
            'not text' => [['block_page' => ['template' => ['x']]], [], 'template must be text'],
            'with styles' => [['block_page' => ['template' => $template, 'styles' => 'p{}']], [], 'styles cannot be set with template'],
            'with both' => [['block_page' => ['template' => $template, 'styles' => 'p{}', 'stylesheet' => '/a.css']], [], 'styles and stylesheet cannot be set with template'],
            'a lockdown with a stylesheet' => [['lockdown_page' => ['template' => $template, 'stylesheet' => '/a.css']], [], 'global.lockdown_page: stylesheet cannot be set with template'],
            'a global template and rule styles' => [
                ['block_page' => ['template' => $template]],
                ['block_page' => ['styles' => 'p{}']],
                'rule "no-admin" metadata.block_page: styles cannot be set with template, which carries its own styling; put it in the template, once merged',
            ],
            'global styles and a rule template' => [
                ['block_page' => ['stylesheet' => '/a.css']],
                ['block_page' => ['template' => $template]],
                'rule "no-admin" metadata.block_page: stylesheet cannot be set with template',
            ],
        ];
    }

    /**
     * @param array<string, mixed> $global
     * @param array<string, mixed> $metadata
     */
    #[DataProvider('unusable')]
    public function testAnUnusableTemplateIsAStartupError(array $global, array $metadata, string $expected): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($expected);

        $this->firewall($global, $metadata);
    }

    /**
     * A conflict inside one setting is that setting's problem, and is not reported a
     * second time as a merged one.
     */
    public function testAConflictIsReportedOnce(): void
    {
        $template = '<html><body>{{page.message}}</body></html>';
        $conflicting = ['template' => $template, 'styles' => 'p{}'];

        $this->assertSame([], BlockPage::mergedProblems($conflicting, ['message' => 'x']));
        $this->assertSame([], BlockPage::mergedProblems(['message' => 'x'], $conflicting));
        $this->assertSame([], BlockPage::mergedProblems(true, ['styles' => 'p{}']));
        $this->assertSame([], BlockPage::mergedProblems(['template' => $template], null));
        $this->assertCount(1, BlockPage::mergedProblems(['template' => $template], ['styles' => 'p{}']));
    }

    public function testATemplateWithoutTheMessageIsAllowed(): void
    {
        $this->assertSame([], BlockPage::problems(['template' => '<html><body>Go away.</body></html>']));
        $this->assertTrue(BlockPage::templateLacksMessage(['template' => '<html><body>Go away.</body></html>']));
        $this->assertFalse(BlockPage::templateLacksMessage(['template' => '<html>{{ page.message }}</html>']));
        $this->assertFalse(BlockPage::templateLacksMessage(true));
    }

    /**
     * The linter warns about a template without the message, and reports the merged
     * conflict as an error.
     */
    public function testTheLinterReportsTemplates(): void
    {
        $findings = (new ConfigLinter([[
            'global' => ['block_page' => ['template' => '<html><body>Go away.</body></html>']],
            'plugins' => [[
                'plugin' => Url::class,
                'response' => 'block',
                'metadata' => ['name' => 'r', 'block_page' => ['styles' => 'p{}']],
                'config' => ['path:/admin'],
            ]],
        ]]))->run();

        $by = static fn(string $status): array => array_values(array_map(
            static fn(Diagnosis $diagnosis): string => $diagnosis->title,
            array_filter($findings, static fn(Diagnosis $diagnosis): bool => $diagnosis->status === $status)
        ));

        $this->assertCount(1, $by(Diagnosis::WARNING));
        $this->assertStringContainsString('`global.block_page` has a template without {{page.message}}', $by(Diagnosis::WARNING)[0]);

        $this->assertCount(1, $by(Diagnosis::ERROR));
        $this->assertStringContainsString('rule "r"', $by(Diagnosis::ERROR)[0]);
        $this->assertStringContainsString('once merged over the global page', $by(Diagnosis::ERROR)[0]);
    }
}
