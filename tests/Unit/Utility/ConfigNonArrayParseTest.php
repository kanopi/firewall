<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\ConfigLoader;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Tests reporting for config inputs that parse to something unusable (#149).
 *
 * The trigger in the wild is a rule *list* handed to a config loader. YAML
 * folds newline-delimited lines into one plain scalar, so the parse succeeds
 * and the rules vanish — previously with nothing written anywhere. For a
 * `response: block` include that fails open; for `response: allow` it fails
 * closed and starts blocking the monitoring it was meant to admit.
 */
class ConfigNonArrayParseTest extends AbstractTestCase
{
    /**
     * Scratch directory for fixtures.
     */
    private string $workspace;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->workspace = sys_get_temp_dir() . '/firewall-nonarray-' . bin2hex(random_bytes(6));
        mkdir($this->workspace, 0775, true);
        Config::clearLoadErrors();
        ConfigLoader::takeLoadErrors();
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        foreach (glob($this->workspace . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->workspace);
        Config::clearLoadErrors();
        parent::tearDown();
    }

    /**
     * Write a fixture and return its path.
     */
    private function fixture(string $name, string $contents): string
    {
        $path = $this->workspace . '/' . $name;
        file_put_contents($path, $contents);

        return $path;
    }

    /**
     * The reported case: a newline-delimited address list.
     */
    public function testNewlineDelimitedListIsReported(): void
    {
        $path = $this->fixture('ips.txt', "216.144.248.16/28\n69.162.124.224/28\n");

        $this->assertSame([], Config::loadFile($path));

        $errors = Config::getLoadErrors();
        $this->assertCount(1, $errors);
        // The loader records the resolved path, which on macOS resolves the
        // temp directory through /private — compare the leaf instead.
        $this->assertSame(basename($path), basename($errors[0]['file']));
        $this->assertStringContainsString('not a configuration mapping', $errors[0]['message']);
    }

    /**
     * The message names the likely cause rather than only the symptom, since
     * "parsed as a string" on its own does not tell an operator what to change.
     */
    public function testMessageExplainsTheFoldedListCase(): void
    {
        Config::loadFile($this->fixture('ips2.txt', "1.2.3.4\n5.6.7.8\n"));

        $message = Config::getLoadErrors()[0]['message'];

        $this->assertStringContainsString('newline-delimited list', $message);
        $this->assertStringContainsString('metadata.sources', $message);
    }

    /**
     * Other scalar documents are reported with their own type.
     *
     * @param string $contents
     *   Fixture contents.
     * @param string $expected
     *   Type the message should name.
     */
    #[DataProvider('scalarDocumentProvider')]
    public function testScalarDocumentsReportTheirType(string $contents, string $expected): void
    {
        Config::loadFile($this->fixture('scalar.yml', $contents));

        $errors = Config::getLoadErrors();

        $this->assertCount(1, $errors);
        $this->assertStringContainsString($expected, $errors[0]['message']);
    }

    /**
     * Documents that parse to something other than a mapping.
     */
    public static function scalarDocumentProvider(): array
    {
        return [
            'string' => ["just a sentence\n", 'string'],
            'integer' => ["42\n", 'int'],
            'boolean' => ["true\n", 'bool'],
            'float' => ["1.5\n", 'float'],
        ];
    }

    /**
     * An empty file is legitimately nothing and must stay silent — otherwise
     * every optional config path in a deployment starts logging an error.
     */
    #[DataProvider('emptyDocumentProvider')]
    public function testEmptyDocumentsAreNotReported(string $contents): void
    {
        $this->assertSame([], Config::loadFile($this->fixture('empty.yml', $contents)));
        $this->assertSame([], Config::getLoadErrors());
    }

    /**
     * Files that contain no configuration but are not mistakes.
     */
    public static function emptyDocumentProvider(): array
    {
        return [
            'completely empty' => [''],
            'whitespace only' => ["\n  \n"],
            'comments only' => ["# nothing here\n# really\n"],
            'explicit null' => ["~\n"],
        ];
    }

    /**
     * A YAML sequence is a perfectly good array and must keep loading — plugin
     * rule files are sequences, so rejecting them would break `metadata.config`.
     */
    public function testSequenceDocumentsStillLoad(): void
    {
        $path = $this->fixture('list.yml', "- 1.2.3.4\n- 5.6.7.8\n");

        $this->assertSame(['1.2.3.4', '5.6.7.8'], Config::loadFile($path));
        $this->assertSame([], Config::getLoadErrors());
    }

    /**
     * A valid mapping is unaffected.
     */
    public function testValidConfigIsUnaffected(): void
    {
        $path = $this->fixture('good.yml', "plugins: []\n");

        $this->assertSame(['plugins' => []], Config::loadFile($path));
        $this->assertSame([], Config::getLoadErrors());
    }

    /**
     * A bad include is reported without taking its parent down with it.
     *
     * This is why the loader records rather than throws: one stray file in a
     * `configs:` glob should cost that file's rules, not the whole ruleset.
     */
    public function testBadIncludeDoesNotDiscardTheParent(): void
    {
        $this->fixture('bad-include.txt', "1.2.3.4\n5.6.7.8\n");
        $parent = $this->fixture('parent.yml', "configs:\n  - bad-include.txt\nplugins: []\n");

        $config = Config::loadFile($parent);

        $this->assertSame(['plugins' => []], $config, "The parent's own config still loads.");

        $errors = Config::getLoadErrors();
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('bad-include.txt', $errors[0]['file']);
    }

    /**
     * A remote config body that parses to a scalar used to raise a TypeError
     * out of postProcess() — an Error, which `loadFile()`'s catch(\Exception)
     * does not catch, so it escaped as a fatal rather than a load error.
     */
    public function testParseOfScalarBodyDoesNotThrow(): void
    {
        $result = ConfigLoader::parse(
            "216.144.248.16/28\n69.162.124.224/28",
            $this->fixture('remote.yml', "plugins: []\n")
        );

        $this->assertSame([], $result);

        $errors = ConfigLoader::takeLoadErrors();
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('not a configuration mapping', $errors[0]['message']);
    }

    /**
     * Draining is destructive, so a second read comes back empty rather than
     * attributing the same failure to a later load.
     */
    public function testTakeLoadErrorsClearsTheList(): void
    {
        ConfigLoader::load($this->fixture('scalar2.yml', "a sentence\n"));

        $this->assertCount(1, ConfigLoader::takeLoadErrors());
        $this->assertSame([], ConfigLoader::takeLoadErrors());
    }

    /**
     * Errors recorded by the loader reach the list `Firewall::create()` reports.
     */
    public function testLoaderErrorsReachTheConfigErrorList(): void
    {
        Config::loadFile($this->fixture('drained.txt', "1.2.3.4\n5.6.7.8\n"));

        $this->assertCount(1, Config::getLoadErrors());
        $this->assertSame([], ConfigLoader::takeLoadErrors(), 'Draining moved them, not copied them.');
    }
}
