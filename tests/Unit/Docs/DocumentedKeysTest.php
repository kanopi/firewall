<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Docs;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Hold the one-page key reference to keys the code actually reads.
 *
 * `docs/reference/configuration-keys.md` exists to answer "what was that key called
 * again" (#196). A lookup table that has drifted is worse than no lookup table: it answers
 * confidently and wrongly, and the reader has no reason to doubt it.
 *
 * The config loader ignores a key it does not recognise, so a wrong-but-plausible key is
 * silent twice over -- which is how five pages came to tell people to write `file:` under
 * `FileStorage`, which reads `storage_file` (#189). That page is the fix for that class of
 * mistake, and this is what stops it becoming another instance of it.
 *
 * Direction matters. This asserts **every key the page names is real**, not the reverse.
 * "Every key in the code is documented" sounds stronger and is not enforceable: `src/`
 * reads plenty of nested keys that belong to a plugin's own rule syntax rather than to
 * configuration, and a test that demanded a table row for each would be turned off within
 * a month. Catching a *phantom* key is the half that prevents the #189 failure.
 */
class DocumentedKeysTest extends TestCase
{
    /**
     * Values, not keys. They appear in the page in backticks because that is how a value
     * is written, and asserting they are readable as configuration keys would be asserting
     * something untrue.
     *
     * @var array<int, string>
     */
    private const NOT_KEYS = [
        'true', 'false', 'null', 'int', 'bool', 'string', 'list', 'map', 'class',
    ];

    private static function page(): string
    {
        return dirname(__DIR__, 3) . '/docs/reference/configuration-keys.md';
    }

    /**
     * Everything the page presents in backticks that is shaped like a key.
     *
     * @return array<string, array{string}>
     *   Keyed by the token, so a duplicate row does not run twice.
     */
    public static function documentedKeys(): array
    {
        $contents = (string) file_get_contents(self::page());

        // Fenced blocks are examples, not claims about key names.
        $contents = (string) preg_replace('/```.*?```/s', '', $contents);

        preg_match_all('/`([A-Za-z_][A-Za-z0-9_]*)`/', $contents, $matches);

        $keys = [];

        foreach (array_unique($matches[1]) as $token) {
            if (in_array($token, self::NOT_KEYS, true)) {
                continue;
            }

            // snake_case settings and the SHOUTED constants; nothing else is a key.
            if (preg_match('/^[a-z][a-z0-9_]*$/', $token) !== 1
                && preg_match('/^KANOPI_[A-Z0-9_]+$/', $token) !== 1
            ) {
                continue;
            }

            $keys[$token] = [$token];
        }

        ksort($keys);

        return $keys;
    }

    /**
     * The code reads it.
     *
     * @param string $key
     *   A key named by the reference page.
     */
    #[DataProvider('documentedKeys')]
    public function testTheKeyIsReadByTheCode(string $key): void
    {
        $this->assertTrue(
            self::appearsInSource($key),
            sprintf(
                'docs/reference/configuration-keys.md documents `%s`, which nothing in src/ '
                . 'reads. Either it was renamed and the table was not, or it never existed — '
                . 'and the loader ignores an unknown key silently, so nobody would find out.',
                $key
            )
        );
    }

    /**
     * Whether `src/` mentions a token as a string literal or a constant.
     *
     * Deliberately a text search rather than anything cleverer. The keys arrive from YAML
     * and are read as array offsets in a dozen different shapes -- `$config['x']`,
     * `$metadata['x'] ??=`, `array_key_exists('x', ...)`, a `match` arm -- and a parser
     * tight enough to model all of them would fail on the next shape somebody writes.
     *
     * @param string $key
     *   The token.
     *
     * @return bool
     *   TRUE when it appears.
     */
    private static function appearsInSource(string $key): bool
    {
        static $haystack = null;

        if ($haystack === null) {
            $haystack = '';
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator(dirname(__DIR__, 3) . '/src')
            );

            foreach ($iterator as $file) {
                if ($file instanceof \SplFileInfo && $file->isFile() && $file->getExtension() === 'php') {
                    $haystack .= (string) file_get_contents($file->getPathname());
                }
            }
        }

        return str_contains($haystack, "'" . $key . "'")
            || str_contains($haystack, '"' . $key . '"');
    }

    /**
     * A backend's keys are read by *that backend*.
     *
     * `testTheKeyIsReadByTheCode()` only proves a key exists somewhere, and that is not
     * enough for the mistake this page was written to prevent: `file` under `FileStorage`
     * passes it, because `file` is real -- `FileRateLimitStorage` reads it. Two backends,
     * two spellings of the same idea, and the wrong one falls back to a hashed filename in
     * the system temp directory rather than erroring (#189).
     *
     * So the storage tables are checked against the class each row names, following the
     * inheritance chain because `FileStorage extends InMemoryStorage`.
     *
     * @param string $class
     *   The backend class named in the row.
     * @param string $key
     *   A key the row attributes to it.
     */
    #[DataProvider('backendKeys')]
    public function testABackendsKeysAreReadByThatBackend(string $class, string $key): void
    {
        $reflectionClass = new \ReflectionClass($class);
        $source = '';

        while ($reflectionClass instanceof \ReflectionClass) {
            $file = $reflectionClass->getFileName();

            if (is_string($file) && is_file($file)) {
                $source .= (string) file_get_contents($file);
            }

            $reflectionClass = $reflectionClass->getParentClass() ?: null;
        }

        // `config['x']`, not just `'x'`. FileStorage logs `['file' => …]` seven times
        // as a *log context* key, which made a looser needle accept `file` as one of its
        // configuration keys -- the exact mistake this test exists to reject.
        $this->assertStringContainsString(
            "config['" . $key . "']",
            $source,
            sprintf(
                'The key reference attributes `%s` to %s, which never reads it as '
                . 'configuration. Check it is not the other backend\'s spelling — that '
                . 'mistake does not error, it silently stores somewhere you did not choose.',
                $key,
                $class
            )
        );
    }

    /**
     * Backend rows from the storage tables: `| \`ClassName\` | \`key\`, \`key\` | … |`.
     *
     * @return array<string, array{string, string}>
     *   Keyed "Class::key".
     */
    public static function backendKeys(): array
    {
        $namespaces = [
            'Kanopi\\Firewall\\Storage\\',
            'Kanopi\\Firewall\\RateLimitStorage\\',
        ];

        $rows = [];

        foreach (explode("\n", (string) file_get_contents(self::page())) as $line) {
            if (preg_match('/^\|\s*`([A-Za-z]+Storage)`\s*\|(.*)$/', $line, $m) !== 1) {
                continue;
            }

            $class = null;

            foreach ($namespaces as $namespace) {
                if (class_exists($namespace . $m[1])) {
                    $class = $namespace . $m[1];
                    break;
                }
            }

            if ($class === null) {
                continue;
            }

            // Only the cell that lists the keys, not the prose column after it.
            $cell = explode('|', $m[2])[0];

            preg_match_all('/`([a-z][a-z0-9_]*)`/', $cell, $keys);

            foreach ($keys[1] as $key) {
                $rows[$m[1] . '::' . $key] = [$class, $key];
            }
        }

        ksort($rows);

        return $rows;
    }

    /**
     * The page was actually read.
     *
     * A regex over a file that moved would find nothing and pass every test above by
     * testing none of them.
     */
    public function testThePageWasFound(): void
    {
        $this->assertFileExists(self::page());
        $this->assertGreaterThan(
            30,
            count(self::documentedKeys()),
            'Far too few keys were extracted — the page moved, or its formatting changed.'
        );

        $this->assertGreaterThan(
            8,
            count(self::backendKeys()),
            'No backend rows were parsed, so the per-backend check is asserting nothing.'
        );
    }
}
