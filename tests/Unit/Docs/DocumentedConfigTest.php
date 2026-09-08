<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Docs;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * Hold the shipped YAML -- documentation and presets -- to the keys the code reads.
 *
 * `mkdocs build --strict` validates links and anchors, which is how a dead anchor was
 * caught before merge in #160. It validates no configuration at all, and the config
 * loader ignores a key it does not recognise -- so a wrong-but-plausible key is silent
 * twice over.
 *
 * That is not hypothetical. The quick start told every new user to write `file:` under
 * `FileStorage`, which reads `storage_file`. There is no error: FileStorage falls back to
 * a hashed filename in the system temp directory, so the firewall appears to work and
 * keeps its block list somewhere the operator did not choose, cannot find, and may lose
 * on reboot. Five places said it (#189).
 *
 * The confusion is understandable, and worth stating: `FileStorage` and
 * `FileRateLimitStorage` name the same idea differently. `file:` is correct under one and
 * wrong under the other.
 */
class DocumentedConfigTest extends TestCase
{
    /**
     * Config keys each storage class actually reads.
     *
     * Derived from the `$config['...']` accesses in each class. Deliberately explicit
     * rather than reflected: a new backend should have to declare its keys here, and
     * testKnownKeysCoverEveryShippedStorageClass() fails until it does.
     *
     * @var array<class-string|string, list<string>>
     */
    private const STORAGE_KEYS = [
        'Kanopi\\Firewall\\Storage\\FileStorage' => ['storage_file', 'offense_file'],
        'Kanopi\\Firewall\\Storage\\DatabaseStorage' => ['connection', 'storage_table', 'offenses_table', 'schema_check_probability'],
        'Kanopi\\Firewall\\Storage\\InMemoryStorage' => [],
        'Kanopi\\Firewall\\Storage\\RedisStorage' => ['redis', 'instance'],
        'Kanopi\\Firewall\\RateLimitStorage\\FileRateLimitStorage' => ['file'],
        'Kanopi\\Firewall\\RateLimitStorage\\DatabaseRateLimitStorage' => ['connection', 'storage_table', 'schema_check_probability'],
        'Kanopi\\Firewall\\RateLimitStorage\\RedisRateLimitStorage' => ['redis', 'ttl', 'instance'],
        'Kanopi\\Firewall\\RateLimitStorage\\CacheRateLimitStorage' => ['adaptor', 'args', 'ttl'],
        'Kanopi\\Firewall\\RateLimitStorage\\InMemoryRateLimitStorage' => [],
    ];

    /**
     * Every complete yaml block in the documentation must parse.
     *
     * Two kinds of block are deliberately exempt, because holding them to this would
     * make the documentation serve the linter rather than the reader:
     *
     * - **Fragments.** A block whose first line is indented is showing a piece of a
     *   larger document -- `metadata:` and its children, say -- and is not valid YAML
     *   on its own. That is the right way to show one option in context.
     * - **Duplicate keys.** The docs use two same-named blocks side by side to contrast
     *   a wrong form with a right one, or one posture with another, and the surrounding
     *   comments make which is which obvious. `docs/configuration/environment-variables.md`
     *   does exactly this to show that `${VAR}` is never substituted.
     *
     * Everything else -- a stray tab, a bad indent, an unclosed quote -- still fails.
     */
    public function testEveryDocumentedYamlBlockParses(): void
    {
        $failures = [];

        foreach ($this->documentedYamlBlocks() as $where => $yaml) {
            if ($this->isFragment($yaml)) {
                continue;
            }

            try {
                Yaml::parse($yaml);
            } catch (ParseException $parseException) {
                if (str_contains($parseException->getMessage(), 'Duplicate key')) {
                    continue;
                }

                $failures[] = $where . ' — ' . $parseException->getMessage();
            }
        }

        $this->assertSame([], $failures, "Unparseable YAML in the documentation:\n" . implode("\n", $failures));
    }

    /**
     * Whether a block is a piece of a larger document rather than a whole one.
     *
     * @param string $yaml
     *   The block source.
     *
     * @return bool
     *   True when the first meaningful line is indented.
     */
    private function isFragment(string $yaml): bool
    {
        foreach (explode("\n", $yaml) as $line) {
            if (trim($line) === '' || str_starts_with(trim($line), '#')) {
                continue;
            }

            return $line !== ltrim($line);
        }

        return true;
    }

    /**
     * Every shipped preset must parse.
     */
    public function testEveryPresetParses(): void
    {
        $failures = [];

        foreach ($this->presetFiles() as $file) {
            try {
                Yaml::parseFile($file);
            } catch (ParseException $parseException) {
                $failures[] = $file . ' — ' . $parseException->getMessage();
            }
        }

        $this->assertSame([], $failures, "Unparseable preset:\n" . implode("\n", $failures));
    }

    /**
     * A storage block must only use keys its declared class reads.
     *
     * This is the check that would have caught #189.
     */
    public function testDocumentedStorageConfigUsesOnlyKnownKeys(): void
    {
        $failures = [];

        foreach ($this->documentedYamlBlocks() as $where => $yaml) {
            try {
                $parsed = Yaml::parse($yaml);
            } catch (ParseException) {
                // Reported by testEveryDocumentedYamlBlockParses().
                continue;
            }

            if (is_array($parsed)) {
                $this->collectUnknownStorageKeys($parsed, $where, $failures);
            }
        }

        foreach ($this->presetFiles() as $file) {
            try {
                $parsed = Yaml::parseFile($file);
            } catch (ParseException) {
                continue;
            }

            if (is_array($parsed)) {
                $this->collectUnknownStorageKeys($parsed, $file, $failures);
            }
        }

        $this->assertSame(
            [],
            $failures,
            "Storage config keys that the named class does not read:\n" . implode("\n", $failures)
        );
    }

    /**
     * Every shipped storage class must declare its keys above.
     *
     * Without this, adding a backend silently exempts it from the check.
     */
    public function testKnownKeysCoverEveryShippedStorageClass(): void
    {
        $undeclared = [];

        foreach (['Storage', 'RateLimitStorage'] as $directory) {
            foreach (glob(dirname(__DIR__, 3) . '/src/' . $directory . '/*.php') ?: [] as $file) {
                $short = basename($file, '.php');

                // Interfaces, factories and the abstract bases are not backends.
                if (str_contains($short, 'Interface') || str_contains($short, 'Factory') || str_starts_with($short, 'Abstract')) {
                    continue;
                }

                $class = 'Kanopi\\Firewall\\' . $directory . '\\' . $short;

                if (!array_key_exists($class, self::STORAGE_KEYS)) {
                    $undeclared[] = $class;
                }
            }
        }

        $this->assertSame(
            [],
            $undeclared,
            "Storage classes with no declared config keys — add them to STORAGE_KEYS:\n"
            . implode("\n", $undeclared)
        );
    }

    /**
     * Walk a parsed document for `type` + `config` pairs and check the keys.
     *
     * @param array<mixed> $node
     *   The node to walk.
     * @param string $where
     *   Where it came from, for the failure message.
     * @param list<string> $failures
     *   Collected failures, by reference.
     */
    private function collectUnknownStorageKeys(array $node, string $where, array &$failures): void
    {
        $type = $node['type'] ?? null;

        if (is_string($type) && isset($node['config']) && is_array($node['config'])) {
            $class = ltrim(str_replace('\\\\', '\\', $type), '\\');

            if (array_key_exists($class, self::STORAGE_KEYS)) {
                foreach (array_keys($node['config']) as $key) {
                    if (!in_array((string) $key, self::STORAGE_KEYS[$class], true)) {
                        $failures[] = sprintf(
                            '%s — %s does not read "%s" (reads: %s)',
                            $where,
                            $class,
                            (string) $key,
                            implode(', ', self::STORAGE_KEYS[$class]) ?: 'nothing'
                        );
                    }
                }
            }
        }

        foreach ($node as $child) {
            if (is_array($child)) {
                $this->collectUnknownStorageKeys($child, $where, $failures);
            }
        }
    }

    /**
     * Every fenced ```yaml block in docs/, keyed by "file:line".
     *
     * @return array<string, string>
     *   Location to YAML source.
     */
    private function documentedYamlBlocks(): array
    {
        $blocks = [];
        $root = dirname(__DIR__, 3);

        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . '/docs'));

        foreach ($iterator as $file) {
            if (!$file->isFile() || $file->getExtension() !== 'md') {
                continue;
            }

            $lines = file($file->getPathname(), FILE_IGNORE_NEW_LINES) ?: [];
            $open = null;
            $buffer = [];

            foreach ($lines as $number => $line) {
                $trimmed = trim($line);

                if ($open === null && preg_match('/^```ya?ml$/', $trimmed)) {
                    $open = $number + 1;
                    $buffer = [];
                    continue;
                }

                if ($open !== null && $trimmed === '```') {
                    $key = str_replace($root . '/', '', $file->getPathname()) . ':' . $open;
                    $blocks[$key] = implode("\n", $buffer);
                    $open = null;
                    continue;
                }

                if ($open !== null) {
                    $buffer[] = $line;
                }
            }
        }

        return $blocks;
    }

    /**
     * @return list<string>
     *   Absolute paths to every shipped preset.
     */
    private function presetFiles(): array
    {
        return glob(dirname(__DIR__, 3) . '/presets/*.yml') ?: [];
    }
}
