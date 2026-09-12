<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Docs;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Hold every doc path the *code* prints to a page that exists.
 *
 * `firewall-doctor` and `firewall-check --lint` end a finding with a pointer:
 *
 * ```
 *   ✗ GeoIP database not found
 *       See docs/how-to/geoip-setup.md
 * ```
 *
 * That pointer is a `Diagnosis::$reference` string. It is not a link, `mkdocs build
 * --strict` never sees it, and nothing else checks it -- so a page renamed or moved during
 * a docs restructure leaves the diagnostic pointing at a 404, and the first person to find
 * out is an operator following it during an incident. Which is the one moment the pointer
 * exists for.
 *
 * This is the same discipline `DocumentedConfigTest` applies to shipped YAML: the code and
 * the docs make claims about each other, and neither one is checked by the other's tooling.
 *
 * Anchors are checked too, and they are the half that rots quietly. Renaming a heading
 * from "When a stale rule source becomes an error" to "Making a stale rule source fail the
 * deploy" leaves the file resolving perfectly and the fragment pointing at nothing.
 */
class DocumentedReferenceTest extends TestCase
{
    /**
     * Where the docs live.
     */
    private static function docsDir(): string
    {
        return dirname(__DIR__, 3) . '/docs';
    }

    /**
     * Every `Diagnosis` reference the shipped code can print.
     *
     * Scraped rather than listed, so a new diagnostic is covered the moment it is written
     * instead of when somebody remembers to add it here. A hand-maintained list would pass
     * for exactly as long as it took the first person to forget.
     *
     * @return array<string, array{string, string}>
     *   Keyed by reference, carrying the reference and the file it was found in.
     */
    public static function references(): array
    {
        $root = dirname(__DIR__, 3);
        $found = [];

        foreach (['src', 'bin'] as $dir) {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($root . '/' . $dir)
            );

            foreach ($iterator as $file) {
                if (!$file instanceof \SplFileInfo || !$file->isFile()) {
                    continue;
                }

                // bin/ scripts carry no extension, so filtering on `.php` would
                // skip every command -- which is where most of these are printed.
                if ($file->getExtension() !== '' && $file->getExtension() !== 'php') {
                    continue;
                }

                $contents = (string) file_get_contents($file->getPathname());

                // Single-quoted, `section/page.md` with an optional `#anchor`.
                // Deliberately narrow: a looser pattern picks up the doc paths
                // inside comments, which are prose rather than a promise the
                // code makes at runtime.
                preg_match_all(
                    "/'((?:configuration|guides|plugins|presets|reference|getting-started|contributing)\/[a-z0-9-]+\.md(?:#[a-z0-9-]+)?)'/",
                    $contents,
                    $matches
                );

                foreach ($matches[1] as $reference) {
                    $found[$reference] = [$reference, str_replace($root . '/', '', $file->getPathname())];
                }
            }
        }

        ksort($found);

        return $found;
    }

    /**
     * The page exists.
     *
     * @param string $reference
     *   The reference as the code prints it.
     * @param string $source
     *   The file it came from, so a failure names something actionable.
     */
    #[DataProvider('references')]
    public function testTheReferencedPageExists(string $reference, string $source): void
    {
        [$page] = array_pad(explode('#', $reference, 2), 2, null);

        $this->assertFileExists(
            self::docsDir() . '/' . $page,
            sprintf('%s points at docs/%s, which does not exist. Printed by firewall-doctor.', $source, $page)
        );
    }

    /**
     * The anchor exists, when one is named.
     *
     * Derived the way MkDocs derives it -- lowercase, non-alphanumerics to
     * hyphens -- rather than by trusting the heading text, because that is what
     * the published page will actually contain.
     *
     * @param string $reference
     *   The reference as the code prints it.
     * @param string $source
     *   The file it came from.
     */
    #[DataProvider('references')]
    public function testTheReferencedAnchorExists(string $reference, string $source): void
    {
        [$page, $anchor] = array_pad(explode('#', $reference, 2), 2, null);

        if ($anchor === null) {
            $this->addToAssertionCount(1);

            return;
        }

        $path = self::docsDir() . '/' . $page;

        if (!is_file($path)) {
            // The page test above already reports this; failing twice for one
            // cause makes the output harder to read, not more informative.
            $this->markTestSkipped(sprintf('docs/%s does not exist.', $page));
        }

        $this->assertContains(
            $anchor,
            self::anchorsIn($path),
            sprintf(
                '%s points at docs/%s#%s. The page exists and has no such heading — '
                . 'a heading was renamed and the reference was not.',
                $source,
                $page,
                $anchor
            )
        );
    }

    /**
     * The anchors MkDocs will generate for a page.
     *
     * @param string $path
     *   The Markdown file.
     *
     * @return array<int, string>
     *   Anchor slugs.
     */
    private static function anchorsIn(string $path): array
    {
        $anchors = [];

        foreach (explode("\n", (string) file_get_contents($path)) as $line) {
            if (!str_starts_with($line, '#')) {
                continue;
            }

            $heading = trim(ltrim($line, '#'));

            // An explicit `{ #custom-id }` wins, the same way it does in the
            // rendered page.
            if (preg_match('/\{\s*#([a-z0-9-]+)\s*\}\s*$/i', $heading, $explicit) === 1) {
                $anchors[] = strtolower($explicit[1]);
                continue;
            }

            // Strip inline formatting before slugging: `**Mode**` and `` `mode` ``
            // both render as an anchor of `mode`, not `mode-1`.
            $heading = str_replace(['`', '*', '_'], '', $heading);

            // Links render as their text: `[mike](https://…)` -> `mike`.
            $heading = (string) preg_replace('/\[([^\]]*)\]\([^)]*\)/', '$1', $heading);

            $slug = strtolower($heading);
            $slug = (string) preg_replace('/[^\p{L}\p{N}\- ]+/u', '', $slug);
            $slug = str_replace(' ', '-', trim($slug));

            if ($slug !== '') {
                $anchors[] = $slug;
            }
        }

        return $anchors;
    }

    /**
     * There are references to check at all.
     *
     * The scrape is a regular expression over two directories. If it silently
     * matched nothing -- a moved file, a changed quoting style -- every test
     * above would pass by testing nothing, which is the failure mode a data
     * provider makes easiest to miss.
     */
    public function testTheScrapeFoundReferences(): void
    {
        $references = self::references();

        $this->assertGreaterThanOrEqual(
            10,
            count($references),
            'The reference scrape found almost nothing, which means the scrape is broken rather than the docs being clean.'
        );

        // Asserted against the file the references live in rather than a
        // specific path, because the paths are exactly what moves -- pinning
        // one here means this canary fails during every restructure for the
        // wrong reason, which is how a canary gets deleted.
        $this->assertContains(
            'src/Diagnostics/Doctor.php',
            array_column($references, 1),
            'The scrape found no references in Doctor.php, which is where most of them live.'
        );
    }
}
