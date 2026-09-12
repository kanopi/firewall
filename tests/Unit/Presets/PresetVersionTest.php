<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Presets;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Every shipped rule set declares a version, and every version is written down.
 *
 * Presets ship *inside* the package, so `composer update` can change what gets blocked on a
 * production site without one line of that site's configuration changing (#212). The
 * version in each preset header is what makes that change reportable; a changelog nobody is
 * obliged to write is one that is written until the first hurried afternoon.
 *
 * The classification is explicit rather than inferred. "Has a `plugins:` key" would call
 * `example-usage.yml` a rule set, and a new preset added without being classified would be
 * silently exempt from both lists -- which is the failure mode this whole issue is about.
 */
class PresetVersionTest extends TestCase
{
    /**
     * Presets whose change alters which traffic is affected.
     *
     * @var array<int, string>
     */
    private const RULE_SETS = [
        'ai-answer-engines.yml',
        'ai-crawlers-challenge.yml',
        'ai-crawlers.yml',
        'drupal-admin.yml',
        'drupal.yml',
        'malicious-requests.yml',
        'malicious-urls.yml',
        'rate-limiting.yml',
        'search-bots.yml',
        'wordpress.yml',
    ];

    /**
     * Presets that ship and are deliberately not versioned.
     *
     * `config`, `logging-pantheon` and `storage-pantheon` configure infrastructure rather
     * than enforcement: changing them cannot change which traffic is affected. The
     * `example-*` files are documentation and are not meant to be included in a real
     * configuration.
     *
     * @var array<int, string>
     */
    private const NOT_VERSIONED = [
        'config.yml',
        'logging-pantheon.yml',
        'storage-pantheon.yml',
        'example-malicious-requests-usage.yml',
        'example-rate-limiting-usage.yml',
        'example-usage.yml',
    ];

    private static function presetsDir(): string
    {
        return dirname(__DIR__, 3) . '/presets';
    }

    /**
     * @return array<string, array{string}>
     */
    public static function ruleSets(): array
    {
        $cases = [];

        foreach (self::RULE_SETS as $file) {
            $cases[$file] = [$file];
        }

        return $cases;
    }

    /**
     * A rule set says which version it is.
     *
     * @param string $file
     *   The preset filename.
     */
    #[DataProvider('ruleSets')]
    public function testARuleSetDeclaresItsVersion(string $file): void
    {
        $path = self::presetsDir() . '/' . $file;

        $this->assertFileExists($path);

        $this->assertSame(
            1,
            preg_match('/^# Preset-Version: (\d+)/m', (string) file_get_contents($path)),
            sprintf(
                '%s has no `# Preset-Version: N` header. Without it, a change to what this '
                . 'preset blocks reaches production on `composer update` with nothing to '
                . 'point at.',
                $file
            )
        );
    }

    /**
     * And the changelog accounts for that version.
     *
     * @param string $file
     *   The preset filename.
     */
    #[DataProvider('ruleSets')]
    public function testTheChangelogAccountsForThatVersion(string $file): void
    {
        $contents = (string) file_get_contents(self::presetsDir() . '/' . $file);

        preg_match('/^# Preset-Version: (\d+)/m', $contents, $version);

        $changelog = (string) file_get_contents(self::presetsDir() . '/CHANGELOG.md');

        $this->assertStringContainsString(
            '## Version ' . $version[1],
            $changelog,
            sprintf('%s declares version %s, which presets/CHANGELOG.md does not document.', $file, $version[1])
        );

        $this->assertStringContainsString(
            $file,
            $changelog,
            sprintf('%s is not mentioned anywhere in presets/CHANGELOG.md.', $file)
        );
    }

    /**
     * Every shipped preset is classified, one way or the other.
     *
     * The check that makes the two lists above worth having: a preset added to the
     * directory and to neither list fails here rather than quietly shipping unversioned.
     */
    public function testEveryShippedPresetIsClassified(): void
    {
        $found = array_map('basename', glob(self::presetsDir() . '/*.yml') ?: []);

        sort($found);

        $classified = array_merge(self::RULE_SETS, self::NOT_VERSIONED);
        sort($classified);

        $this->assertSame(
            $classified,
            $found,
            'A preset was added or removed without being classified. Add it to RULE_SETS if a '
            . 'change to it would change which traffic is affected, or to NOT_VERSIONED with a '
            . 'reason if it cannot.'
        );
    }
}
