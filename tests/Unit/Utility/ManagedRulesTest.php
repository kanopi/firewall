<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\ManagedRules;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The file a command owns, and the line it will not cross (#290).
 *
 * The refusals matter more than the successes here. A tool that silently
 * rewrote a hand-written config would destroy the comments `firewall-init`
 * goes to some trouble to generate, and the person who ran it would not find
 * out until they next opened the file.
 */
class ManagedRulesTest extends AbstractTestCase
{
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-managed-' . uniqid();
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @chmod($file, 0600);
            @unlink($file);
        }

        @rmdir($this->dir);
        parent::tearDown();
    }

    /**
     * @param array<int, string> $values
     *
     * @return array<string, mixed>
     */
    private function rule(string $name, array $values = ['198.51.100.1'], string $response = 'block'): array
    {
        return ManagedRules::rule(
            \Kanopi\Firewall\Plugins\IpAddress::class,
            $response,
            $values,
            $name,
            0
        );
    }

    // -----------------------------------------------------------------------
    // Reading
    // -----------------------------------------------------------------------

    /**
     * A file that is not there is the state before the first `add`, not a
     * problem to report.
     */
    public function testAnAbsentFileIsEmptyAndFine(): void
    {
        $this->assertSame(
            ['rules' => [], 'problem' => null],
            ManagedRules::read($this->dir . '/nothing.yml')
        );
    }

    /**
     * A file without the marker was written by a human, and is refused.
     *
     * This is the guard that stops the whole feature turning into the thing it
     * exists to avoid: point `--managed=` at your own config by accident and
     * the next write would replace it with two rules and a generated header.
     */
    public function testAFileWithoutTheMarkerIsRefused(): void
    {
        $path = $this->dir . '/theirs.yml';
        file_put_contents($path, "# mine\nplugins:\n  - plugin: X\n");

        $result = ManagedRules::read($path);

        $this->assertSame([], $result['rules']);
        $this->assertStringContainsString('was not written by this command', (string) $result['problem']);
    }

    /**
     * Round trip: what is written comes back.
     */
    public function testWritingAndReadingBack(): void
    {
        $path = $this->dir . '/managed.yml';

        $this->assertTrue(ManagedRules::write($path, [$this->rule('office')]));

        $result = ManagedRules::read($path);

        $this->assertNull($result['problem']);
        $this->assertCount(1, $result['rules']);
        $this->assertSame('office', ManagedRules::nameOf($result['rules'][0]));
        $this->assertStringContainsString(ManagedRules::MARKER, (string) file_get_contents($path));
    }

    /**
     * An empty managed file is still a valid document, because a `configs:`
     * entry naming a missing file empties the whole configuration -- so the
     * file has to exist before the include does.
     */
    public function testAnEmptyManagedFileIsValidYamlWithNoRules(): void
    {
        $path = $this->dir . '/managed.yml';

        $this->assertTrue(ManagedRules::write($path, []));
        $this->assertSame(['rules' => [], 'problem' => null], ManagedRules::read($path));
        $this->assertStringContainsString('plugins: []', (string) file_get_contents($path));
    }

    /**
     * A managed file that stopped being valid YAML says which, rather than
     * being silently treated as empty and overwritten.
     */
    public function testBrokenYamlIsReportedRatherThanOverwritten(): void
    {
        $path = $this->dir . '/managed.yml';
        file_put_contents($path, ManagedRules::MARKER . "\nplugins:\n  - [unclosed\n");

        $result = ManagedRules::read($path);

        $this->assertSame([], $result['rules']);
        $this->assertStringContainsString('is not valid YAML', (string) $result['problem']);
    }

    /**
     * @param string $body
     *   What sits under the marker.
     * @param string $expected
     *   The fragment the problem must mention.
     */
    #[DataProvider('unusableBodies')]
    public function testAMarkedFileThatIsNotRulesIsReported(string $body, string $expected): void
    {
        $path = $this->dir . '/managed.yml';
        file_put_contents($path, ManagedRules::MARKER . "\n" . $body);

        $result = ManagedRules::read($path);

        $this->assertSame([], $result['rules']);
        $this->assertStringContainsString($expected, (string) $result['problem']);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function unusableBodies(): array
    {
        return [
            'a scalar' => ["just a string\n", 'does not parse to a configuration document'],
            'plugins is not a list' => ["plugins: nope\n", 'not a list'],
        ];
    }

    /**
     * A file that exists and cannot be read is reported, not treated as empty.
     */
    public function testAnUnreadableFileIsReported(): void
    {
        $path = $this->dir . '/managed.yml';
        ManagedRules::write($path, [$this->rule('office')]);

        // Probing the read rather than asking `is_readable()`, which answers
        // the wrong question for root and disagrees with the actual read on
        // some container filesystems.
        if (!chmod($path, 0000) || @file_get_contents($path) !== false) {
            $this->markTestSkipped('Cannot make a file unreadable as this user.');
        }

        $this->assertSame('exists but could not be read', ManagedRules::read($path)['problem']);
    }

    /**
     * Entries that are not rules are dropped rather than carried into a write
     * that would then fail to parse.
     */
    public function testNonArrayEntriesAreDropped(): void
    {
        $path = $this->dir . '/managed.yml';
        file_put_contents($path, ManagedRules::MARKER . "\nplugins:\n  - 'nope'\n  - plugin: X\n");

        $this->assertCount(1, ManagedRules::read($path)['rules']);
    }

    /**
     * A directory that does not exist yet is created, so `--managed=` can name
     * somewhere sensible on a fresh install.
     */
    public function testTheDirectoryIsCreated(): void
    {
        $path = $this->dir . '/nested/deeper/managed.yml';

        $this->assertTrue(ManagedRules::write($path, []));
        $this->assertFileExists($path);

        @unlink($path);
        @rmdir($this->dir . '/nested/deeper');
        @rmdir($this->dir . '/nested');
    }

    /**
     * A path that cannot be written reports failure rather than pretending.
     *
     * Nested under a regular *file*, not under a directory a privileged user
     * happens to be able to create: root in a container can `mkdir` almost
     * anywhere, and a test that relies on it not being able to passes on a
     * laptop and fails in CI. Nothing can make a directory inside a file.
     */
    public function testAnUnwritablePathIsReported(): void
    {
        $blocker = $this->dir . '/not-a-directory';
        file_put_contents($blocker, 'i am a file');

        $this->assertFalse(ManagedRules::write($blocker . '/nested/managed.yml', []));
    }

    // -----------------------------------------------------------------------
    // Naming
    // -----------------------------------------------------------------------

    /**
     * Resolved the way `AbstractPluginBase::getName()` resolves it, so what
     * this prints is what the log will call it (#182).
     *
     * @param array<string, mixed> $rule
     *   The entry.
     * @param string $expected
     *   The name it answers to.
     */
    #[DataProvider('namings')]
    public function testNameResolution(array $rule, string $expected): void
    {
        $this->assertSame($expected, ManagedRules::nameOf($rule));
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function namings(): array
    {
        return [
            'declared' => [['plugin' => 'A\\B\\Url', 'metadata' => ['name' => 'no-xmlrpc']], 'no-xmlrpc'],
            'falls back to the class' => [['plugin' => 'A\\B\\Url'], 'Url'],
            'an empty name is no name' => [['plugin' => 'A\\B\\Url', 'metadata' => ['name' => '']], 'Url'],
            'a non-string name is no name' => [['plugin' => 'A\\B\\Url', 'metadata' => ['name' => 7]], 'Url'],
            'no plugin either' => [[], ''],
        ];
    }

    // -----------------------------------------------------------------------
    // Changing
    // -----------------------------------------------------------------------

    public function testAddAppends(): void
    {
        $result = ManagedRules::add([$this->rule('one')], $this->rule('two'));

        $this->assertNull($result['problem']);
        $this->assertSame(['one', 'two'], array_map(
            static fn(array $rule): string => ManagedRules::nameOf($rule),
            $result['rules']
        ));
    }

    /**
     * A duplicate name is refused, because two rules answering to one name is
     * exactly what the linter tells you to fix (#216) -- generating it would
     * be perverse.
     */
    public function testADuplicateNameIsRefused(): void
    {
        $result = ManagedRules::add([$this->rule('one')], $this->rule('one'));

        $this->assertCount(1, $result['rules']);
        $this->assertStringContainsString('already exists', (string) $result['problem']);
    }

    public function testRemove(): void
    {
        $result = ManagedRules::remove([$this->rule('one'), $this->rule('two')], 'one');

        $this->assertNull($result['problem']);
        $this->assertSame(['two'], array_map(
            static fn(array $rule): string => ManagedRules::nameOf($rule),
            $result['rules']
        ));
    }

    /**
     * Removing leaves a list, not a list with a hole in it -- a gap in the
     * integer keys would dump as a YAML map and stop being a `plugins:` list
     * at all.
     */
    public function testRemoveKeepsTheListDense(): void
    {
        $result = ManagedRules::remove(
            [$this->rule('one'), $this->rule('two'), $this->rule('three')],
            'two'
        );

        $this->assertSame([0, 1], array_keys($result['rules']));
    }

    public function testRemoveWhatIsNotThere(): void
    {
        $result = ManagedRules::remove([$this->rule('one')], 'absent');

        $this->assertCount(1, $result['rules']);
        $this->assertStringContainsString('no managed rule is named "absent"', (string) $result['problem']);
    }

    /**
     * Disabling keeps the definition where the next person can read it. An
     * incident is not the moment to reconstruct a rule from memory.
     */
    public function testDisableAndEnable(): void
    {
        $rules = [$this->rule('one')];

        $off = ManagedRules::setEnabled($rules, 'one', false);
        $this->assertNull($off['problem']);
        $this->assertFalse($off['rules'][0]['enable']);
        $this->assertSame('one', ManagedRules::nameOf($off['rules'][0]), 'The rule is still there');

        $on = ManagedRules::setEnabled($off['rules'], 'one', true);
        $this->assertTrue($on['rules'][0]['enable']);
    }

    public function testEnableWhatIsNotThere(): void
    {
        $result = ManagedRules::setEnabled([], 'absent', true);

        $this->assertStringContainsString('no managed rule is named "absent"', (string) $result['problem']);
    }

    public function testIndexOfMissingIsNull(): void
    {
        $this->assertNull(ManagedRules::indexOf([$this->rule('one')], 'two'));
    }

    // -----------------------------------------------------------------------
    // Inventory
    // -----------------------------------------------------------------------

    /**
     * The `managed` column is the useful part of a listing: without it, an
     * operator is invited to `remove` a rule that cannot be removed, and finds
     * out after deciding it was gone.
     */
    public function testInventoryMarksWhatItOwns(): void
    {
        $managed = [$this->rule('office', ['198.51.100.0/24'], 'allow')];

        $configured = [
            ['plugin' => 'A\\B\\Url', 'response' => 'block', 'weight' => 5, 'metadata' => ['name' => 'xmlrpc']],
            $managed[0],
        ];

        $rows = ManagedRules::inventory($configured, $managed);

        $this->assertSame(['xmlrpc', 'office'], array_column($rows, 'name'));
        $this->assertSame([false, true], array_column($rows, 'managed'));
        $this->assertSame(['block', 'allow'], array_column($rows, 'response'));
        $this->assertSame([5, 0], array_column($rows, 'weight'));
        $this->assertSame([true, true], array_column($rows, 'enabled'));
    }

    /**
     * Ownership is name *and* class. A hand-written rule that happens to share
     * a name with a managed one is still not this command's to change, and
     * both rows appear -- which is itself worth seeing.
     */
    public function testASharedNameOnADifferentPluginIsNotOwned(): void
    {
        $managed = [$this->rule('office')];

        $rows = ManagedRules::inventory(
            [['plugin' => 'A\\B\\Url', 'metadata' => ['name' => 'office']]],
            $managed
        );

        $this->assertFalse($rows[0]['managed']);
    }

    /**
     * A malformed entry in the merged config is skipped rather than crashing a
     * listing -- `plugins: [nope]` is an ordinary mistake (#281).
     */
    public function testInventorySkipsEntriesThatAreNotRules(): void
    {
        $this->assertSame([], ManagedRules::inventory(['nope', 7], []));
    }

    /**
     * Defaults are filled the way the loader fills them, so a listing reflects
     * what will actually run rather than what was typed.
     */
    public function testInventoryFillsDefaults(): void
    {
        $rows = ManagedRules::inventory([['plugin' => 'A\\B\\Url']], []);

        $this->assertSame('block', $rows[0]['response']);
        $this->assertSame(0, $rows[0]['weight']);
        $this->assertTrue($rows[0]['enabled']);
        $this->assertSame('A\\B\\Url', $rows[0]['plugin']);
    }

    /**
     * A rule whose `plugin` is not a string is reported with an empty class
     * rather than being coerced into one.
     */
    public function testInventoryHandlesANonStringPlugin(): void
    {
        $rows = ManagedRules::inventory([['plugin' => 42, 'metadata' => ['name' => 'odd']]], []);

        $this->assertSame('', $rows[0]['plugin']);
    }

    // -----------------------------------------------------------------------
    // Plugin resolution
    // -----------------------------------------------------------------------

    /**
     * @param string $given
     *   What was typed.
     * @param string|null $expected
     *   The class it resolves to.
     */
    #[DataProvider('pluginNames')]
    public function testPluginResolution(string $given, ?string $expected): void
    {
        $this->assertSame($expected, ManagedRules::resolvePlugin($given));
    }

    /**
     * @return array<string, array{string, string|null}>
     */
    public static function pluginNames(): array
    {
        return [
            'alias' => ['ip', \Kanopi\Firewall\Plugins\IpAddress::class],
            'alias, shouted' => ['IP', \Kanopi\Firewall\Plugins\IpAddress::class],
            'alias, padded' => [' url ', \Kanopi\Firewall\Plugins\Url::class],
            'a class' => [\Kanopi\Firewall\Plugins\Asn::class, \Kanopi\Firewall\Plugins\Asn::class],
            'a class with a leading slash' => [
                '\\' . \Kanopi\Firewall\Plugins\Crs::class,
                \Kanopi\Firewall\Plugins\Crs::class,
            ],
            'neither' => ['banana', null],
            'nothing' => ['', null],
        ];
    }

    /**
     * Every alias names a class that exists. An alias is a promise that
     * `--ip=` produces a rule meaning what it looks like; a typo here would
     * break that quietly at the point somebody most needs it.
     */
    public function testEveryAliasResolves(): void
    {
        foreach (ManagedRules::ALIASES as $alias => $class) {
            $this->assertTrue(class_exists($class), sprintf('Alias %s names a missing class', $alias));
            $this->assertSame($class, ManagedRules::resolvePlugin($alias));
        }
    }

    /**
     * The rule builder produces the `plugins:` shape the loader reads.
     */
    public function testRuleShape(): void
    {
        $rule = ManagedRules::rule('A\\B\\Url', 'challenge', ['path:/x'], 'named', -50);

        $this->assertSame([
            'plugin' => 'A\\B\\Url',
            'response' => 'challenge',
            'weight' => -50,
            'enable' => true,
            'metadata' => ['name' => 'named'],
            'config' => ['path:/x'],
        ], $rule);
    }
}
