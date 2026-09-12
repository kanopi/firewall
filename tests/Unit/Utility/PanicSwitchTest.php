<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\FirewallMode;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\PanicSwitch;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Reading the file that changes the mode without a deploy (#207).
 *
 * The interesting assertions here are the negative ones. A panic switch is a
 * thing that turns a firewall off, so every way of being wrong about the file
 * has to land on "change nothing" -- and each of those ways gets its own test,
 * because a regression in any one of them is a firewall that silently is not
 * running.
 */
class PanicSwitchTest extends AbstractTestCase
{
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-panic-' . uniqid();
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

    private function write(string $contents): string
    {
        $path = $this->dir . '/panic';
        file_put_contents($path, $contents);

        return $path;
    }

    /**
     * No `panic_file` configured is the overwhelmingly common case, and it
     * touches the filesystem not at all.
     *
     * @param mixed $configured
     *   What `global.panic_file` held.
     */
    #[DataProvider('unconfiguredValues')]
    public function testAnUnconfiguredPathIsIdle(mixed $configured): void
    {
        $this->assertSame(
            ['active' => false, 'mode' => null, 'path' => null, 'problem' => null],
            PanicSwitch::read($configured)
        );
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function unconfiguredValues(): array
    {
        return [
            'unset' => [null],
            'empty string' => [''],
            'whitespace only' => ["  \n"],
            // `panic_file: true` is a plausible YAML mistake -- it reads like a
            // feature flag. It is not a path, and reaching file_get_contents()
            // with it would be a TypeError, not a diagnosis (#281's lesson).
            'a boolean' => [true],
            'an array' => [[]],
        ];
    }

    /**
     * A configured path that does not exist reports the path, so a status page
     * can say which file to create, and is otherwise idle.
     */
    public function testAConfiguredPathThatDoesNotExistIsIdle(): void
    {
        $path = $this->dir . '/absent';

        $this->assertSame(
            ['active' => false, 'mode' => null, 'path' => $path, 'problem' => null],
            PanicSwitch::read($path)
        );
    }

    /**
     * A directory is not a panic file. `is_file()` rather than
     * `file_exists()`, so this stops before the read.
     */
    public function testADirectoryIsNotAPanicFile(): void
    {
        $this->assertFalse(PanicSwitch::read($this->dir)['active']);
        $this->assertNull(PanicSwitch::read($this->dir)['problem']);
    }

    /**
     * Every mode the firewall has can be asked for by name.
     */
    #[DataProvider('everyMode')]
    public function testEveryModeCanBeRequested(FirewallMode $mode): void
    {
        $path = $this->write($mode->value);

        $this->assertSame(
            ['active' => true, 'mode' => $mode, 'path' => $path, 'problem' => null],
            PanicSwitch::read($path)
        );
    }

    /**
     * @return array<string, array{FirewallMode}>
     */
    public static function everyMode(): array
    {
        $cases = [];

        foreach (FirewallMode::cases() as $mode) {
            $cases[$mode->value] = [$mode];
        }

        return $cases;
    }

    /**
     * `echo log >` leaves a newline, and an operator typing this at 2am should
     * not have to think about `printf` or about capitals.
     *
     * @param string $contents
     *   What the file holds.
     */
    #[DataProvider('sloppyButUnambiguous')]
    public function testWhitespaceAndCaseAreForgiven(string $contents): void
    {
        $result = PanicSwitch::read($this->write($contents));

        $this->assertTrue($result['active']);
        $this->assertSame(FirewallMode::Log, $result['mode']);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function sloppyButUnambiguous(): array
    {
        return [
            'trailing newline' => ["log\n"],
            'uppercase' => ['LOG'],
            'mixed case and padding' => ["  Log \n"],
            'CRLF' => ["log\r\n"],
        ];
    }

    /**
     * An empty file changes nothing.
     *
     * This is the one that matters most: `touch panic` is the most natural
     * thing to try, and the obvious implementation -- any file means "off" --
     * would disable the firewall here. It has to be inert, and it has to say
     * why, because somebody just tried to use it.
     */
    public function testAnEmptyFileChangesNothingAndSaysSo(): void
    {
        $path = $this->write("\n  \n");
        $result = PanicSwitch::read($path);

        $this->assertFalse($result['active']);
        $this->assertNull($result['mode']);
        $this->assertSame($path, $result['path']);
        $this->assertStringContainsString('does not say what to switch to', (string) $result['problem']);
    }

    /**
     * A file naming something that is not a mode changes nothing, and the
     * report lists what would have worked.
     */
    public function testAnUnrecognisedModeChangesNothingAndListsTheRealOnes(): void
    {
        $result = PanicSwitch::read($this->write('banhammer'));

        $this->assertFalse($result['active']);
        $this->assertNull($result['mode']);
        $this->assertStringContainsString('names "banhammer", which is not a mode', (string) $result['problem']);

        foreach (FirewallMode::cases() as $mode) {
            $this->assertStringContainsString($mode->value, (string) $result['problem']);
        }
    }

    /**
     * A file that exists and cannot be read changes nothing.
     *
     * Fails closed on the *switch*, which means failing open on nothing: the
     * configured mode stands. Reading it as "off" would hand anyone who can
     * make a file unreadable a way to disable the firewall.
     */
    public function testAnUnreadableFileChangesNothing(): void
    {
        $path = $this->write('disabled');

        // Probing the read rather than asking `is_readable()`, which answers
        // the wrong question for root and disagrees with the actual read on
        // some container filesystems: it reported "not readable" while
        // file_get_contents() went ahead and read the file anyway, so the skip
        // did not fire and the test failed instead.
        if (!chmod($path, 0000) || @file_get_contents($path) !== false) {
            $this->markTestSkipped('Cannot make a file unreadable as this user.');
        }

        $result = PanicSwitch::read($path);

        $this->assertFalse($result['active']);
        $this->assertNull($result['mode']);
        $this->assertSame('exists but could not be read', $result['problem']);
    }

    /**
     * The switch escalates as well as relaxes. A deployment sitting in `log`
     * needs a way to start enforcing during an incident, and that is the same
     * file with different contents rather than a second mechanism.
     */
    public function testTheSwitchCanTightenAsWellAsLoosen(): void
    {
        $this->assertSame(FirewallMode::Block, PanicSwitch::read($this->write('block'))['mode']);
    }

    /**
     * The path is trimmed, so a YAML value with a stray trailing space still
     * names the file it looks like it names.
     */
    public function testThePathIsTrimmed(): void
    {
        $path = $this->write('log');

        $this->assertSame($path, PanicSwitch::read('  ' . $path . ' ')['path']);
        $this->assertTrue(PanicSwitch::read('  ' . $path . ' ')['active']);
    }
}
