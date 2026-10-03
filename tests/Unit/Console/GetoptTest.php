<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Console;

use Kanopi\Firewall\Console\Getopt;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * `Getopt::parse()` gives what `getopt()` gives (#289).
 *
 * Each case runs PHP's own `getopt()` in a subprocess, where it reads the arguments
 * PHP was started with, and compares. `firewall check` and `firewall init` moved
 * from `getopt()` to this, so any difference would be an argument they used to
 * accept and no longer do.
 */
final class GetoptTest extends AbstractTestCase
{
    private const SHORT = 'hv:w::';

    private const LONG = ['config:', 'ip::', 'header:', 'explain', 'json', 'help'];

    /**
     * @return array<string, array{array<int, string>}>
     */
    public static function arguments(): array
    {
        return [
            'nothing' => [[]],
            'required, joined' => [['--config=a.yml']],
            'required, separate' => [['--config', 'a.yml']],
            'required, nothing after' => [['--config']],
            'required takes an option-looking value' => [['--config', '--json']],
            'required, empty' => [['--config=']],
            'required, empty, then a flag' => [['--config=', '--json']],
            'required, value with =' => [['--config=a=b']],
            'required, zero' => [['--config=0']],
            'required, repeated' => [['--config=a', '--config=b']],
            'optional, joined' => [['--ip=1.2.3.4']],
            'optional, separate, stops there' => [['--ip', '1.2.3.4', '--json']],
            'optional, empty' => [['--ip=']],
            'optional, then bare' => [['--ip=x', '--ip']],
            'flag' => [['--json']],
            'flag, repeated' => [['--json', '--json']],
            'flag with a value' => [['--json=1']],
            'unknown, skipped' => [['--unknown', '--json']],
            'no abbreviation' => [['--he', '--expl']],
            'stops at a non-option' => [['file.yml', '--json']],
            'stops after a non-option' => [['--json', 'file.yml', '--explain']],
            'stops at --' => [['--config=a', '--', '--json']],
            'stops at -' => [['-', '--json']],
            'three dashes' => [['---json']],
            'empty name' => [['--=x', '--json']],
            'repeated header' => [['--header=X:1', '--header', 'Y:2']],
            'short flag' => [['-h']],
            'short flags bundled' => [['-hh']],
            'short, unknown' => [['-x', '--json']],
            'short, unknown in a bundle' => [['-hx']],
            'short required, joined' => [['-vfoo']],
            'short required, separate' => [['-v', 'foo']],
            'short required, nothing after' => [['-v']],
            'short required, option-looking value' => [['-v', '--json']],
            'short optional, joined' => [['-wbar']],
            'short optional, separate' => [['-w', 'bar']],
            'short bundle ending in a value' => [['-hvX']],
            'mixed' => [['--config', 'a', '--json', 'b', '--explain']],
        ];
    }

    /**
     * @param array<int, string> $arguments
     */
    #[DataProvider('arguments')]
    public function testItMatchesGetopt(array $arguments): void
    {
        $script = sprintf(
            'echo json_encode(getopt(%s, %s));',
            var_export(self::SHORT, true),
            var_export(self::LONG, true)
        );

        $process = proc_open([PHP_BINARY, '-r', $script, '--', ...$arguments], [1 => ['pipe', 'w']], $pipes);
        $this->assertIsResource($process);
        $expected = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        proc_close($process);

        $this->assertSame(
            json_decode((string) $expected, true),
            json_decode((string) json_encode(Getopt::parse(['firewall', ...$arguments], self::SHORT, self::LONG)), true)
        );
    }

    /**
     * The program name is not an argument, as `$argv[0]` is not.
     */
    public function testTheProgramNameIsNotParsed(): void
    {
        $this->assertSame([], Getopt::parse(['--json'], '', ['json']));
    }
}
