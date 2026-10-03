<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Console;

/**
 * PHP's `getopt()`, over an argument list rather than the process's (#289).
 *
 * `getopt()` reads the arguments PHP was started with and nothing else. A
 * subcommand run by `bin/firewall` is handed its own list -- `firewall check
 * --config=x` is `check`'s `--config=x` -- so the two commands that parsed
 * with `getopt()` need the same parse over a list they are given. Same
 * result, case for case, so moving them changed nothing they accept:
 *
 * - Parsing stops at the first argument that is not an option, at `--`, and
 *   at a lone `-`. What follows is not read.
 * - An option it does not know is skipped. There is no abbreviation.
 * - `name:` (required) takes `--name=value`, or the next argument whatever it
 *   looks like. Nothing after it, and it is left out.
 * - `name::` (optional) takes only `--name=value`; `--name` alone is `false`.
 * - An empty `--name=` is left out, and does not take the next argument.
 * - `--flag=value` on a flag is the flag; the value is ignored.
 * - Short options bundle (`-hv`), and a short option with a value takes the
 *   rest of its argument or, if required, the next one.
 * - A flag is `false`. An option given more than once is a list of its values.
 */
final class Getopt
{
    /**
     * Parse options out of an argument list.
     *
     * @param array<int, string> $argv
     *   The arguments, the program name first, as `$argv` is.
     * @param string $short
     *   Short options, as `getopt()` takes them: `hv:w::`.
     * @param array<int, string> $long
     *   Long options, as `getopt()` takes them: `config:`, `ip::`, `json`.
     *
     * @return array<string, string|false|array<int, string|false>>
     *   What `getopt()` would have returned for the same arguments.
     */
    public static function parse(array $argv, string $short, array $long = []): array
    {
        $shortSpec = self::shortSpec($short);
        $longSpec = self::longSpec($long);
        $arguments = array_slice($argv, 1);
        $count = count($arguments);
        $options = [];

        for ($index = 0; $index < $count; $index++) {
            $argument = $arguments[$index];

            if ($argument === '--' || $argument === '-' || !str_starts_with($argument, '-')) {
                break;
            }

            if (str_starts_with($argument, '--')) {
                $name = substr($argument, 2);
                $value = null;

                if (str_contains($name, '=')) {
                    [$name, $value] = explode('=', $name, 2);
                }

                $mode = $longSpec[$name] ?? null;

                if ($mode === null) {
                    continue;
                }

                if ($mode === '') {
                    self::add($options, $name, false);
                    continue;
                }

                if ($value !== null) {
                    if ($value !== '') {
                        self::add($options, $name, $value);
                    }

                    continue;
                }

                if ($mode === '::') {
                    self::add($options, $name, false);
                    continue;
                }

                if ($index + 1 < $count) {
                    self::add($options, $name, $arguments[++$index]);
                }

                continue;
            }

            $letters = substr($argument, 1);
            $length = strlen($letters);

            for ($position = 0; $position < $length; $position++) {
                $letter = $letters[$position];
                $mode = $shortSpec[$letter] ?? null;

                if ($mode === null) {
                    continue;
                }

                if ($mode === '') {
                    self::add($options, $letter, false);
                    continue;
                }

                $rest = substr($letters, $position + 1);

                if ($rest !== '') {
                    self::add($options, $letter, $rest);
                    break;
                }

                if ($mode === '::') {
                    self::add($options, $letter, false);
                    break;
                }

                if ($index + 1 < $count) {
                    self::add($options, $letter, $arguments[++$index]);
                }

                break;
            }
        }

        return $options;
    }

    /**
     * Short options, by letter: `''` a flag, `':'` a required value, `'::'` an optional one.
     *
     * @return array<string, string>
     */
    private static function shortSpec(string $short): array
    {
        preg_match_all('/([A-Za-z0-9])(:{0,2})/', $short, $matches, PREG_SET_ORDER);

        $spec = [];
        foreach ($matches as $match) {
            $spec[$match[1]] = $match[2];
        }

        return $spec;
    }

    /**
     * Long options, by name, as shortSpec().
     *
     * @param array<int, string> $long
     *
     * @return array<string, string>
     */
    private static function longSpec(array $long): array
    {
        $spec = [];

        foreach ($long as $option) {
            $name = rtrim($option, ':');
            $spec[$name] = substr($option, strlen($name));
        }

        return $spec;
    }

    /**
     * Record a value, turning a repeated option into a list.
     *
     * @param array<string, string|false|array<int, string|false>> $options
     */
    private static function add(array &$options, string $name, string|false $value): void
    {
        if (!array_key_exists($name, $options)) {
            $options[$name] = $value;

            return;
        }

        $existing = $options[$name];
        $options[$name] = is_array($existing) ? [...$existing, $value] : [$existing, $value];
    }
}
