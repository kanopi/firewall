<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * Rules a command owns, in a file a human does not (#290).
 *
 * ## Why there is a second file at all
 *
 * The obvious design is a command that edits `firewall.yml` in place. It cannot be built
 * without breaking something, and the reason was measured rather than assumed:
 *
 * ```
 * === original ===              === after Yaml::dump(Yaml::parse(...)) ===
 * # a comment that matters      global:
 * global:                         mode: log
 *   # why this is log           plugins:
 *   mode: log                     - plugin: A
 * plugins:
 *   - plugin: A   # trailing note
 * ```
 *
 * Symfony's YAML has no comment-preserving round trip, and `bin/firewall-init` (#210) goes
 * to some trouble to generate a *heavily commented* config precisely so an operator reads it
 * and edits it. A command whose first `add` silently deleted all of that would have taken
 * something away, and the person who ran it would not find out until they next opened the
 * file.
 *
 * So this owns a file of its own, and rewriting *that* one costs nothing, because everything
 * in it was written by this class.
 *
 * ## What that buys, and what it cannot
 *
 * Measured against the loader rather than guessed at:
 *
 * - **Root-level `plugins:` appends across includes.** `ConfigLoader::mergeConfigs()`
 *   special-cases it; every other list is replaced wholesale. So a rule in the managed file
 *   lands *beside* the ones a human wrote, keeping its own `config:` list, and adding is
 *   clean.
 * - **Nothing merges into an existing rule.** Declaring the same rule again produces two
 *   entries, not one modified one -- and since #216 the linter warns about two rules sharing
 *   a name, so a tool that did that would be generating exactly what the linter tells you to
 *   fix.
 *
 * That second point is the whole shape of this feature: **rules this wrote can be added,
 * removed, enabled and disabled; rules a human wrote can only be listed.** Pretending
 * otherwise would mean either destroying comments or splicing lines into arbitrary YAML --
 * flow style, anchors, multi-document files, whatever indentation the writer chose -- and
 * getting that wrong quietly disables a rule somebody is relying on.
 *
 * The refusal is explicit and names the file, so the answer to "why will it not disable this
 * one" is on screen rather than in the docs.
 */
class ManagedRules
{
    /**
     * Short names for the rule types worth typing at 2am.
     *
     * Not every plugin: an alias is a promise that `--ip=198.51.100.5` produces a rule that
     * means what it looks like, and that only holds for plugins whose `config:` is a plain
     * list of values. `--plugin=` takes any class for the rest.
     *
     * @var array<string, class-string>
     */
    public const ALIASES = [
        'ip' => \Kanopi\Firewall\Plugins\IpAddress::class,
        'url' => \Kanopi\Firewall\Plugins\Url::class,
        'agent' => \Kanopi\Firewall\Plugins\UserAgent::class,
        'asn' => \Kanopi\Firewall\Plugins\Asn::class,
        'geo' => \Kanopi\Firewall\Plugins\GeoLocation::class,
    ];

    /**
     * The buckets a rule can be filed under.
     *
     * @var array<int, string>
     */
    public const RESPONSES = ['allow', 'block', 'challenge'];

    /**
     * The line that says a file is not to be hand-edited.
     *
     * Matched on read, not just written: a file without it is a file somebody wrote
     * themselves, and overwriting it would be the exact loss this class exists to avoid.
     */
    public const MARKER = '# Managed by bin/firewall-rule. Edits here are overwritten.';

    /**
     * Read the rules out of a managed file.
     *
     * @param string $path
     *   The managed file.
     *
     * @return array{rules: array<int, array<string, mixed>>, problem: string|null}
     *   The rules, and why there are none when a file exists and could not be
     *   used. A file that is simply absent is not a problem -- it is the state
     *   before the first `add`.
     */
    public static function read(string $path): array
    {
        if (!is_file($path)) {
            return ['rules' => [], 'problem' => null];
        }

        $contents = @file_get_contents($path);

        if ($contents === false) {
            return ['rules' => [], 'problem' => 'exists but could not be read'];
        }

        if (!str_contains($contents, self::MARKER)) {
            return [
                'rules' => [],
                'problem' => 'exists and was not written by this command, so it will not be overwritten',
            ];
        }

        try {
            $parsed = Yaml::parse($contents);
        } catch (ParseException $parseException) {
            return ['rules' => [], 'problem' => 'is not valid YAML: ' . $parseException->getMessage()];
        }

        if (!is_array($parsed)) {
            return ['rules' => [], 'problem' => 'does not parse to a configuration document'];
        }

        $rules = $parsed['plugins'] ?? [];

        if (!is_array($rules)) {
            return ['rules' => [], 'problem' => 'has a `plugins:` key that is not a list'];
        }

        return [
            'rules' => array_values(array_filter($rules, is_array(...))),
            'problem' => null,
        ];
    }

    /**
     * The name a rule answers to.
     *
     * Resolved the same way `AbstractPluginBase::getName()` resolves it, so what this
     * prints is what the log will call it (#182).
     *
     * @param array<string, mixed> $rule
     *   A rule entry.
     *
     * @return string
     *   The declared name, or the plugin's short class name.
     */
    public static function nameOf(array $rule): string
    {
        $declared = $rule['metadata']['name'] ?? null;

        if (is_string($declared) && $declared !== '') {
            return $declared;
        }

        $class = is_string($rule['plugin'] ?? null) ? $rule['plugin'] : '';

        return substr((string) strrchr('\\' . $class, '\\'), 1);
    }

    /**
     * Where a rule of this name sits in the list.
     *
     * @param array<int, array<string, mixed>> $rules
     *   The managed rules.
     * @param string $name
     *   The name to find.
     *
     * @return int|null
     *   The index, or NULL when there is no such rule.
     */
    public static function indexOf(array $rules, string $name): ?int
    {
        foreach ($rules as $index => $rule) {
            if (self::nameOf($rule) === $name) {
                return $index;
            }
        }

        return null;
    }

    /**
     * Build a rule entry.
     *
     * @param string $plugin
     *   The plugin class, already resolved from any alias.
     * @param string $response
     *   `allow`, `block` or `challenge`.
     * @param array<int, string> $values
     *   The `config:` entries -- the addresses, paths or patterns.
     * @param string $name
     *   The rule's name.
     * @param int $weight
     *   Evaluation order; lower runs first.
     *
     * @return array<string, mixed>
     *   A rule entry in the `plugins:` format.
     */
    public static function rule(string $plugin, string $response, array $values, string $name, int $weight): array
    {
        return [
            'plugin' => $plugin,
            'response' => $response,
            'weight' => $weight,
            'enable' => true,
            'metadata' => ['name' => $name],
            'config' => array_values($values),
        ];
    }

    /**
     * Add a rule, refusing a name that is already taken.
     *
     * @param array<int, array<string, mixed>> $rules
     *   The managed rules.
     * @param array<string, mixed> $rule
     *   The rule to add.
     *
     * @return array{rules: array<int, array<string, mixed>>, problem: string|null}
     *   The new list, or the old one and the reason it did not change.
     */
    public static function add(array $rules, array $rule): array
    {
        $name = self::nameOf($rule);

        if (self::indexOf($rules, $name) !== null) {
            return [
                'rules' => $rules,
                'problem' => sprintf('a managed rule named "%s" already exists', $name),
            ];
        }

        $rules[] = $rule;

        return ['rules' => array_values($rules), 'problem' => null];
    }

    /**
     * Remove a rule by name.
     *
     * @param array<int, array<string, mixed>> $rules
     *   The managed rules.
     * @param string $name
     *   The rule to remove.
     *
     * @return array{rules: array<int, array<string, mixed>>, problem: string|null}
     *   The new list, or the old one and why it did not change.
     */
    public static function remove(array $rules, string $name): array
    {
        $index = self::indexOf($rules, $name);

        if ($index === null) {
            return ['rules' => $rules, 'problem' => sprintf('no managed rule is named "%s"', $name)];
        }

        unset($rules[$index]);

        return ['rules' => array_values($rules), 'problem' => null];
    }

    /**
     * Turn a rule on or off, leaving it in the file.
     *
     * Disabling rather than removing is the point of having it: an incident is not the
     * moment to reconstruct a rule from memory, and `enable: false` keeps the definition
     * where the next person can read it.
     *
     * @param array<int, array<string, mixed>> $rules
     *   The managed rules.
     * @param string $name
     *   The rule to change.
     * @param bool $enabled
     *   Whether it should evaluate.
     *
     * @return array{rules: array<int, array<string, mixed>>, problem: string|null}
     *   The new list, or the old one and why it did not change.
     */
    public static function setEnabled(array $rules, string $name, bool $enabled): array
    {
        $index = self::indexOf($rules, $name);

        if ($index === null) {
            return ['rules' => $rules, 'problem' => sprintf('no managed rule is named "%s"', $name)];
        }

        $rules[$index]['enable'] = $enabled;

        return ['rules' => array_values($rules), 'problem' => null];
    }

    /**
     * Render the managed file.
     *
     * Written line by line rather than dumped, for the same reason `StarterConfig` is: the
     * header has to survive, and it is the header that stops a later run treating a
     * hand-edited file as its own.
     *
     * @param array<int, array<string, mixed>> $rules
     *   The managed rules.
     *
     * @return string
     *   YAML.
     */
    public static function render(array $rules): string
    {
        $lines = [
            self::MARKER,
            '#',
            '# Add, remove and disable entries with `firewall-rule`, not an editor -- this',
            '# file is rewritten in full on every change and anything you add by hand goes',
            '# with it. Rules you want to keep belong in your own configuration, where they',
            '# keep their comments and this command will not touch them.',
            '#',
            '# Include it from your configuration:',
            '#',
            '#   configs:',
            '#     - "firewall-managed.yml"',
        ];

        if ($rules === []) {
            $lines[] = '';
            $lines[] = 'plugins: []';

            return implode("\n", $lines) . "\n";
        }

        $lines[] = '';
        $lines[] = rtrim(Yaml::dump(['plugins' => array_values($rules)], 6, 2));

        return implode("\n", $lines) . "\n";
    }

    /**
     * Write the managed file.
     *
     * @param string $path
     *   Where to write.
     * @param array<int, array<string, mixed>> $rules
     *   The managed rules.
     *
     * @return bool
     *   TRUE when it was written.
     */
    public static function write(string $path, array $rules): bool
    {
        $directory = dirname($path);

        if (!is_dir($directory) && !@mkdir($directory, 0755, true) && !is_dir($directory)) {
            return false;
        }

        return @file_put_contents($path, self::render($rules)) !== false;
    }

    /**
     * Every rule the firewall will evaluate, and which file it came from.
     *
     * The distinction is the useful part: a listing that did not draw it would invite
     * `remove` on a rule this cannot remove, and the refusal would arrive after the operator
     * had already decided it was gone.
     *
     * Matched on name *and* class, because a name is not unique across files -- and where
     * one is duplicated, both rows appear, which is worth seeing on its own.
     *
     * @param array<int, mixed> $configured
     *   The `plugins:` list out of the fully merged configuration.
     * @param array<int, array<string, mixed>> $managed
     *   The rules in the managed file.
     *
     * @return array<int, array{name: string, plugin: string, response: string, weight: int, enabled: bool, managed: bool}>
     *   One row per configured rule, in evaluation-agnostic declaration order.
     */
    public static function inventory(array $configured, array $managed): array
    {
        $owned = [];

        foreach ($managed as $rule) {
            $owned[self::nameOf($rule) . "\0" . (is_string($rule['plugin'] ?? null) ? $rule['plugin'] : '')] = true;
        }

        $rows = [];

        foreach ($configured as $rule) {
            if (!is_array($rule)) {
                continue;
            }

            $class = is_string($rule['plugin'] ?? null) ? $rule['plugin'] : '';
            $name = self::nameOf($rule);

            $rows[] = [
                'name' => $name,
                'plugin' => $class,
                'response' => is_string($rule['response'] ?? null) ? $rule['response'] : 'block',
                'weight' => is_numeric($rule['weight'] ?? null) ? (int) $rule['weight'] : 0,
                'enabled' => (bool) ($rule['enable'] ?? true),
                'managed' => isset($owned[$name . "\0" . $class]),
            ];
        }

        return $rows;
    }

    /**
     * Turn `--plugin=ip` into a class, and leave a class alone.
     *
     * @param string $plugin
     *   An alias or a fully-qualified class name.
     *
     * @return string|null
     *   The class, or NULL when it is neither.
     */
    public static function resolvePlugin(string $plugin): ?string
    {
        $alias = strtolower(trim($plugin));

        if (isset(self::ALIASES[$alias])) {
            return self::ALIASES[$alias];
        }

        $class = ltrim(trim($plugin), '\\');

        return class_exists($class) ? $class : null;
    }
}
