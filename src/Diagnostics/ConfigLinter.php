<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Diagnostics;

use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\PluginConfigNormalizer;
use Kanopi\Firewall\Utility\RuleDiagnostics;

/**
 * Read a configuration and report what it says that it does not mean.
 *
 * The static half of the pair. `Doctor` asks what is wrong with this *environment* --
 * whether the database answers, whether the GeoIP file is there. This asks what is wrong
 * with the *rules*, and the answer does not depend on where it runs: a rule that cannot
 * match anything cannot match anything on any machine (#216).
 *
 * ## Why this exists when startup already warns
 *
 * #173 made an unmatchable rule loud -- but loud *at startup*, in a log, on a running site.
 * An operator editing a config wants the answer before the deploy, and a CI job wants it
 * without standing up a firewall. Everything here runs against the configuration alone.
 *
 * ## What it deliberately does not do
 *
 * It does not decide whether one rule's matches are a subset of another's. "This block rule
 * is shadowed by that allow rule" is only answerable by understanding what each rule
 * matches, which is specific to every plugin and, done approximately, produces confident
 * warnings about rules that are fine. The one shadowing case reported here is the
 * unambiguous one: an allow rule that matches every address, which nothing after it can be
 * reached past.
 */
class ConfigLinter
{
    /**
     * Rules that match every possible client, by plugin class and rule.
     *
     * Deliberately a short, literal list rather than anything clever. Each entry is a rule
     * whose match set is provably everything, so a rule ordered after it is unreachable --
     * no interpretation required, and no way to be wrong about it.
     *
     * @var array<string, array<int, string>>
     */
    private const CATCH_ALL_RULES = [
        \Kanopi\Firewall\Plugins\IpAddress::class => ['0.0.0.0/0', '::/0', '*'],
        \Kanopi\Firewall\Plugins\Url::class => ['path@regex:/.*/', 'path@contains:'],
    ];

    /**
     * @param array<int, string|array<string, mixed>|null> $configs
     *   Configuration sources, as `Firewall::create()` takes them.
     */
    public function __construct(private readonly array $configs)
    {
    }

    /**
     * Inspect the configuration.
     *
     * @return array<int, Diagnosis>
     *   Every finding. Empty findings of `ok` are included, so a clean config
     *   still reports what was looked at.
     */
    public function run(): array
    {
        Config::clearLoadErrors();
        $config = Config::load($this->configs);

        $findings = [];

        foreach (Config::getLoadErrors() as $error) {
            $findings[] = Diagnosis::error(
                'Config file failed to load: ' . $error['file'],
                $error['message'],
                'configuration/loading-and-includes.md'
            );
        }

        $plugins = $this->declaredPlugins($config);

        if ($plugins === []) {
            $findings[] = Diagnosis::warning(
                'No rules are configured',
                'A firewall with no rules allows everything.',
                'configuration/index.md'
            );

            return $findings;
        }

        foreach ($this->checkNames($plugins) as $diagnosi) {
            $findings[] = $diagnosi;
        }

        foreach ($this->checkEmptyRuleLists($plugins) as $diagnosi) {
            $findings[] = $diagnosi;
        }

        foreach ($this->checkShadowing($config) as $diagnosi) {
            $findings[] = $diagnosi;
        }

        foreach ($this->checkRules($plugins) as $diagnosi) {
            $findings[] = $diagnosi;
        }

        foreach ($this->checkLiteralWildcards($plugins) as $diagnosi) {
            $findings[] = $diagnosi;
        }

        if (array_filter($findings, static fn(Diagnosis $diagnosis): bool => $diagnosis->status !== Diagnosis::OK) === []) {
            $findings[] = Diagnosis::ok(
                sprintf('%d rule%s inspected', count($plugins), count($plugins) === 1 ? '' : 's'),
                'Nothing that cannot match, nothing unreachable, no duplicate names'
            );
        }

        return $findings;
    }

    /**
     * Every plugin entry the configuration declares, as maps.
     *
     * @param array<string, mixed> $config
     *   The loaded configuration.
     *
     * @return array<int, array<string, mixed>>
     *   Plugin entries.
     */
    private function declaredPlugins(array $config): array
    {
        $declared = is_array($config['plugins'] ?? null) ? $config['plugins'] : [];
        $plugins = [];

        foreach ($declared as $entry) {
            if (is_array($entry)) {
                $plugins[] = $entry;
            }
        }

        return $plugins;
    }

    /**
     * The name a rule will be known by, resolved the way `getName()` resolves it.
     *
     * @param array<string, mixed> $plugin
     *   A plugin entry.
     *
     * @return string
     *   Its name.
     */
    private function nameOf(array $plugin): string
    {
        $metadata = is_array($plugin['metadata'] ?? null) ? $plugin['metadata'] : [];
        $declared = $metadata['name'] ?? null;

        if (is_string($declared) && $declared !== '') {
            return $declared;
        }

        $class = is_string($plugin['plugin'] ?? null) ? $plugin['plugin'] : '(no class)';

        return substr((string) strrchr('\\' . $class, '\\'), 1);
    }

    /**
     * Two rules sharing a name.
     *
     * Nothing the firewall *does* depends on the name, so this is a warning --
     * but everything said about it afterwards does, and a log line naming a
     * rule that could be either of two is worth less than one that cannot.
     *
     * @param array<int, array<string, mixed>> $plugins
     *   Plugin entries.
     *
     * @return array<int, Diagnosis>
     *   Findings.
     */
    private function checkNames(array $plugins): array
    {
        $seen = [];

        foreach ($plugins as $plugin) {
            $metadata = is_array($plugin['metadata'] ?? null) ? $plugin['metadata'] : [];
            $declared = $metadata['name'] ?? null;
            // Only names somebody chose. Two IpAddress rules with no name both
            // resolve to "IpAddress", which is the default and is #182's
            // problem to solve, not a mistake in this configuration.
            if (!is_string($declared)) {
                continue;
            }

            if ($declared === '') {
                continue;
            }

            $seen[$declared] = ($seen[$declared] ?? 0) + 1;
        }

        $findings = [];

        foreach ($seen as $name => $count) {
            if ($count > 1) {
                $findings[] = Diagnosis::warning(
                    sprintf('Two rules are named "%s"', $name),
                    'A log line naming this rule will not say which one fired.',
                    'plugins/index.md'
                );
            }
        }

        return $findings;
    }

    /**
     * A rule list with nothing in it.
     *
     * @param array<int, array<string, mixed>> $plugins
     *   Plugin entries.
     *
     * @return array<int, Diagnosis>
     *   Findings.
     */
    private function checkEmptyRuleLists(array $plugins): array
    {
        $findings = [];

        foreach ($plugins as $plugin) {
            if (!($plugin['enable'] ?? true)) {
                continue;
            }

            $rules = $plugin['config'] ?? null;
            $metadata = is_array($plugin['metadata'] ?? null) ? $plugin['metadata'] : [];
            // A plugin drawing its rules from a source has an empty `config:`
            // legitimately, and one that takes no rules at all -- a CRS engine,
            // a reputation lookup -- never had any.
            if (!is_array($rules)) {
                continue;
            }

            if ($rules !== []) {
                continue;
            }

            if (isset($metadata['sources'])) {
                continue;
            }

            $findings[] = Diagnosis::warning(
                sprintf('Rule "%s" has an empty rule list', $this->nameOf($plugin)),
                'It declares `config: []` and no `metadata.sources`, so it can never match.',
                'configuration/index.md'
            );
        }

        return $findings;
    }

    /**
     * Rules ordered after an allow rule that matches everything.
     *
     * @param array<string, mixed> $config
     *   The loaded configuration.
     *
     * @return array<int, Diagnosis>
     *   Findings.
     */
    private function checkShadowing(array $config): array
    {
        // Partitioned and sorted the way the firewall will consult them, so
        // "after" here means what it means at runtime rather than what the file
        // happens to look like.
        $partitioned = PluginConfigNormalizer::partitionAndSort(
            is_array($config['plugins'] ?? null) ? $config['plugins'] : []
        );

        $catchAll = null;

        foreach ($partitioned['allow'] as $plugin) {
            if ($catchAll === null && $this->matchesEverything($plugin)) {
                $catchAll = $plugin;
            }
        }

        if ($catchAll === null) {
            return [];
        }

        $shadowed = count($partitioned['block']) + count($partitioned['challenge']);

        if ($shadowed === 0) {
            return [];
        }

        return [Diagnosis::error(
            sprintf('Rule "%s" allows every request', $this->nameOf($catchAll)),
            sprintf(
                '%d block or challenge rule%s can never be reached, because allow rules are '
                . 'consulted first and this one matches everything.',
                $shadowed,
                $shadowed === 1 ? '' : 's'
            ),
            'configuration/index.md'
        )];
    }

    /**
     * Whether a plugin entry matches every possible request.
     *
     * @param array<string, mixed> $plugin
     *   A plugin entry.
     *
     * @return bool
     *   TRUE when one of its rules is a known catch-all.
     */
    private function matchesEverything(array $plugin): bool
    {
        $class = is_string($plugin['plugin'] ?? null) ? ltrim($plugin['plugin'], '\\') : '';
        $catchAlls = self::CATCH_ALL_RULES[$class] ?? [];

        if ($catchAlls === []) {
            return false;
        }

        $rules = is_array($plugin['config'] ?? null) ? $plugin['config'] : [];

        foreach ($rules as $rule) {
            if (is_string($rule) && in_array($rule, $catchAlls, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * A wildcard written into a rule that matches literally.
     *
     * `variable:value` is an exact comparison. `path:/wp-admin/*` therefore
     * matches the literal path `/wp-admin/*` and nothing else -- it reads like
     * a glob, it is not one, and it fails by quietly never matching.
     *
     * Found by writing it myself while testing this command, which is the best
     * argument for the check existing: nothing about the rule looks wrong, the
     * variable is valid, and #173's inspection passes it because `path` is a
     * variable it knows.
     *
     * A warning rather than an error, and only for `*`. Matching a literal
     * asterisk is conceivable, so this says what it suspects rather than
     * refusing the config over it -- and only errors fail the command.
     *
     * @param array<int, array<string, mixed>> $plugins
     *   Plugin entries.
     *
     * @return array<int, Diagnosis>
     *   Findings.
     */
    private function checkLiteralWildcards(array $plugins): array
    {
        $findings = [];

        foreach ($plugins as $plugin) {
            $rules = is_array($plugin['config'] ?? null) ? $plugin['config'] : [];

            foreach ($rules as $rule) {
                if (!is_string($rule)) {
                    continue;
                }

                if (!str_contains($rule, ':')) {
                    continue;
                }

                [$variable, $value] = explode(':', $rule, 2);
                // An `@operator` is the pattern-matching form and means what it
                // says, so `path@contains:*` is somebody's business.
                if (str_contains($variable, '@')) {
                    continue;
                }

                if (!str_contains($value, '*')) {
                    continue;
                }

                $findings[] = Diagnosis::warning(
                    sprintf('Rule "%s" compares exactly against a value containing *', $this->nameOf($plugin)),
                    sprintf(
                        '%s — `%s:` is an exact match, so this matches the literal text and never a pattern. '
                        . 'Did you mean %s@starts_with: or %s@regex:?',
                        json_encode($rule, JSON_UNESCAPED_SLASHES),
                        $variable,
                        $variable,
                        $variable
                    ),
                    'configuration/conditional-logic.md'
                );
            }
        }

        return $findings;
    }

    /**
     * Rules that cannot match anything.    /**
     * Rules that cannot match anything.
     *
     * Constructing a plugin is what inspects its rules (#173), and the report
     * goes to the log. So this constructs each one against a handler of its own
     * and reads what came out, rather than reimplementing the inspection --
     * which would drift from the one that actually runs.
     *
     * @param array<int, array<string, mixed>> $plugins
     *   Plugin entries.
     *
     * @return array<int, Diagnosis>
     *   Findings.
     */
    private function checkRules(array $plugins): array
    {
        $findings = [];

        foreach ($plugins as $plugin) {
            $class = is_string($plugin['plugin'] ?? null) ? ltrim($plugin['plugin'], '\\') : '';
            if ($class === '') {
                continue;
            }

            if (!class_exists($class)) {
                continue;
            }

            if (!in_array(PluginInterface::class, (array) class_implements($class), true)) {
                continue;
            }

            $rules = is_array($plugin['config'] ?? null) ? $plugin['config'] : [];
            if ($rules === []) {
                continue;
            }

            if (!array_is_list($rules)) {
                continue;
            }

            $known = $this->knownVariablesOf($class);

            if ($known === []) {
                continue;
            }

            foreach (RuleDiagnostics::inspect($rules, $known)['issues'] as $issue) {
                $findings[] = Diagnosis::error(
                    sprintf('Rule "%s" contains something that cannot match', $this->nameOf($plugin)),
                    sprintf(
                        '%s — %s',
                        json_encode($issue['rule'], JSON_UNESCAPED_SLASHES),
                        $issue['reason']
                    ),
                    'configuration/conditional-logic.md'
                );
            }
        }

        return $findings;
    }

    /**
     * The rule variables a plugin class understands, without building one.
     *
     * `knownRuleVariables()` is an instance method, and the obvious way to reach
     * it is to construct the plugin -- which is what this did, and what made
     * linting anything but static.
     *
     * **Constructing a plugin touches the environment.** A rate limit rule
     * builds its storage backend, which opens a connection and creates its
     * table; a rule with `metadata.sources` fetches them. So `--lint` on a
     * production config, run from a laptop, created tables in that production
     * database and pulled every remote list -- from a command documented as
     * saying nothing about the environment, and reasonably expected to be safe
     * to run against anything.
     *
     * `newInstanceWithoutConstructor()` gives an object to call the method on
     * without any of that. Every implementation in this package returns a
     * constant list, so there is no constructor state to miss -- and a plugin
     * that does need some returns nothing rather than misreporting, which
     * leaves its rules uninspected instead of wrongly condemned.
     *
     * @param class-string $class
     *   The plugin class.
     *
     * @return array<int, string>
     *   Variables it understands, or empty when they cannot be read.
     */
    private function knownVariablesOf(string $class): array
    {
        try {
            $instance = (new \ReflectionClass($class))->newInstanceWithoutConstructor();
            $reflectionMethod = new \ReflectionMethod($instance, 'knownRuleVariables');

            $known = $reflectionMethod->invoke($instance);
        } catch (\Throwable) {
            return [];
        }

        if (!is_array($known)) {
            return [];
        }

        return array_values(array_filter($known, is_string(...)));
    }
}
