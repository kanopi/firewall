<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

/**
 * Checks a plugin's rule list for rules that cannot do anything.
 *
 * A rule the evaluator cannot interpret returns FALSE, which for a block plugin
 * is indistinguishable from a rule that is working and finding nothing. That is
 * how a typo, a wrong variable name, or the wrong YAML shape turns into hours
 * of wondering why traffic is not being stopped (#165).
 *
 * Two shapes account for nearly all of it. A misspelled variable —
 * `automatd:true` — and the natural-looking YAML map:
 *
 * ```yaml
 * config:
 *   - automated: true      # a map, not the string "automated:true"
 * ```
 *
 * The second is what YAML *looks* like, reads as obviously correct, and parses
 * to something `evaluateRule()` does not recognise. It is accepted here rather
 * than merely reported, because the intent is unambiguous — but it is reported
 * too, so the config gets fixed rather than silently carried.
 *
 * Checks run once, at plugin construction. A plugin opts in by returning its
 * vocabulary from `AbstractPluginBase::knownRuleVariables()`; one that returns
 * an empty list — `IpAddress`, whose config is bare addresses rather than
 * rules — is skipped entirely.
 */
final class RuleDiagnostics
{
    /**
     * Maximum edit distance for a "did you mean" suggestion.
     */
    private const SUGGESTION_DISTANCE = 3;

    /**
     * Inspect a rule list, repairing what is unambiguous and reporting the rest.
     *
     * @param array<array-key, mixed> $rules
     *   The plugin's assembled rule list.
     * @param array<int, string> $known
     *   Variable roots the plugin can resolve. Empty disables all checking.
     *
     * @return array{rules: array<array-key, mixed>, issues: array<int, array{rule: string, reason: string}>}
     *   The rule list to use, and anything worth telling the operator about.
     */
    public static function inspect(array $rules, array $known): array
    {
        if ($known === []) {
            return ['rules' => $rules, 'issues' => []];
        }

        $issues = [];
        $checked = [];

        foreach ($rules as $key => $rule) {
            $checked[$key] = self::inspectRule($rule, $known, $issues);
        }

        return ['rules' => $checked, 'issues' => $issues];
    }

    /**
     * Inspect one rule, returning what should replace it.
     *
     * @param mixed $rule
     *   The rule as configured.
     * @param array<int, string> $known
     *   Variable roots the plugin can resolve.
     * @param array<int, array{rule: string, reason: string}> $issues
     *   Collected issues, appended to.
     *
     * @return mixed
     *   The rule, repaired where that was unambiguous.
     */
    private static function inspectRule(mixed $rule, array $known, array &$issues): mixed
    {
        if (is_string($rule)) {
            self::inspectStringRule($rule, $known, $issues);

            return $rule;
        }

        if (!is_array($rule)) {
            $issues[] = [
                'rule' => get_debug_type($rule),
                'reason' => sprintf('A rule must be a string or a map, %s given.', get_debug_type($rule)),
            ];

            return $rule;
        }

        // A group: recurse, so a bad rule nested three levels down is still named.
        if (isset($rule['type'], $rule['rules']) && is_array($rule['rules'])) {
            foreach ($rule['rules'] as $index => $nested) {
                $rule['rules'][$index] = self::inspectRule($nested, $known, $issues);
            }

            return $rule;
        }

        // A structured rule.
        if (isset($rule['variable'], $rule['operator']) && array_key_exists('value', $rule)) {
            if (is_string($rule['variable'])) {
                self::checkVariable($rule['variable'], $rule['variable'], $known, $issues);
            }

            return $rule;
        }

        return self::repairScalarMap($rule, $known, $issues);
    }

    /**
     * Handle the `- variable: value` shape.
     *
     * @param array<array-key, mixed> $rule
     *   A map that is neither a group nor a structured rule.
     * @param array<int, string> $known
     *   Variable roots the plugin can resolve.
     * @param array<int, array{rule: string, reason: string}> $issues
     *   Collected issues, appended to.
     *
     * @return mixed
     *   An equivalent string rule when the intent is unambiguous, else the
     *   rule unchanged.
     */
    private static function repairScalarMap(array $rule, array $known, array &$issues): mixed
    {
        if (count($rule) !== 1) {
            $issues[] = [
                'rule' => json_encode($rule) ?: 'map',
                'reason' => 'Not a recognisable rule: expected a string, an AND/OR group, '
                    . 'or a structured rule with variable, operator and value.',
            ];

            return $rule;
        }

        $variable = (string) array_key_first($rule);
        $value = reset($rule);

        if (is_array($value) || is_object($value)) {
            $issues[] = [
                'rule' => $variable,
                'reason' => 'Not a recognisable rule: expected a string, an AND/OR group, '
                    . 'or a structured rule with variable, operator and value.',
            ];

            return $rule;
        }

        $rendered = $variable . ':' . self::stringify($value);

        if (!self::isKnown($variable, $known)) {
            $issues[] = [
                'rule' => $variable,
                'reason' => self::unknownVariableReason($variable, $known),
            ];

            return $rule;
        }

        $issues[] = [
            'rule' => $variable,
            'reason' => sprintf(
                'Written as a YAML map, which the evaluator does not recognise as a rule. '
                . 'Reading it as "%s"; quote it in the config to make that explicit.',
                $rendered
            ),
        ];

        return $rendered;
    }

    /**
     * Check a string rule's shape and variable.
     *
     * @param string $rule
     *   The rule.
     * @param array<int, string> $known
     *   Variable roots the plugin can resolve.
     * @param array<int, array{rule: string, reason: string}> $issues
     *   Collected issues, appended to.
     */
    private static function inspectStringRule(string $rule, array $known, array &$issues): void
    {
        $trimmed = ltrim(trim($rule), '!');

        if ($trimmed === '') {
            $issues[] = ['rule' => $rule, 'reason' => 'Empty rule.'];

            return;
        }

        $hasValue = str_contains($trimmed, ':');
        $hasOperator = str_contains($trimmed, '@');
        $hasComparison = preg_match('/[<>]/', $trimmed) === 1;

        if (!$hasValue && !$hasOperator && !$hasComparison) {
            $issues[] = [
                'rule' => $rule,
                'reason' => 'Not a recognisable rule: expected "variable:value", '
                    . '"variable@operator:value", or a comparison such as "variable >= 5".',
            ];

            return;
        }

        self::checkVariable($rule, $trimmed, $known, $issues);
    }

    /**
     * Check that a rule's variable is one the plugin resolves.
     *
     * @param string $rule
     *   The rule as written, for the message.
     * @param string $expression
     *   The rule with any negation stripped.
     * @param array<int, string> $known
     *   Variable roots the plugin can resolve.
     * @param array<int, array{rule: string, reason: string}> $issues
     *   Collected issues, appended to.
     */
    private static function checkVariable(string $rule, string $expression, array $known, array &$issues): void
    {
        $root = self::rootOf($expression);

        if ($root === '' || self::isKnown($root, $known)) {
            return;
        }

        $issues[] = ['rule' => $rule, 'reason' => self::unknownVariableReason($root, $known)];
    }

    /**
     * The variable root a rule addresses.
     *
     * @param string $expression
     *   A rule with negation already stripped.
     *
     * @return string
     *   The root, before any dot path, operator, or value.
     */
    private static function rootOf(string $expression): string
    {
        $root = preg_split('/[.@:<>]/', $expression, 2)[0] ?? '';

        return trim($root);
    }

    /**
     * Whether a variable root is one the plugin resolves.
     *
     * @param string $root
     *   The root to check.
     * @param array<int, string> $known
     *   Variable roots the plugin can resolve.
     *
     * @return bool
     *   True when recognised.
     */
    private static function isKnown(string $root, array $known): bool
    {
        foreach ($known as $candidate) {
            if (strcasecmp($root, $candidate) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Explain an unrecognised variable, with a suggestion when one is close.
     *
     * @param string $root
     *   The variable that was not recognised.
     * @param array<int, string> $known
     *   Variable roots the plugin can resolve.
     *
     * @return string
     *   Operator-readable reason.
     */
    private static function unknownVariableReason(string $root, array $known): string
    {
        $suggestion = self::closest($root, $known);

        if ($suggestion !== null) {
            return sprintf(
                'Unknown variable "%s" — did you mean "%s"? This rule matches nothing.',
                $root,
                $suggestion
            );
        }

        return sprintf(
            'Unknown variable "%s". This rule matches nothing. Known variables: %s.',
            $root,
            implode(', ', $known)
        );
    }

    /**
     * The nearest known variable, when one is near enough to be worth naming.
     *
     * @param string $root
     *   The variable that was not recognised.
     * @param array<int, string> $known
     *   Variable roots the plugin can resolve.
     *
     * @return string|null
     *   The closest candidate, or NULL when nothing is close.
     */
    private static function closest(string $root, array $known): ?string
    {
        $best = null;
        $bestDistance = self::SUGGESTION_DISTANCE + 1;

        foreach ($known as $candidate) {
            $distance = levenshtein(strtolower($root), strtolower($candidate));

            if ($distance < $bestDistance) {
                $bestDistance = $distance;
                $best = $candidate;
            }
        }

        return $bestDistance <= self::SUGGESTION_DISTANCE ? $best : null;
    }

    /**
     * Render a scalar the way the rule syntax expects it.
     *
     * @param mixed $value
     *   A scalar from the config.
     *
     * @return string
     *   Its rule-syntax form.
     */
    private static function stringify(mixed $value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        return $value === null ? '' : (string) $value;
    }
}
