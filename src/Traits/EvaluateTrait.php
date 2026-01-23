<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Traits;

use Kanopi\Firewall\Logging\LoggingTrait;
use Symfony\Component\HttpFoundation\Request;

/**
 * Trait used for evaluating item.
 */
trait EvaluateTrait
{
    use LoggingTrait;

    /**
     * Split the query by a delimiter and confirm that no empty strings are provided.
     *
     * @param string $query
     *   Query string to split.
     * @param string $delimiter
     *   Delimiter value to split by.
     *
     * @return array
     *   Return the query broken down into an array.
     */
    protected function splitQuery(string $query, string $delimiter = '.'): array
    {
        return array_filter(explode($delimiter, trim($query)), fn ($item): bool => $item !== '');
    }

    /**
     * Evaluate the request and check if passes conditions.
     *
     * @param Request $request
     *   Request to pass through and evaluate.
     * @param array $data
     *   Data rules to check against.
     *
     * @return bool
     *   Return TRUE if passed FALSE if not.
     */
    protected function evaluateRequest(Request $request, array $data = []): bool
    {
        $this->getLogger()->debug('Starting request evaluation', $this->getContext($request, [
            'rules_count' => count($data),
        ]));

        foreach ($data as $index => $rule) {
            if ($this->evaluateRule($request, $rule)) {
                $this->getLogger()->debug('Rule matched', $this->getContext($request, [
                    'rule_index' => $index,
                    'rule' => is_string($rule) ? $rule : (is_array($rule) ? array_keys($rule) : 'complex'),
                ]));
                return true;
            }
        }

        $this->getLogger()->debug('No rules matched', $this->getContext($request, [
            'rules_evaluated' => count($data),
        ]));

        return false;
    }

    /**
     * Evaluate a single rule or group of rules.
     *
     * Supports:
     * - Simple string rule (e.g. "method:POST")
     * - Structured rule array (with variable, operator, value, negate, matches_any)
     * - Group of rules with 'type' = 'AND' or 'OR' and nested 'rules' array
     *
     * @param Request $request
     *   Symfony HTTP request object.
     * @param mixed $rule
     *   Rule definition: string or array.
     *
     * @return bool
     *   True if rule passes, false if it fails.
     */
    protected function evaluateRule(Request $request, mixed $rule): bool
    {
        if (is_string($rule)) {
            return $this->evaluateSimpleStringRule($request, $rule);
        }

        if (is_array($rule) && isset($rule['type']) && isset($rule['rules']) && is_array($rule['rules'])) {
            return $this->evaluateGroup($request, $rule);
        }

        if (is_array($rule) && isset($rule['variable'], $rule['operator'], $rule['value'])) {
            return $this->evaluateStructuredRule($request, $rule);
        }

        // Unknown rule format returns false for safety.
        return false;
    }

    /**
     * Evaluate the group of rules.
     *
     * @param Request $request
     *   Request to get information from.
     * @param mixed $rule
     *   Rule that is currently being evaluated.
     *
     * @return bool
     *   True if the rule passes, false if it fails.
     */
    protected function evaluateGroup(Request $request, mixed $rule): bool
    {
        $type = strtoupper((string) $rule['type']);
        $rulesCount = is_array($rule['rules']) ? count($rule['rules']) : 0;

        $this->getLogger()->debug('Evaluating rule group', $this->getContext($request, [
            'type' => $type,
            'rules_count' => $rulesCount,
        ]));

        if ($type === 'AND') {
            foreach ($rule['rules'] as $index => $subRule) {
                if (!$this->evaluateRule($request, $subRule)) {
                    $this->getLogger()->debug('AND group failed at rule', $this->getContext($request, [
                        'rule_index' => $index,
                    ]));
                    return false;
                }
            }

            return true;
        }

        if ($type === 'OR') {
            foreach ($rule['rules'] as $index => $subRule) {
                if ($this->evaluateRule($request, $subRule)) {
                    $this->getLogger()->debug('OR group succeeded at rule', $this->getContext($request, [
                        'rule_index' => $index,
                    ]));
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Evaluate a simple string rule of the format "variable:value".
     * This is a shorthand for an equals operator without negation.
     *
     * @param Request $request
     *   Symfony HTTP request object.
     * @param string $rule
     *   Simple string rule to parse and evaluate.
     *
     * @return bool
     *   True if request variable equals value, false otherwise.
     */
    protected function evaluateSimpleStringRule(Request $request, string $rule): bool
    {
        if (!str_contains($rule, ':')) {
            // Invalid format; return false to not block.
            return false;
        }

        $rule = $this->parseSimpleStringRule($rule);
        return $this->evaluateStructuredRule($request, $rule);
    }

    /**
     * Parse a simple string rule into a structured associative array.
     *
     * Supported syntaxes:
     *   - "variable:value"                         → defaults to 'equals'
     *   - "variable@operator:value"                → uses the given operator
     *   - "!variable:value"                        → negated equals
     *   - "!variable@operator:value"               → negated with operator
     *   - "variable > value" / "variable <= value" → shorthand numeric comparison
     *   - (optional) Append "#matches" for array matching behavior:
     *       - "#any", "#all", "#none", "#some"
     *         e.g., "tags@contains:eco,green#all"
     *
     * Operators supported include: equals, not_equals, contains, starts_with,
     * ends_with, regex, in, greater_than, less_than, greater_than_or_equal,
     * less_than_or_equal, etc.
     *
     * @param string $rule
     *   A string rule in shorthand notation.
     *
     * @return array{
     *     variable: string,
     *     operator: string,
     *     value: string|array,
     *     negate: bool,
     *     matches?: string|null
     * }
     *   The normalized rule array.
     */
    protected function parseSimpleStringRule(string $rule): array
    {
        $negate = false;

        // Handle leading ! for negation
        if (str_starts_with($rule, '!')) {
            $negate = true;
            $rule = substr($rule, 1);
        }

        $operator = 'equals'; // default
        $variable = '';
        $value = null;
        $matches = null;

        // Extract optional #matches mode from the end (e.g., #any, #all)
        // Only split on # if it's followed by a valid matches mode
        if (preg_match('/#(any|all|none|some)$/i', $rule, $matchesMatch)) {
            $matches = strtolower($matchesMatch[1]);
            $rule = substr($rule, 0, -strlen($matchesMatch[0]));
        }

        // Operator map for shorthand comparisons
        $operatorMap = [
            '>=' => 'greater_than_or_equal',
            '<=' => 'less_than_or_equal',
            '>'  => 'greater_than',
            '<'  => 'less_than',
        ];

        // Check for explicit @operator syntax
        if (str_contains($rule, '@')) {
            [$variable, $rest] = explode('@', $rule, 2);
            [$operator, $value] = explode(':', $rest, 2);
        } elseif (preg_match('/^([^><:]+)\s*(>=|<=|>|<)\s*([^><]+)$/', $rule, $matchesMatch)) {
            // Shorthand comparison like "score>=42"
            [, $variable, $symbol, $value] = $matchesMatch;
            $operator = $operatorMap[$symbol];
        } else {
            // Default fallback to equals
            [$variable, $value] = explode(':', $rule, 2);
            $operator = 'equals';
        }

        // Handle multi-value splitting
        // Note: 'regex' is NOT included because regex patterns can contain commas (e.g., {1,2})
        $multiValueOps = ['in', 'matches_any', 'equals', 'contains', 'starts_with', 'ends_with'];
        $value = trim($value);
        if (str_contains($value, ',') && in_array($operator, $multiValueOps, true)) {
            $value = array_map(trim(...), explode(',', $value));
        }

        return [
            'variable' => trim($variable),
            'operator' => trim($operator),
            'value' => $value,
            'negate' => $negate,
            'matches' => $matches,
        ];
    }

    /**
     * Evaluate a structured rule definition against the request.
     *
     * Each rule should be an associative array with the following keys:
     * - variable: string
     *     The request field or input to evaluate (e.g., method, host, query param).
     * - operator: string
     *     Comparison logic, such as:
     *       equals, not_equals, contains, starts_with, ends_with, regex, in,
     *       greater_than, less_than, greater_than_or_equal, less_than_or_equal
     * - value: string|array
     *     The value(s) to compare against.
     * - negate: bool (optional)
     *     Whether to negate the final result. Defaults to false.
     * - matches: string (optional)
     *     If 'value' is an array, defines how to evaluate:
     *       - "any" → pass if at least one match
     *       - "all" → pass only if all match
     *       - "none" → pass if none match
     *       - "some" → pass if some but not all match
     * - case_sensitive: bool (optional)
     *     Whether the comparison should be case-sensitive. Defaults to false.
     *
     * @param Request $request
     *   Symfony HTTP request object.
     * @param array $rule
     *   Structured rule definition.
     *
     * @return bool
     *   True if the rule passes; false otherwise (with optional negation applied).
     */
    protected function evaluateStructuredRule(Request $request, array $rule): bool
    {
        $variable = $rule['variable'];
        $operator = $rule['operator'];
        $value = $rule['value'];
        /** @phpstan-ignore-next-line */
        $negate = !empty($rule['negate']) && (bool) $rule['negate'];
        /** @phpstan-ignore-next-line */
        $matches = $rule['matches'] ?? false;
        /** @phpstan-ignore-next-line */
        $caseSensitive = !empty($rule['case_sensitive']) && $rule['case_sensitive'];

        // Operator adjusted to convert in operator to equals.
        if ($operator === 'in') {
            $operator = 'equals';
            $matches = $matches === false ? 'any' : $matches;
        }

        $requestValue = $this->getRequestValue($request, $variable);

        $result = false;

        if (is_array($value) && in_array($matches, ['any', 'all', 'none', 'some'], true)) {
            $evaluations = array_map(
                fn($val) => $this->evaluateComparison($requestValue, $operator, $val, $caseSensitive),
                $value
            );

            $total = count($evaluations);
            $passed = count(array_filter($evaluations));

            $result = match ($matches) {
                'any'   => $passed > 0,
                'all'   => $passed === $total,
                'none'  => $passed === 0,
                'some'  => $passed > 0 && $passed < $total,
            };
        } else {
            $result = $this->evaluateComparison($requestValue, $operator, $value, $caseSensitive);
        }

        return $negate ? !$result : $result;
    }

    /**
     * Validate and execute a regex pattern match safely.
     *
     * @param string $pattern
     *   The regex pattern to match.
     * @param string $subject
     *   The string to match against.
     *
     * @return bool
     *   True if pattern matches, false otherwise or if pattern is invalid.
     */
    protected function isValidRegexMatch(string $pattern, string $subject): bool
    {
        // Validate that pattern has delimiters
        // Check if pattern is at least 3 chars and starts/ends with same non-alphanumeric char
        if (strlen($pattern) < 3) {
            $this->getLogger()->warning('Invalid regex pattern: too short', [
                'pattern' => $pattern,
            ]);
            return false;
        }

        // Extract first character as potential delimiter
        $delimiter = $pattern[0];

        // Delimiter must be non-alphanumeric and not backslash or whitespace
        if (ctype_alnum($delimiter) || $delimiter === '\\' || ctype_space($delimiter)) {
            $this->getLogger()->warning('Invalid regex pattern: invalid delimiter', [
                'pattern' => $pattern,
                'delimiter' => $delimiter,
            ]);
            return false;
        }

        // Find matching closing delimiter (accounting for modifiers)
        $lastDelimiterPos = strrpos($pattern, $delimiter);
        if ($lastDelimiterPos === 0 || $lastDelimiterPos === false) {
            $this->getLogger()->warning('Invalid regex pattern: missing closing delimiter', [
                'pattern' => $pattern,
                'delimiter' => $delimiter,
            ]);
            return false;
        }

        // Attempt to match - suppress errors and check for validity
        $prevErrorReporting = error_reporting(0);
        $result = preg_match($pattern, $subject);
        $lastError = preg_last_error();
        error_reporting($prevErrorReporting);

        // Check for preg_match errors
        if ($lastError !== PREG_NO_ERROR) {
            $errorMessages = [
                PREG_INTERNAL_ERROR => 'Internal PCRE error',
                PREG_BACKTRACK_LIMIT_ERROR => 'Backtrack limit exhausted',
                PREG_RECURSION_LIMIT_ERROR => 'Recursion limit exhausted',
                PREG_BAD_UTF8_ERROR => 'Malformed UTF-8 data',
                PREG_BAD_UTF8_OFFSET_ERROR => 'Bad UTF-8 offset',
                PREG_JIT_STACKLIMIT_ERROR => 'JIT stack limit exhausted',
            ];

            $this->getLogger()->warning('Regex pattern match error', [
                'pattern' => $pattern,
                'error_code' => $lastError,
                'error_message' => $errorMessages[$lastError] ?? 'Unknown error',
            ]);
            return false;
        }

        // preg_match returns 1 for match, 0 for no match, false for error
        return $result === 1;
    }

    /**
     * Perform the actual comparison between the request value and rule value
     * based on the operator.
     *
     * Supported operators:
     * - equals: strict equality
     * - starts_with: string starts with value
     * - contains: string contains value
     * - regex: regex pattern match (preg_match)
     *
     * Case-insensitive by default.
     *
     * @param mixed $requestValue
     *   The value extracted from the Request object.
     * @param string $operator
     *   Operator name for comparison.
     * @param mixed $value
     *   Value to compare against (string or array).
     * @param bool $caseSensitive
     *   Whether comparison is case-sensitive (default false).
     *
     * @return bool
     *   Result of comparison.
     */
    protected function evaluateComparison(mixed $requestValue, string $operator, mixed $value, bool $caseSensitive = false): bool
    {
        if (!$caseSensitive && is_string($requestValue)) {
            $requestValue = strtolower($requestValue);
        }

        if (!$caseSensitive && is_string($value)) {
            $value = strtolower($value);
        } elseif (!$caseSensitive && is_array($value)) {
            $value = array_map(strtolower(...), $value);
        }

        $result = match ($operator) {
            'equals' => $requestValue === $value,
            'starts_with' => str_starts_with((string) $requestValue, (string) $value),
            'ends_with' => str_ends_with((string) $requestValue, (string) $value),
            'contains' => str_contains((string) $requestValue, (string) $value),
            'regex' => $this->isValidRegexMatch((string) $value, (string) $requestValue),
            'in' => is_array($value) && in_array($requestValue, $value, true),
            'greater_than' => is_numeric($requestValue) && is_numeric($value) && $requestValue > $value,
            'less_than' => is_numeric($requestValue) && is_numeric($value) && $requestValue < $value,
            'greater_than_or_equal' => is_numeric($requestValue) && is_numeric($value) && $requestValue >= $value,
            'less_than_or_equal' => is_numeric($requestValue) && is_numeric($value) && $requestValue <= $value,
            default => false,
        };

        $this->getLogger()->debug('Comparison matched', [
            'operator' => $operator,
            'request_value' => $requestValue,
            'case_sensitive' => $caseSensitive,
        ]);

        return $result;
    }

    /**
     * Extract the value for a given variable name from the Request object.
     *
     * @param Request $request
     *   Symfony HTTP request object.
     * @param string $variable
     *   Variable name to extract from the request.
     *
     * @return mixed
     *   The value of the variable or empty string if not found.
     */
    protected function getRequestValue(Request $request, string $variable): mixed
    {
        if (trim($variable) === '') {
            return null;
        }

        /** @phpstan-ignore-next-line */
        if (method_exists($this, 'getValue')) {
            return $this->getValue($request, $variable);
        }

        return null;
    }
}
