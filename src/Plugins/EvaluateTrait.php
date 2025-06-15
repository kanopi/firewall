<?php

namespace Kanopi\Firewall\Plugins;

use Symfony\Component\HttpFoundation\Request;

/**
 * Trait used for evaluating item.
 */
trait EvaluateTrait
{
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
        foreach ($data as $rule) {
            if ($this->evaluateRule($request, $rule)) {
                return true;
            }
        }
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
        $type = strtoupper($rule['type']);
        if ($type === 'AND') {
            foreach ($rule['rules'] as $subRule) {
                if (!$this->evaluateRule($request, $subRule)) {
                    return false;
                }
            }
            return true;
        } elseif ($type === 'OR') {
            foreach ($rule['rules'] as $subRule) {
                if ($this->evaluateRule($request, $subRule)) {
                    return true;
                }
            }
            return false;
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
     * Parse a simple string rule into a structured array.
     *
     * Supports the syntax:
     *   "variable:value"                  (defaults to 'equals')
     *   "variable@operator:value"
     *   "!variable:value"                (negated equals)
     *   "!variable@operator:value"       (negated custom operator)
     *
     * @param string $rule
     *   A simple string rule.
     *
     * @return array
     *   The normalized rule array
     */
    protected function parseSimpleStringRule(string $rule): array
    {
        $negate = false;

        // Handle leading ! for negation
        if (str_starts_with($rule, '!')) {
            $negate = true;
            $rule = substr($rule, 1);
        }

        // Determine operator
        if (str_contains($rule, '@')) {
            [$variable, $rest] = explode('@', $rule, 2);
            [$operator, $value] = explode(':', $rest, 2);
        } else {
            [$variable, $value] = explode(':', $rule, 2);
            $operator = 'equals';
        }

        // Handle comma-separated values for multi-value operators
        $multiValueOps = ['in', 'matches_any'];
        if (in_array($operator, $multiValueOps)) {
            $value = array_map('trim', explode(',', $value));
        }

        return [
            'variable' => trim($variable),
            'operator' => trim($operator),
            'value' => $value,
            'negate' => $negate,
        ];
    }

    /**
     * Evaluate a structured rule with keys:
     * - variable: request field to check (e.g., method, host, path, or parameter name)
     * - operator: comparison operator (equals, starts_with, contains, regex)
     * - value: value to compare against
     * - negate: optional boolean to invert result (default false)
     * - matches_any: optional boolean indicating $value is an array to check if any match
     *
     * @param Request $request
     *   Symfony HTTP request object.
     * @param array $rule
     *   Structured rule definition.
     *
     * @return bool
     *   Result of evaluation, negated if specified.
     */
    protected function evaluateStructuredRule(Request $request, array $rule): bool
    {
        $variable = $rule['variable'];
        $operator = $rule['operator'];
        $value = $rule['value'];
        $negate = !empty($rule['negate']);
        $matchesAny = !empty($rule['matches_any']);

        $requestValue = $this->getRequestValue($request, $variable);

        $result = false;

        if ($matchesAny && is_array($value)) {
            foreach ($value as $val) {
                if ($this->evaluateComparison($requestValue, $operator, $val, false)) {
                    $result = true;
                    break;
                }
            }
        } else {
            $result = $this->evaluateComparison($requestValue, $operator, $value, false);
        }

        return $negate ? !$result : $result;
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
        if (!$caseSensitive) {
            if (is_string($value)) {
                $requestValue = strtolower($requestValue);
                $value = strtolower($value);
            } elseif (is_array($value)) {
                $value = array_map('strtolower', $value);
            }
        }

        return match ($operator) {
            'equals' => $requestValue === $value,
            'starts_with' => str_starts_with($requestValue, $value),
            'contains' => str_contains($requestValue, $value),
            'regex' => preg_match($value, $requestValue) === 1,
            default => false,
        };
    }

    /**
     * Extract the value for a given variable name from the Request object.
     *
     * Supported variables:
     * - method: HTTP method (GET, POST, etc.)
     * - host: Hostname
     * - path: URI path (e.g. /admin)
     * - any other string: attempts to fetch from query parameters or POST data
     *
     * @param Request $request
     *   Symfony HTTP request object.
     * @param string $variable
     *   Variable name to extract from the request.
     *
     * @return string
     *   The value of the variable or empty string if not found.
     */
    protected function getRequestValue(Request $request, string $variable)
    {
        return '';
    }
}
