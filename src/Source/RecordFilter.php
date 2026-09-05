<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Source;

use Kanopi\Firewall\Traits\EvaluateTrait;
use Symfony\Component\HttpFoundation\Request;

/**
 * Applies a source's `where` rules to decoded records.
 *
 * This reuses the same conditional-logic engine plugins use against requests —
 * every operator, negation, and AND/OR group documented in
 * `docs/configuration/conditional-logic.md` works here unchanged. `EvaluateTrait`
 * never touches the request directly; it reaches values only through
 * `getValue()`, so overriding that to read from a record is all it takes.
 *
 * **`where` is AND, not OR.** A plugin's `config:` list is first-match-wins, so
 * listing two rules there widens what matches. A `where` list narrows instead:
 * a record is kept only when it satisfies every rule. Use an explicit
 * `{type: OR, rules: [...]}` group when you want the other behaviour.
 */
final class RecordFilter
{
    use EvaluateTrait;

    /**
     * The record currently being evaluated.
     *
     * @var array<array-key, mixed>|null
     */
    private ?array $record = null;

    /**
     * A request the evaluator never reads, satisfying its signature.
     */
    private ?Request $request = null;

    /**
     * Keep the records satisfying every rule.
     *
     * @param array<int, mixed> $records
     *   Decoded records.
     * @param array<int, mixed> $rules
     *   The source's `where` rules.
     *
     * @return array<int, mixed>
     *   The records that passed, reindexed.
     */
    public function filter(array $records, array $rules): array
    {
        if ($rules === []) {
            return array_values($records);
        }

        $kept = [];

        foreach ($records as $record) {
            if ($this->matches($record, $rules)) {
                $kept[] = $record;
            }
        }

        return $kept;
    }

    /**
     * Whether one record satisfies every rule.
     *
     * @param mixed $record
     *   The record under test.
     * @param array<int, mixed> $rules
     *   The source's `where` rules.
     *
     * @return bool
     *   True when every rule passed.
     */
    public function matches(mixed $record, array $rules): bool
    {
        // A scalar record exposes itself as "value", so a text list can still
        // be filtered: where: ["value@starts_with:10."].
        $this->record = is_array($record) ? $record : ['value' => $record];

        try {
            foreach ($rules as $rule) {
                if (!$this->evaluateRule($this->requestStub(), $rule)) {
                    return false;
                }
            }
        } finally {
            $this->record = null;
        }

        return true;
    }

    /**
     * Resolve a rule variable against the current record.
     *
     * Overrides the hook `EvaluateTrait` provides for exactly this purpose. The
     * request argument is unused — records are not requests.
     *
     * @param Request $request
     *   Ignored.
     * @param string $variable
     *   Dot-path into the record, e.g. `service` or `geo.country`.
     *
     * @return mixed
     *   The resolved value, or NULL when the record has no such field.
     */
    protected function getValue(Request $request, string $variable): mixed
    {
        if ($this->record === null) {
            return null;
        }

        $current = $this->record;

        foreach ($this->splitQuery($variable) as $segment) {
            if (!is_array($current) || !array_key_exists($segment, $current)) {
                return null;
            }

            $current = $current[$segment];
        }

        return $current;
    }

    /**
     * A shared empty request, built once.
     *
     * @return Request
     *   The stub passed through to the evaluator.
     */
    private function requestStub(): Request
    {
        return $this->request ??= new Request();
    }
}
