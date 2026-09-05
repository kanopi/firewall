# Conditional Logic

Conditions are evaluated in two places. Plugins evaluate them against an incoming
**request**, which is what the rest of this page describes. A rule source's `where` key
evaluates the same syntax against a **record** from the list it is decoding — every
operator, negation, and group below works there unchanged, with one difference worth
knowing: a `where` list is AND, where a plugin's `config:` list is first-match-wins. See
[Rule Sources](sources.md#where-filtering-records).

The firewall supports three formats for defining conditions:

## 1. Simple Format

Quick and readable syntax for common conditions:

```yaml
# Basic equality
- "variable:value"

# With operator
- "variable@operator:value"

# Negation
- "!variable:value"
- "!variable@operator:value"

# Numeric comparisons
- "rate > 100"
- "client.version <= 10"

# Array matching
- "tags@contains:spam,malware#all"  # Must contain all
- "tags@contains:bot,crawler#any"   # Must contain at least one
```

### Supported Operators

- `equals` (default)
- `not_equals`
- `contains`
- `starts_with`
- `ends_with`
- `regex`
- `in`
- `greater_than` (>)
- `less_than` (<)
- `greater_than_or_equal` (>=)
- `less_than_or_equal` (<=)
- `exists`

`exists` is the one operator that takes **no value** — it asks only whether the request
carried the variable at all, so there is nothing after the operator name:

```yaml
- "query.cmd@exists"              # the parameter is present, whatever its value
- "!header.authorization@exists"  # the header is absent
- "query.flag@exists"             # `?flag=` counts as present
```

The shorthand comparisons carry no colon either, and are written with or without spaces:

```yaml
- "client.version <= 10"
- "query.n>=5"
```

## 2. Complex Format

Detailed configuration with full control:

```yaml
- variable: method
  operator: in
  value: [GET, POST]
  negate: false
  case_sensitive: true
  matches: any  # For array values: any, all, none, some
```

## 3. Grouped Format

Combine multiple conditions with logical operators:

```yaml
- type: AND
  rules:
    - "method:POST"
    - "path@starts_with:/api"
    - type: OR
      rules:
        - "header.authorization@exists"
        - "query.api_key@exists"
```

## When a rule does not match

A rule the evaluator cannot interpret matches nothing. For a `block` plugin that is
indistinguishable from a rule which is working and finding nothing, so the firewall says so
at construction rather than leaving you to guess:

```
firewall.WARNING: Firewall rule will not match anything
    {"plugin":"User Agent","rule":"automatd:true",
     "reason":"Unknown variable \"automatd\" — did you mean \"automated\"? This rule matches nothing."}
```

Three shapes account for nearly all of it.

**A misspelled or unknown variable.** Each plugin knows its own vocabulary, so the warning
names the near miss where there is one, and lists the alternatives where there is not.

**A rule that is not rule-shaped.** A bare string with no value, operator, or comparison —
`"nonsense"` — cannot be parsed into anything.

**The YAML map shape.** This is the one that catches people, because it is what YAML looks
like and it reads as obviously correct:

```yaml
config:
  - automated: true       # a map — NOT the string "automated:true"
```

That parses to `{"automated": true}`, which is neither a group nor a structured rule. The
intent is unambiguous, so it is **accepted** and read as `automated:true` — and reported,
so the config gets corrected rather than silently carried. Quote it:

```yaml
config:
  - "automated:true"
```

Checking runs once when the plugin is constructed, not per request, and only for plugins
whose `config` is a rule list. `IpAddress` takes bare addresses and `VulnerabilityScore` a
nested scoring tree, so neither is checked.
