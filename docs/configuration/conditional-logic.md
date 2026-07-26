# Conditional Logic

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
