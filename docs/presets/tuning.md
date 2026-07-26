# Tuning & False Positives

## Understanding Regex Patterns

### Regex Delimiter Requirement

**IMPORTANT**: All regex patterns MUST include delimiters. The firewall validates regex patterns and will reject patterns without proper delimiters.

**Valid patterns:**
```yaml
- path@regex:#^/test\.php$#        # Using # delimiter
- path@regex:/test\.php$/          # Using / delimiter
- path@regex:@test\.php$@          # Using @ delimiter
- path@regex:~test\.php$~          # Using ~ delimiter
```

**Invalid patterns (will be rejected):**
```yaml
- path@regex:^/test\.php$          # Missing delimiters - INVALID
- path@regex:test\.php             # Missing delimiters - INVALID
```

### Choosing Delimiters

Choose a delimiter that doesn't appear in your pattern to avoid excessive escaping:
- Use `#` for paths with slashes: `#^/test/#`
- Use `/` for simple patterns: `/test/`
- Use `@` if pattern contains `/` and `#`: `@test@`

## Understanding the Generic PHP Block

The `malicious-urls.yml` preset includes this powerful catch-all rule:

```yaml
- path@regex:#(?<!index)\.php(\?.*)?$#
```

This blocks **any PHP file except index.php**. This is useful for:
- Preventing execution of uploaded malicious PHP files
- Blocking common backdoor file names
- Stopping unknown exploits

### When to Use This Rule

**Use when:**
- Running a CMS (WordPress, Drupal) where all requests go through index.php
- You have a front-controller pattern (Laravel, Symfony)
- Maximum security is required

**Don't use when:**
- You have legitimate PHP files at root level (contact.php, api.php)
- Your application doesn't use a front-controller pattern
- You need to access various PHP files directly

### Adapting the Generic PHP Block

If you need to allow specific PHP files, add an `allow` entry to your `plugins:` array:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: allow
    weight: -200
    enable: true
    config:
      - path:/contact.php
      - path:/api.php
      - path:/webhook.php
      - path@regex:#^/api/.*\.php$#  # Allow all files in /api/ directory
```

Or modify the preset to exclude specific patterns:

```yaml
# Allow PHP files in /api/ and /public/ directories
- type: AND
  rules:
    - path@regex:(?<!index)\.php(\?.*)?$
    - path@not_contains:/api/
    - path@not_contains:/public/
```

## Common False Positives

### Legitimate PHP Files Blocked

**Problem**: Your application has legitimate PHP files that are blocked.

**Solution**: Add an `allow` entry for those specific files:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: allow
    weight: -200
    enable: true
    config:
      - path:/my-file.php
```

### WordPress Plugin/Theme Files Blocked

**Problem**: WordPress plugins or themes have PHP files that are being blocked.

**Solution**: The preset already allows `/wp-content/plugins/` and `/wp-content/themes/`. If you're still having issues:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: allow
    weight: -200
    enable: true
    config:
      - path@starts_with:/wp-content/plugins/
      - path@starts_with:/wp-content/themes/
```

### API Endpoints Blocked

**Problem**: Your REST API endpoints are being blocked.

**Solution**: Add specific `allow` entries for API routes:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: allow
    weight: -200
    enable: true
    config:
      - path@starts_with:/api/
      - path@starts_with:/wp-json/
```
