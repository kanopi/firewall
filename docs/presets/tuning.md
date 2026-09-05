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

## Drupal false positives

**`/user/<id>` versus `/user/login`.** `drupal-admin.yml` names the authentication routes
individually rather than blocking the `/user` prefix, because public user profiles live at
`/user/123` on a great many sites. If yours has no public profiles, blocking
`path@starts_with:/user` is tighter — but check first.

**Language prefixes.** A multilingual site serves `/es/user/login` as well as
`/user/login`. The preset covers a two-letter code with an optional region
(`/pt-br/user/login`); a site using a longer or non-standard prefix needs its own rule.

**Drupal 7 query routing is deliberately absent.** `?q=admin` and `?q=user/login` are not
blocked, for two reasons found by testing rather than reasoning. `q` is the parameter a
great many search forms use, so `?q=admin` is a visitor searching for the word "admin" at
least as often as it is someone reaching the back end. And the rule would not work anyway:
the separator arrives percent-encoded (`q=admin%2Fcontent`), so a `q=admin/` pattern never
matches. If you need it, match the encoded form and accept the search false positive.

**`/core/` is not blocked wholesale.** Core serves its CSS and JavaScript from
`/core/misc/` and `/core/assets/`, so only named files and the `scripts`, `tests`, and
module-test directories are blocked. Adding `path@starts_with:/core/` will unstyle the
site.

**Uploaded media stays reachable.** Only *executable* extensions under `/sites/*/files/`
are blocked. Blocking the directory outright takes every image and document with it.

**`/admin` prefix matching.** `path@starts_with:/admin/` plus an exact `path:/admin` is
deliberate — it means `/administrative-services` and `/news/admin-appointed` keep working,
which a bare `path@contains:/admin` would break.
## Search crawler allow: what to check

**The scope is the safety.** `search-bots.yml` is only defensible because the allow does
not cover the admin surface. If you copy it and drop the path exclusion, you have published
a firewall bypass that anyone can use with `curl -A Googlebot`.

**Add your own admin path.** The exclusion knows about WordPress and Drupal. A custom admin
route, a headless CMS endpoint, or an API you do not want crawled needs adding to the same
rule.

**Watch the `-Extended` names.** `Applebot` and `Applebot-Extended` are different crawlers
that mean opposite things, and one contains the other as a substring. The preset excludes
`-Extended` explicitly for this reason. If you add a crawler to the list by hand, check
whether its name is a prefix of something you do not want to allow.

**Google-Extended is not Googlebot.** Blocking `Googlebot` deindexes the site; blocking
`Google-Extended` only opts out of training collection. They are on different lists here
on purpose.
