# CRS (OWASP Core Rule Set) Plugin

**Namespace**: `\Kanopi\Firewall\Plugins\Crs`

Evaluates each request against the [OWASP Core Rule Set](https://coreruleset.org/) — the same ruleset that powers ModSecurity, Coraza, and most commercial WAFs. Detects SQL injection, XSS, LFI, RFI, RCE, PHP / Java injection, session fixation, protocol-level attacks, and known scanner traffic. Backed by the [`kanopi/crs-engine`](https://packagist.org/packages/kanopi/crs-engine) composer package, which parses CRS source files into a runtime-optimised cache and refreshes weekly from upstream.

## Key Features

- **Real CRS rules**: Parses the upstream `REQUEST-*.conf` files directly — no hand-translation, no divergence from CRS behavior.
- **Paranoia levels (1-4)**: Trade detection coverage against false-positive rate the same way CRS deployments tune ModSecurity.
- **Per-rule / per-category disable**: Silence known false positives without touching upstream rule files.
- **Monitor vs block modes**: Roll the plugin out in monitor mode first; the firewall logs what would have been blocked without rejecting traffic.
- **In-process rule cache**: ~3-4 ms per request once warm (FPM worker steady state). Zero extension dependencies — no APCu / OPcache preload required.
- **Auto-refreshed rules**: The `crs-engine` package CI fetches new CRS releases weekly and opens a reviewable PR; `composer update` pulls the latest curated bump.

## Configuration Example

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Crs"
    response: block
    # CRS work is non-trivial — run cheap IP / UA / ASN filters first.
    weight: 50
    enable: true
    config:
      # Paranoia level 1-4. 1 is the recommended starting point.
      paranoia: 1
      # block (default) or monitor (log without blocking)
      mode: block
      # HTTP status returned for blocked requests
      block_status: 403
      # How long the firewall remembers the offending IP (seconds)
      block_duration: 3600
      # Known false-positives — disable by rule ID
      disabled_rules: [942130]
      # Or by category. Available categories:
      #   sqli, xss, lfi, rfi, rce, php, java, session_fixation,
      #   protocol_attack, protocol_enforcement, method_enforcement,
      #   scanner, multipart, generic, response_leak_sql,
      #   response_leak_java, response_leak_php, response_leak_iis,
      #   web_shell, correlation
      disabled_categories: []
      # Override anomaly-score thresholds
      anomaly_thresholds:
        critical: 5
        error: 4
        warning: 3
        notice: 2
      # Custom rule cache location — defaults to vendor/kanopi/crs-engine/rules
      # rules_path: /etc/firewall/crs-rules
```

## Coverage

Currently the plugin handles request-side evaluation: every CRS rule in `REQUEST-*.conf` runs against the incoming request. Response-side rules (RESPONSE-* files — SQL error / stack-trace / PHP warning leakage detection) are tracked under issue #69 and will land as a follow-up.

The four CRS rules that rely on `libinjection` (`@detectSQLi` / `@detectXSS` — rules 941100, 941180, 942100, 942500) are parsed but not evaluated; the engine logs them as `parser warnings` in `vendor/kanopi/crs-engine/rules/manifest.json`. CRS's regex-based SQLi/XSS rules in the same files run normally and provide the bulk of the detection.

## What gets logged

Blocked requests log at `info` level with full context:
- `rule_id` — the CRS rule that fired the block
- `total_score` — accumulated anomaly score
- `scores` — per-category breakdown (sqli, xss, lfi, etc.)
- `matched_rule` — the rule's human-readable message
- `matched_data` — the substring of the request that matched

Non-blocking matches (monitor mode, or rules whose action is `pass`) log at `debug` level.

## Inspecting the verdict programmatically

`evaluate()` returns a plain bool, which is all the firewall needs to make a decision. When you want the full CRS verdict — to surface in an admin UI, forward to a SIEM, or drive your own routing — `Crs::getLastVerdict()` returns the `Kanopi\Crs\CrsVerdict` from the most recent evaluation, or `null` if the plugin has not evaluated anything yet.

The plugin instances the firewall builds internally are not exposed, so use this by driving the plugin directly, alongside (or instead of) the firewall:

```php
use Kanopi\Firewall\Plugins\Crs;
use Symfony\Component\HttpFoundation\Request;

$request = Request::createFromGlobals();

$crs = new Crs(metadata: [], config: [
    'paranoia' => 1,
    'mode' => 'monitor',   // Score and report without blocking.
]);

// evaluate() returns FALSE when CRS would block the request.
$allowed = $crs->evaluate($request);

$verdict = $crs->getLastVerdict();
if ($verdict !== null) {
    $siem->send([
        'blocked'       => $verdict->isBlocked(),
        'rule_id'       => $verdict->blockingRuleId,
        'action'        => $verdict->action,
        'total_score'   => $verdict->totalScore,
        'scores'        => $verdict->scores,      // per-category breakdown
        'matched_rules' => $verdict->matchedRules,
    ]);
}
```

This pairs naturally with `mode: monitor`, where the request is allowed through and you want to record what *would* have been blocked in more detail than the log line carries. `getLastVerdict()` returns `null` until `evaluate()` has run at least once on that instance.
