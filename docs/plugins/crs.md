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

!!! warning "Upgrading from a release built on `crs-engine` 0.1.0"

    This plugin now requires `crs-engine` ^1.0, which is the first version where the engine actually enforces. In 0.1.0 the detection pipeline was substantially inert — the anomaly-evaluation rules could never fire, `TX:` targets never resolved, and `skipAfter` silently discarded the rest of the ruleset. **Traffic that used to pass will now be rejected**, because previously very little was.

    Roll it out with `mode: monitor` first. Let it run over real traffic, group the `contributing_rules` on the debug log lines by rule ID, and build your `disabled_rules` list from what you actually see before you let it block. CRS at paranoia 1 does flag some ordinary editorial content — a support ticket containing `cat /etc/hosts | grep` scores 15 and would be rejected — so on a CMS this step is not optional.

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
      #   scanner, multipart, generic, response_leak, response_leak_sql,
      #   response_leak_java, response_leak_php, response_leak_iis,
      #   response_leak_ruby, web_shell, correlation, blocking_evaluation
      # Do not disable blocking_evaluation — it is how anomaly scoring
      # rejects anything at all.
      disabled_categories: []
      # Anomaly-score thresholds. There are exactly two — see
      # "Anomaly scores and thresholds" below before reaching for these.
      anomaly_thresholds:
        # Request-side score at or above which the request is rejected.
        inbound: 5
        # Response-side equivalent. Inert until response evaluation lands (#69).
        outbound: 4
      # Custom rule cache location — defaults to vendor/kanopi/crs-engine/rules
      # rules_path: /etc/firewall/crs-rules
```

## Anomaly scores and thresholds

A matching rule adds points to the request's anomaly score, weighted by the rule's CRS severity — critical contributes 5, error 4, warning 3, notice 2. Those per-severity weights are fixed by CRS and are not configurable through this plugin.

Once the accumulated score reaches the threshold, CRS rule 949110 rejects the request. The two thresholds are:

| Key | Default | Controls |
|---|---|---|
| `inbound` | `5` | Request-side threshold — the score at or above which a request is rejected. |
| `outbound` | `4` | Response-side equivalent. Not reached yet; this plugin does not call `evaluateResponse()` (issue #69). |

At the default of 5, a single critical rule is enough to reject. Raise it to require corroboration from several rules, lower it to reject on weaker evidence:

```php
$payload = ['id' => "1' UNION SELECT 1,2,3--"];   // scores 10: rules 942190 + 942360

(new Crs([], ['anomaly_thresholds' => ['inbound' => 5]]))->evaluate($request);    // true  — rejected
(new Crs([], ['anomaly_thresholds' => ['inbound' => 500]]))->evaluate($request);  // false — allowed
```

The severity-named spellings `critical` (= `inbound`) and `error` (= `outbound`) are still accepted, so config written before the rename keeps working — the plugin translates them, which also keeps `crs-engine`'s deprecation notice out of your logs. Any other key, including the `warning` and `notice` that earlier versions of this document showed, has never had any effect; the plugin logs a warning naming what it ignored rather than accepting it silently. If both spellings of one threshold are present, `inbound` / `outbound` win.

!!! danger "A block is attributed to rule 949110, not to the rule that caught the payload"

    949110 is the CRS rule that compares the score to the threshold, so it is the `rule_id` on every anomaly-score block. **Never put it in `disabled_rules`** — that switches off anomaly blocking entirely. The rules worth excluding are in `contributing_rules` on the same log line.

To tune a false positive, in rough order of precision:

- **`disabled_rules`** — the precise lever. Take the IDs from `contributing_rules` in the block's log line.
- **`disabled_categories`** — blunter, when a whole class of rules is wrong for your app. Note `blocking_evaluation` is a category: disabling it turns off anomaly blocking, so treat it as off-limits.
- **`anomaly_thresholds.inbound`** — raise it to require more corroboration before rejecting. Affects everything, so prefer the two above when you know which rule is wrong.
- **`paranoia`** — lower it to drop the aggressive rule tiers wholesale.
- **`mode: monitor`** — evaluates and logs but never rejects. The safe setting while you build an exclusion list.

## Coverage

Currently the plugin handles request-side evaluation: every CRS rule in `REQUEST-*.conf` runs against the incoming request. Response-side rules (RESPONSE-* files — SQL error / stack-trace / PHP warning leakage detection) are tracked under issue #69 and will land as a follow-up.

The four CRS rules that rely on `libinjection` (`@detectSQLi` / `@detectXSS` — rules 941100, 941180, 942100, 942500) are parsed but not evaluated; the engine logs them as `parser warnings` in `vendor/kanopi/crs-engine/rules/manifest.json`. CRS's regex-based SQLi/XSS rules in the same files run normally and provide the bulk of the detection.

## What gets logged

Blocked requests log at `info` level with full context:
- `rule_id` — the CRS rule that fired the block. For an anomaly-score block this is always **949110**, the rule that compares the score to the threshold — not the rule that caught the payload, and not something to put in `disabled_rules`.
- `contributing_rules` — the rules that actually detected something, in match order. **These are the IDs to feed to `disabled_rules`.**
- `total_score` — accumulated anomaly score
- `scores` — per-category breakdown (sqli, xss, lfi, etc.)
- `matched_rule` — the first matching rule's human-readable message
- `matched_data` — the substring of the request that matched
- `operator_errors` / `truncations` — see below

Non-blocking matches (monitor mode, or a score under the threshold) log at `debug` level with the same `contributing_rules`, which is what makes monitor mode usable for building an exclusion list.

Separately, the plugin logs at `warning` level when `operator_errors` or `truncations` is non-empty — a rule that could not run, or an inspection cap that engaged. Both mean part of the request went unexamined, so a clean verdict is weaker evidence than it looks. This fires even when nothing matched, because that is exactly when a silent gap in coverage is most likely to be believed.

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

// evaluate() returns TRUE when the plugin matched — i.e. when CRS would
// block the request. See PluginInterface::evaluate().
$matched = $crs->evaluate($request);

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
