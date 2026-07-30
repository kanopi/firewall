#!/usr/bin/env php
<?php

declare(strict_types=1);

/*
 * Aggregate the per-scenario k6 summaries into a comparison report.
 *
 * This tool reports; it never fails. CircleCI runners are shared hardware and
 * an absolute latency gate would flake far more often than it would catch a
 * real regression, so the exit status is always 0 and the judgement is left
 * to whoever reads the artifact.
 *
 * Three questions the output is built to answer:
 *
 *   1. What does each plugin cost?          -> the per-plugin cost table,
 *                                              which subtracts the bootstrap
 *                                              scenario so config parsing is
 *                                              not attributed to plugins.
 *   2. Does the firewall bottleneck PHP?    -> throughput relative to
 *                                              baseline, plus the gap between
 *                                              firewall time and end-to-end
 *                                              time. A large gap means
 *                                              requests are queueing for a
 *                                              worker, which is what a
 *                                              bottleneck actually looks like.
 *   3. Is it still blocking correctly?      -> observed block rate per traffic
 *                                              profile per scenario.
 *
 * Usage:
 *   php bin/report.php --results=DIR [--started=ISO8601] [--php-version=8.3] ...
 */

$options = getopt('', [
    'results::',
    'started::',
    'php-version::',
    'vus::',
    'workers::',
    'app-work-ms::',
    'help',
]);

if (isset($options['help'])) {
    echo "Aggregate tests/Performance/results/*.json into report.md and report.html\n";
    exit(0);
}

$resultsDir = rtrim((string) ($options['results'] ?? dirname(__DIR__) . '/results'), '/');

if (!is_dir($resultsDir)) {
    fwrite(STDERR, "results directory not found: {$resultsDir}\n");
    exit(0);
}

$meta = [
    'started'     => (string) ($options['started'] ?? 'unknown'),
    'php_version' => (string) ($options['php-version'] ?? 'unknown'),
    'vus'         => (string) ($options['vus'] ?? 'unknown'),
    'workers'     => (string) ($options['workers'] ?? 'unknown'),
    'app_work_ms' => (string) ($options['app-work-ms'] ?? '0'),
];

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

$scenarios = [];

foreach (glob($resultsDir . '/*.json') ?: [] as $file) {
    $name = basename($file, '.json');

    // Warm-up runs write a file too; they are not measurements.
    if (str_starts_with($name, 'warmup-') || $name === 'summary' ) {
        continue;
    }

    $decoded = json_decode((string) file_get_contents($file), true);

    if (!is_array($decoded) || !isset($decoded['run'])) {
        fwrite(STDERR, "skipping malformed result file: {$file}\n");
        continue;
    }

    $scenarios[$name] = $decoded;
}

if ($scenarios === []) {
    fwrite(STDERR, "no scenario results found in {$resultsDir}\n");
    exit(0);
}

// Preserve the run order from bin/run.sh rather than glob's alphabetical order,
// so cheap plugins stay above expensive ones in the tables.
$order = [
    'baseline', 'bootstrap', 'ip-address', 'url', 'user-agent', 'geolocation',
    'asn', 'vulnerability-score', 'abuseipdb', 'rate-limit', 'rate-limit-redis',
    'crs', 'all-on', 'all-on-redis',
];

uksort($scenarios, static function (string $a, string $b) use ($order): int {
    $ai = array_search($a, $order, true);
    $bi = array_search($b, $order, true);
    $ai = $ai === false ? PHP_INT_MAX : $ai;
    $bi = $bi === false ? PHP_INT_MAX : $bi;
    return $ai <=> $bi ?: strcmp($a, $b);
});

$baseline = $scenarios['baseline'] ?? null;
$bootstrap = $scenarios['bootstrap'] ?? null;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

$num = static function (float $value, int $decimals = 2): string {
    return number_format($value, $decimals);
};

$usToMs = static fn (float $us): float => $us / 1000.0;

$pct = static function (float $value): string {
    return number_format($value, 1) . '%';
};

/** Signed delta, so a regression is visually distinct from an improvement. */
$signed = static function (float $value, int $decimals = 2, string $unit = ''): string {
    $prefix = $value > 0 ? '+' : '';
    return $prefix . number_format($value, $decimals) . $unit;
};

// ---------------------------------------------------------------------------
// Derive the comparison rows
// ---------------------------------------------------------------------------

$baselineRps = $baseline['run']['rps'] ?? 0.0;
$baselineP95 = $baseline['latency']['http_req_duration_ms']['p95'] ?? 0.0;
$bootstrapEvalP95 = $bootstrap['latency']['fw_eval_us']['p95'] ?? 0.0;

$rows = [];

foreach ($scenarios as $name => $s) {
    $rps = (float) ($s['run']['rps'] ?? 0);
    $e2eP95 = (float) ($s['latency']['http_req_duration_ms']['p95'] ?? 0);
    $evalP95 = (float) ($s['latency']['fw_eval_us']['p95'] ?? 0);
    $evalP50 = (float) ($s['latency']['fw_eval_us']['med'] ?? 0);
    $evalP99 = (float) ($s['latency']['fw_eval_us']['p99'] ?? 0);
    $bootP95 = (float) ($s['latency']['fw_boot_us']['p95'] ?? 0);

    $rows[$name] = [
        'scenario'      => $name,
        'rps'           => $rps,
        'rps_ratio'     => $baselineRps > 0 ? ($rps / $baselineRps) * 100 : 0.0,
        'e2e_p50'       => (float) ($s['latency']['http_req_duration_ms']['med'] ?? 0),
        'e2e_p95'       => $e2eP95,
        'e2e_p99'       => (float) ($s['latency']['http_req_duration_ms']['p99'] ?? 0),
        'e2e_added_p95' => $e2eP95 - $baselineP95,
        'eval_p50_ms'   => $usToMs($evalP50),
        'eval_p95_ms'   => $usToMs($evalP95),
        'eval_p99_ms'   => $usToMs($evalP99),
        'boot_p95_ms'   => $usToMs($bootP95),
        // Plugin work only: the bootstrap scenario's evaluate() cost is the
        // fixed overhead every configuration pays, so subtracting it leaves
        // what the plugins themselves are responsible for.
        'plugin_p95_ms' => $name === 'baseline'
            ? 0.0
            : max(0.0, $usToMs($evalP95 - $bootstrapEvalP95)),
        'mem_p95_kb'    => (float) ($s['memory']['peak_kb']['p95'] ?? 0),
        'reqs'          => (int) ($s['run']['http_reqs'] ?? 0),
        'blocked'       => (int) ($s['outcomes']['block'] ?? 0),
        'errors'        => (int) ($s['outcomes']['error'] ?? 0),
        'no_response'   => (int) ($s['run']['no_response'] ?? 0),
        'failed_rate'   => (float) ($s['run']['http_req_failed_rate'] ?? 0),
        'profiles'      => $s['profiles'] ?? [],
    ];
}

// ---------------------------------------------------------------------------
// Markdown report
// ---------------------------------------------------------------------------

$md = [];
$md[] = '# Firewall Performance Report';
$md[] = '';
$md[] = sprintf(
    '**Run started:** %s  |  **PHP:** %s  |  **Peak VUs:** %s  |  **php-fpm workers:** %s  |  **Simulated app work:** %s ms',
    $meta['started'],
    $meta['php_version'],
    $meta['vus'],
    $meta['workers'],
    $meta['app_work_ms'],
);
$md[] = '';
$md[] = 'This report does not pass or fail. It is a measurement, and the numbers';
$md[] = 'below are only comparable *within* a single run — CircleCI runners vary';
$md[] = 'enough between jobs that comparing one run\'s absolute milliseconds to';
$md[] = 'another\'s will mislead you. Compare scenarios to the `baseline` row in';
$md[] = 'the same table.';
$md[] = '';

if ($meta['app_work_ms'] === '0' || $meta['app_work_ms'] === '') {
    $md[] = '> **Note on the overhead percentages below.** This run used no simulated';
    $md[] = '> application work, so the app under test is effectively a hello-world.';
    $md[] = '> The *absolute* millisecond costs are real and transferable; the';
    $md[] = '> *relative* ones ("N% slower") are worst-case and will look far';
    $md[] = '> smaller against a real application. Re-run with `PERF_APP_WORK_MS`';
    $md[] = '> set to your own median response time for a representative ratio.';
    $md[] = '';
}

// --- Health first. A beautiful latency table over a run where half the
// --- requests died is the single easiest way to draw a wrong conclusion.
$unhealthy = array_filter(
    $rows,
    static fn (array $r): bool => $r['errors'] > 0 || $r['no_response'] > 0 || $r['failed_rate'] > 1.0,
);

$md[] = '## Run health';
$md[] = '';

if ($unhealthy === []) {
    $md[] = 'All scenarios completed with no PHP errors, no dropped connections, and';
    $md[] = 'an HTTP failure rate under 1%.';
} else {
    $md[] = 'Read these scenarios\' latency numbers with suspicion: a request that';
    $md[] = 'failed fast is a request that did not wait, which flatters the percentiles.';
    $md[] = '';
    $md[] = '| Scenario | PHP errors | No response | HTTP failure rate |';
    $md[] = '|---|---:|---:|---:|';
    foreach ($unhealthy as $r) {
        $md[] = sprintf(
            '| `%s` | %d | %d | %s |',
            $r['scenario'],
            $r['errors'],
            $r['no_response'],
            $pct($r['failed_rate']),
        );
    }
}
$md[] = '';

// --- Throughput and latency.
$md[] = '## Throughput and latency';
$md[] = '';
$md[] = '`Firewall p95` is the firewall\'s own decision time, measured inside PHP.';
$md[] = '`End-to-end p95` is what the client saw. When the two diverge sharply, the';
$md[] = 'time is going somewhere other than the firewall — usually requests queueing';
$md[] = 'for a php-fpm worker, which is the signature of saturation.';
$md[] = '';
$md[] = '| Scenario | RPS | vs baseline | End-to-end p50 / p95 / p99 (ms) | Firewall p50 / p95 / p99 (ms) | Added p95 (ms) | Peak mem (MB) |';
$md[] = '|---|---:|---:|---|---|---:|---:|';

foreach ($rows as $r) {
    $md[] = sprintf(
        '| `%s` | %s | %s | %s / %s / %s | %s / %s / %s | %s | %s |',
        $r['scenario'],
        $num($r['rps'], 1),
        $r['scenario'] === 'baseline' ? '—' : $pct($r['rps_ratio']),
        $num($r['e2e_p50']), $num($r['e2e_p95']), $num($r['e2e_p99']),
        $r['scenario'] === 'baseline' ? '—' : $num($r['eval_p50_ms'], 3),
        $r['scenario'] === 'baseline' ? '—' : $num($r['eval_p95_ms'], 3),
        $r['scenario'] === 'baseline' ? '—' : $num($r['eval_p99_ms'], 3),
        $r['scenario'] === 'baseline' ? '—' : $signed($r['e2e_added_p95']),
        $num($r['mem_p95_kb'] / 1024, 1),
    );
}
$md[] = '';

// --- Per-plugin cost ranking.
$md[] = '## What each plugin costs';
$md[] = '';

if ($bootstrap === null) {
    $md[] = 'The `bootstrap` scenario did not run, so plugin cost cannot be separated';
    $md[] = 'from the firewall\'s fixed setup cost. Re-run including `bootstrap`.';
} else {
    $md[] = sprintf(
        'Fixed cost of having the firewall at all (the `bootstrap` scenario): '
        . '**%s ms** to construct, **%s ms** to evaluate with zero plugins. '
        . 'The table below has that subtracted, so each row is the plugin\'s own work.',
        $num($rows['bootstrap']['boot_p95_ms'], 3),
        $num($rows['bootstrap']['eval_p95_ms'], 3),
    );
    $md[] = '';

    // The combined configurations are not plugins, so they do not belong in a
    // per-plugin ranking — listing them there invites reading `all-on` as if
    // it were a single expensive plugin. They get their own comparison below.
    $pluginRows = array_filter(
        $rows,
        static fn (array $r): bool => !in_array($r['scenario'], ['baseline', 'bootstrap'], true)
            && !str_starts_with($r['scenario'], 'all-on'),
    );
    uasort($pluginRows, static fn (array $a, array $b): int => $b['plugin_p95_ms'] <=> $a['plugin_p95_ms']);

    $md[] = '| Scenario | Plugin work p95 (ms) | Share of end-to-end p95 | Throughput vs baseline |';
    $md[] = '|---|---:|---:|---:|';

    foreach ($pluginRows as $r) {
        $share = $r['e2e_p95'] > 0 ? ($r['plugin_p95_ms'] / $r['e2e_p95']) * 100 : 0.0;
        $md[] = sprintf(
            '| `%s` | %s | %s | %s |',
            $r['scenario'],
            $num($r['plugin_p95_ms'], 3),
            $pct($share),
            $pct($r['rps_ratio']),
        );
    }

    // The short-circuit check. This is the claim all-on.yml's comment makes,
    // and it is cheap to verify, so verify it rather than asserting it.
    $individual = array_filter(
        $pluginRows,
        static fn (array $r): bool => !str_starts_with($r['scenario'], 'all-on')
            && $r['scenario'] !== 'rate-limit-redis',
    );
    $sumIndividual = array_sum(array_column($individual, 'plugin_p95_ms'));

    if (isset($rows['all-on'])) {
        $md[] = '';
        $md[] = sprintf(
            'Sum of the individual plugin scenarios: **%s ms**. The `all-on` scenario '
            . 'measures **%s ms**. %s',
            $num($sumIndividual, 3),
            $num($rows['all-on']['plugin_p95_ms'], 3),
            $rows['all-on']['plugin_p95_ms'] < $sumIndividual
                ? 'The combined config is cheaper than the sum, which is the expected '
                  . 'result: cheap plugins run first and short-circuit the chain before '
                  . 'the expensive ones are reached.'
                : '**The combined config is not cheaper than the sum.** Plugin ordering '
                  . 'is not short-circuiting the way the weights intend — worth '
                  . 'investigating before shipping this configuration.',
        );
    }
}
$md[] = '';

// --- Storage delta.
if (isset($rows['rate-limit'], $rows['rate-limit-redis'])) {
    $md[] = '## Cost of shared state';
    $md[] = '';
    $md[] = sprintf(
        'Rate limiting with in-memory storage: **%s ms** p95. With Redis: **%s ms** p95. '
        . 'The difference, **%s ms**, is the per-request cost of counters that are '
        . 'actually shared across workers — the price of correct rate limiting behind '
        . 'a load balancer.',
        $num($rows['rate-limit']['plugin_p95_ms'], 3),
        $num($rows['rate-limit-redis']['plugin_p95_ms'], 3),
        $num($rows['rate-limit-redis']['plugin_p95_ms'] - $rows['rate-limit']['plugin_p95_ms'], 3),
    );
    $md[] = '';
}

// --- Block behaviour.
$md[] = '## Observed block rate by traffic profile';
$md[] = '';
$md[] = 'Percentage of each traffic profile that the firewall blocked. A single-plugin';
$md[] = 'scenario legitimately allows malicious traffic aimed at a different plugin, so';
$md[] = 'read down the `all-on` columns for coverage and across a row to see which';
$md[] = 'plugin is responsible for catching what.';
$md[] = '';

$profileNames = [];
foreach ($rows as $r) {
    foreach (array_keys($r['profiles']) as $p) {
        $profileNames[$p] = true;
    }
}
$profileNames = array_keys($profileNames);

if ($profileNames !== []) {
    $header = '| Profile | Intent |';
    $divider = '|---|---|';
    foreach ($rows as $r) {
        if ($r['scenario'] === 'baseline') {
            continue;
        }
        $header .= ' `' . $r['scenario'] . '` |';
        $divider .= '---:|';
    }
    $md[] = $header;
    $md[] = $divider;

    foreach ($profileNames as $p) {
        $intent = 'unknown';
        foreach ($rows as $r) {
            if (isset($r['profiles'][$p]['expect'])) {
                $intent = (string) $r['profiles'][$p]['expect'];
                break;
            }
        }

        $line = sprintf('| `%s` | %s |', $p, $intent);
        foreach ($rows as $r) {
            if ($r['scenario'] === 'baseline') {
                continue;
            }
            $rate = $r['profiles'][$p]['block_rate'] ?? null;
            $line .= ' ' . ($rate === null ? '—' : $pct((float) $rate)) . ' |';
        }
        $md[] = $line;
    }
}
$md[] = '';

$md[] = '## How to read this';
$md[] = '';
$md[] = '- **"Does the firewall bottleneck PHP?"** Look at `Throughput vs baseline`.';
$md[] = '  A scenario holding above ~90% of baseline RPS is not the constraint. One';
$md[] = '  falling well below it is consuming enough CPU per request to reduce how';
$md[] = '  many requests the same worker pool can serve.';
$md[] = '- **A wide gap between `Firewall p95` and `End-to-end p95`** means time is';
$md[] = '  being spent outside the firewall. At high VU counts that is usually';
$md[] = '  requests waiting for a free php-fpm worker. Raise `PERF_FPM_WORKERS` or';
$md[] = '  lower `PERF_VUS` and see whether the gap closes; if it does, you found';
$md[] = '  the pool size, not a firewall problem.';
$md[] = '- **`Firewall p99` far above `Firewall p95`** points at a warm-up effect';
$md[] = '  that the warm-up phase did not fully absorb — most likely a per-worker';
$md[] = '  cache being built. Relevant for CRS in particular.';
$md[] = '';

$markdown = implode("\n", $md) . "\n";
file_put_contents($resultsDir . '/report.md', $markdown);

// ---------------------------------------------------------------------------
// Machine-readable summary, for trending across runs
// ---------------------------------------------------------------------------

file_put_contents(
    $resultsDir . '/summary.json',
    json_encode(
        [
            'meta'      => $meta,
            'scenarios' => array_map(
                static function (array $r): array {
                    unset($r['profiles']);
                    return $r;
                },
                $rows,
            ),
        ],
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES,
    ) . "\n",
);

// ---------------------------------------------------------------------------
// HTML, for the CircleCI artifact browser
// ---------------------------------------------------------------------------

$rowsHtml = '';
$maxRps = max(array_map(static fn (array $r): float => $r['rps'], $rows)) ?: 1.0;

foreach ($rows as $r) {
    $barWidth = ($r['rps'] / $maxRps) * 100;
    $healthy = $r['errors'] === 0 && $r['no_response'] === 0;

    $rowsHtml .= sprintf(
        '<tr class="%s">'
        . '<td><code>%s</code></td>'
        . '<td class="n">%s<div class="bar"><span style="width:%.1f%%"></span></div></td>'
        . '<td class="n">%s</td><td class="n">%s</td><td class="n">%s</td>'
        . '<td class="n">%s</td><td class="n">%s</td>'
        . '</tr>',
        $healthy ? '' : 'warn',
        htmlspecialchars($r['scenario'], ENT_QUOTES),
        $num($r['rps'], 1),
        $barWidth,
        $r['scenario'] === 'baseline' ? '&mdash;' : $pct($r['rps_ratio']),
        $num($r['e2e_p95']),
        $r['scenario'] === 'baseline' ? '&mdash;' : $num($r['eval_p95_ms'], 3),
        $r['scenario'] === 'baseline' ? '&mdash;' : $num($r['plugin_p95_ms'], 3),
        $num($r['mem_p95_kb'] / 1024, 1),
    );
}

$html = <<<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Firewall Performance Report</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; margin: 0; padding: 2rem 1.5rem; line-height: 1.55; max-width: 78rem; margin-inline: auto; }
  h1 { margin-top: 0; font-size: 1.6rem; }
  h2 { font-size: 1.1rem; margin-top: 2.25rem; }
  .meta { font-size: .85rem; opacity: .75; margin-bottom: 1.5rem; }
  .note { border-left: 3px solid #f0ad4e; padding: .6rem .9rem; background: rgba(240,173,78,.08); font-size: .9rem; border-radius: 0 4px 4px 0; }
  .table-wrap { overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; font-size: .88rem; min-width: 48rem; }
  th, td { padding: .45rem .7rem; text-align: left; border-bottom: 1px solid rgba(128,128,128,.25); }
  th { font-weight: 600; font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; opacity: .7; }
  td.n, th.n { text-align: right; font-variant-numeric: tabular-nums; }
  tr.warn td { background: rgba(217,83,79,.09); }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9em; }
  .bar { height: 3px; background: rgba(128,128,128,.2); border-radius: 2px; margin-top: 3px; }
  .bar span { display: block; height: 100%; background: #4a90d9; border-radius: 2px; }
  footer { margin-top: 2.5rem; font-size: .82rem; opacity: .7; }
</style>
</head>
<body>
<h1>Firewall Performance Report</h1>
<p class="meta">
  Started {$meta['started']} &middot; PHP {$meta['php_version']} &middot;
  {$meta['vus']} peak VUs &middot; {$meta['workers']} php-fpm workers &middot;
  {$meta['app_work_ms']} ms simulated app work
</p>
<p class="note">
  This report measures; it does not gate. Numbers are comparable only within
  this run &mdash; compare each scenario to <code>baseline</code>, not to a
  previous job on different hardware.
</p>

<h2>Throughput and cost</h2>
<div class="table-wrap">
<table>
  <thead>
    <tr>
      <th>Scenario</th>
      <th class="n">Requests/sec</th>
      <th class="n">vs baseline</th>
      <th class="n">End-to-end p95 (ms)</th>
      <th class="n">Firewall p95 (ms)</th>
      <th class="n">Plugin work p95 (ms)</th>
      <th class="n">Peak mem (MB)</th>
    </tr>
  </thead>
  <tbody>{$rowsHtml}</tbody>
</table>
</div>

<footer>
  Full detail, including per-profile block rates, is in <code>report.md</code>.
  Raw per-scenario k6 summaries are the other JSON files in this directory.
</footer>
</body>
</html>
HTML;

file_put_contents($resultsDir . '/report.html', $html);

// ---------------------------------------------------------------------------
// Console
// ---------------------------------------------------------------------------

echo $markdown;
echo "\nWrote report.md, report.html and summary.json to {$resultsDir}\n";

// Always zero. See the header comment.
exit(0);
