#!/usr/bin/env php
<?php

declare(strict_types=1);

/*
 * Pre-seed the AbuseIpdb plugin's file cache for every address in the pool.
 *
 * The plugin calls a third-party API on a cache miss. Letting a benchmark do
 * that would measure AbuseIPDB's network latency instead of the firewall's
 * work, exhaust the daily quota within seconds, and be rude. Seeding the cache
 * makes every lookup a hit, which is also the path a real deployment takes for
 * effectively all of its traffic once warm.
 *
 * The cache format is read from the plugin's own contract in
 * src/Plugins/AbuseIpdb.php (readCache / writeCache / cachePath):
 *
 *   path:  {cache_dir}/abuseipdb-{sha1(ip)}.json
 *   body:  {"report":{"abuse_confidence_score":N,"is_whitelisted":B,
 *                     "total_reports":N,"country_code":"XX"}}
 *   fresh: judged by the file's mtime against cache_ttl
 *
 * If any of those change in the plugin, this script goes stale and the
 * abuseipdb scenario will start making real network calls — which shows up
 * immediately as a collapse in that scenario's throughput. That is the
 * intended failure signal.
 *
 * Usage:
 *   php bin/seed-abuseipdb-cache.php [--pool=path] [--dir=/perf-cache/abuseipdb]
 */

$options = getopt('', ['pool::', 'dir::', 'flagged-percent::', 'help']);

if (isset($options['help'])) {
    echo <<<TXT
    Pre-seed the AbuseIpdb file cache so the benchmark never calls the API.

      --pool=PATH             IP pool JSON (default tests/Performance/k6/ip-pool.json)
      --dir=PATH              Cache directory (default /perf-cache/abuseipdb)
      --flagged-percent=N     Percentage of addresses scored above the block
                              threshold (default 10)

    TXT;
    exit(0);
}

$poolFile = (string) ($options['pool'] ?? dirname(__DIR__) . '/k6/ip-pool.json');
$cacheDir = (string) ($options['dir'] ?? '/perf-cache/abuseipdb');
$flaggedPercent = max(0, min(100, (int) ($options['flagged-percent'] ?? 10)));

if (!is_file($poolFile)) {
    fwrite(STDERR, "IP pool not found: {$poolFile}\nRun bin/generate-ip-pool.php first.\n");
    exit(1);
}

$pool = json_decode((string) file_get_contents($poolFile), true);

if (!is_array($pool) || !isset($pool['ips']) || !is_array($pool['ips'])) {
    fwrite(STDERR, "IP pool is malformed: {$poolFile}\n");
    exit(1);
}

if (!is_dir($cacheDir) && !mkdir($cacheDir, 0775, true) && !is_dir($cacheDir)) {
    fwrite(STDERR, "could not create cache directory: {$cacheDir}\n");
    exit(1);
}

$written = 0;
$flagged = 0;

foreach ($pool['ips'] as $entry) {
    if (!is_array($entry) || !isset($entry['ip']) || !is_string($entry['ip'])) {
        continue;
    }

    $ip = $entry['ip'];
    $country = is_string($entry['country'] ?? null) ? $entry['country'] : '';

    // Derive the verdict from the address itself so reruns are identical.
    // A random score per run would move the abuseipdb block rate between
    // runs and make the scenario look non-deterministic.
    $bucket = hexdec(substr(sha1('abuseipdb-seed:' . $ip), 0, 4)) % 100;
    $isFlagged = $bucket < $flaggedPercent;

    if ($isFlagged) {
        $flagged++;
    }

    $report = [
        // Above the scenario's threshold of 75 when flagged, comfortably
        // below it otherwise.
        'abuse_confidence_score' => $isFlagged ? 80 + ($bucket % 21) : $bucket % 40,
        'is_whitelisted'         => false,
        'total_reports'          => $isFlagged ? 40 + ($bucket % 200) : $bucket % 5,
        'country_code'           => $country === 'XX' ? '' : $country,
    ];

    $path = $cacheDir . '/abuseipdb-' . sha1($ip) . '.json';

    if (file_put_contents($path, json_encode(['report' => $report]), LOCK_EX) === false) {
        fwrite(STDERR, "could not write {$path}\n");
        exit(1);
    }

    // Freshness is judged from mtime, so make sure it is now rather than
    // whatever the filesystem inherited.
    touch($path);

    $written++;
}

printf(
    "Seeded %d AbuseIPDB cache entries in %s (%d above the block threshold)\n",
    $written,
    $cacheDir,
    $flagged,
);

// TEST-NET addresses in the pool are reserved ranges. AbuseIpdb::evaluate()
// short-circuits on those before it ever consults the cache, so their entries
// are written but never read. Harmless, and cheaper than special-casing them.
