#!/usr/bin/env php
<?php

declare(strict_types=1);

/*
 * Generate the client IP population shared by every part of the harness.
 *
 * WHY A FIXED POOL RATHER THAN RANDOM IPS PER REQUEST:
 *
 *   1. Rate limiting needs repeat visitors. Fully random addresses would give
 *      every request a fresh counter and nothing would ever be limited.
 *   2. AbuseIpdb's cache has to be pre-seeded, and you cannot seed an
 *      unbounded set. A fixed pool makes every lookup a deterministic cache
 *      hit instead of a live API call.
 *   3. Runs have to be comparable. A different IP mix between two runs moves
 *      the GeoLocation and Asn block rates, and then a plugin looks slower
 *      when really it was just handed different traffic.
 *
 * The generator is seeded, so the same pool comes out on every machine and
 * every CI run unless --seed changes.
 *
 * Usage:
 *   php bin/generate-ip-pool.php [--size=5000] [--seed=20260729] [--out=path]
 */

$options = getopt('', ['size::', 'seed::', 'out::', 'help']);

if (isset($options['help'])) {
    echo <<<TXT
    Generate the shared client IP pool for the performance harness.

      --size=N    Number of addresses to generate (default 5000)
      --seed=N    PRNG seed; same seed gives the same pool (default 20260729)
      --out=PATH  Output file (default tests/Performance/k6/ip-pool.json)

    TXT;
    exit(0);
}

$size = max(100, (int) ($options['size'] ?? 5000));
$seed = (int) ($options['seed'] ?? 20260729);
$out  = (string) ($options['out'] ?? dirname(__DIR__) . '/k6/ip-pool.json');

/*
 * Real, currently-allocated ranges per country, so MaxMind actually resolves
 * them. Invented ranges would leave GeoLocation and Asn resolving to nothing
 * and quietly turn two of the scenarios into measurements of the miss path.
 *
 * The weights are a rough public-web traffic mix, not a claim about any
 * specific site's audience.
 */
$countries = [
    'US' => ['weight' => 30, 'ranges' => [['4.16.0.0', '4.31.255.255'], ['23.20.0.0', '23.23.255.255'], ['64.233.160.0', '64.233.191.255']]],
    'CN' => ['weight' => 12, 'ranges' => [['1.2.4.0', '1.2.4.255'], ['14.144.0.0', '14.159.255.255'], ['223.4.0.0', '223.7.255.255']]],
    'RU' => ['weight' => 8,  'ranges' => [['5.45.192.0', '5.45.255.255'], ['95.108.128.0', '95.108.255.255'], ['217.69.128.0', '217.69.143.255']]],
    'DE' => ['weight' => 7,  'ranges' => [['46.4.0.0', '46.4.255.255'], ['88.198.0.0', '88.198.255.255']]],
    'GB' => ['weight' => 6,  'ranges' => [['81.2.69.0', '81.2.69.255'], ['51.140.0.0', '51.143.255.255']]],
    'FR' => ['weight' => 5,  'ranges' => [['51.15.0.0', '51.15.255.255'], ['90.0.0.0', '90.15.255.255']]],
    'BR' => ['weight' => 5,  'ranges' => [['177.0.0.0', '177.15.255.255'], ['189.0.0.0', '189.15.255.255']]],
    'IN' => ['weight' => 5,  'ranges' => [['49.32.0.0', '49.47.255.255'], ['103.21.0.0', '103.21.255.255']]],
    'JP' => ['weight' => 4,  'ranges' => [['126.0.0.0', '126.15.255.255'], ['133.11.0.0', '133.11.255.255']]],
    'KR' => ['weight' => 3,  'ranges' => [['175.192.0.0', '175.207.255.255']]],
    'VN' => ['weight' => 3,  'ranges' => [['113.160.0.0', '113.175.255.255']]],
    'NG' => ['weight' => 2,  'ranges' => [['41.58.0.0', '41.58.255.255'], ['105.112.0.0', '105.115.255.255']]],
    'IR' => ['weight' => 2,  'ranges' => [['2.144.0.0', '2.159.255.255']]],
    // TEST-NET-2 and TEST-NET-3 (RFC 5737). Reserved for documentation, so
    // they will never resolve to a real country — which is exactly why the
    // IpAddress scenario blocks them: a guaranteed, geography-independent
    // match that does not depend on the GeoLite2 vintage.
    'XX' => ['weight' => 8,  'ranges' => [['198.51.100.0', '198.51.100.255'], ['203.0.113.0', '203.0.113.255']]],
];

mt_srand($seed);

$weightTotal = array_sum(array_column($countries, 'weight'));
$ips = [];
$seen = [];

foreach ($countries as $code => $spec) {
    $count = (int) round($size * $spec['weight'] / $weightTotal);

    for ($i = 0; $i < $count; $i++) {
        // Retry on collision so the pool holds `size` distinct addresses; a
        // duplicate would silently double one client's rate-limit weight.
        for ($attempt = 0; $attempt < 20; $attempt++) {
            $range = $spec['ranges'][mt_rand(0, count($spec['ranges']) - 1)];
            $ip = long2ip(mt_rand(ip2long($range[0]), ip2long($range[1])));

            if (!isset($seen[$ip])) {
                $seen[$ip] = true;
                $ips[] = ['ip' => $ip, 'country' => $code];
                break;
            }
        }
    }
}

// Deterministic shuffle so the burst slice (the first N entries, used by the
// rate-limit profile) is a country mix rather than whichever country the
// loop above happened to emit first.
mt_srand($seed + 1);
for ($i = count($ips) - 1; $i > 0; $i--) {
    $j = mt_rand(0, $i);
    [$ips[$i], $ips[$j]] = [$ips[$j], $ips[$i]];
}

$payload = [
    'seed'       => $seed,
    'size'       => count($ips),
    // The rate-limit profile draws only from the first `burst_slice` entries.
    // Concentrating the flood on a small client set is what makes the limiter
    // actually trip; spread across all 5000 it would never reach a threshold.
    'burst_slice' => min(50, count($ips)),
    'ips'        => $ips,
];

if (!is_dir(dirname($out)) && !mkdir(dirname($out), 0775, true) && !is_dir(dirname($out))) {
    fwrite(STDERR, "could not create directory " . dirname($out) . "\n");
    exit(1);
}

if (file_put_contents($out, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n") === false) {
    fwrite(STDERR, "could not write {$out}\n");
    exit(1);
}

printf(
    "Wrote %d addresses (seed %d, burst slice %d) to %s\n",
    count($ips),
    $seed,
    $payload['burst_slice'],
    $out,
);
