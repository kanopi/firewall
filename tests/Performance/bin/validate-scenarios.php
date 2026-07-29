#!/usr/bin/env php
<?php

declare(strict_types=1);

/*
 * Check every scenario config loads and evaluates before spending twenty
 * minutes of CI on a benchmark.
 *
 * A typo in a scenario YAML does not stop the harness — Firewall::create()
 * logs a config load failure and carries on with a partial ruleset — so the
 * benchmark would happily produce a beautiful set of numbers for a firewall
 * that was not running the plugins you thought it was. This catches that in
 * a couple of seconds.
 *
 * Runs against the real Firewall, in exception mode, with a synthetic request
 * for each traffic profile the k6 generator sends.
 *
 * Usage:
 *   php bin/validate-scenarios.php [--scenario=NAME] [--skip-geoip]
 *
 * Exit status is 1 when a scenario fails to load or throws unexpectedly, so
 * this one *is* safe to gate on — unlike the benchmark itself, it measures
 * correctness, not timing, so it does not care what hardware it is on.
 */

require dirname(__DIR__, 3) . '/vendor/autoload.php';

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Utility\Config;
use Symfony\Component\HttpFoundation\Request;

$options = getopt('', ['scenario::', 'skip-geoip', 'help']);

if (isset($options['help'])) {
    echo <<<TXT
    Validate that every performance scenario config loads and evaluates.

      --scenario=NAME   Check only this scenario
      --skip-geoip      Skip scenarios that need a MaxMind database

    TXT;
    exit(0);
}

$scenarioDir = dirname(__DIR__) . '/scenarios';

$files = isset($options['scenario'])
    ? [$scenarioDir . '/' . basename((string) $options['scenario']) . '.yml']
    : (glob($scenarioDir . '/*.yml') ?: []);

if ($files === []) {
    fwrite(STDERR, "no scenario files found in {$scenarioDir}\n");
    exit(1);
}

sort($files);

$geoipScenarios = ['geolocation', 'asn', 'vulnerability-score', 'all-on', 'all-on-redis'];
$redisScenarios = ['rate-limit-redis', 'all-on-redis'];
$skipGeoip = isset($options['skip-geoip']);

// Requests mirroring what k6/traffic.js sends, so validation exercises the
// same code paths the benchmark will.
$probes = [
    'browse'       => ['GET', '/', [], 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15'],
    'scanner_url'  => ['GET', '/wp-login.php', [], 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36'],
    'sqli'         => ['GET', '/search', ['q' => "1' UNION SELECT 1,2,3--"], 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36'],
    'xss'          => ['GET', '/search', ['q' => '<script>alert(1)</script>'], 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36'],
    'scanner_ua'   => ['GET', '/', [], 'sqlmap/1.8.3#stable (https://sqlmap.org)'],
    'bot_ua'       => ['GET', '/', [], 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
    'blocked_ip'   => ['GET', '/', [], 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36'],
    'risky_method' => ['DELETE', '/api/v1/items/7', [], 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36'],
];

$exitCode = 0;
$checked = 0;

foreach ($files as $file) {
    $name = basename($file, '.yml');

    if ($skipGeoip && in_array($name, $geoipScenarios, true)) {
        printf("SKIP  %-22s (needs a MaxMind database)\n", $name);
        continue;
    }

    if (in_array($name, $redisScenarios, true) && !@fsockopen(getenv('REDIS_HOST') ?: 'redis', (int) (getenv('REDIS_PORT') ?: 6379), $e, $s, 1)) {
        printf("SKIP  %-22s (no redis reachable)\n", $name);
        continue;
    }

    $checked++;

    Config::clearLoadErrors();

    try {
        $firewall = Firewall::create([$file], ['global' => ['mode' => 'exception']]);
    } catch (Throwable $e) {
        printf("FAIL  %-22s create() threw %s: %s\n", $name, $e::class, $e->getMessage());
        $exitCode = 1;
        continue;
    }

    // A config that failed to load does not throw by default; it logs and
    // carries on with whatever it managed to parse. For a benchmark that is
    // the worst possible outcome, so treat it as a hard failure here.
    $loadErrors = Config::getLoadErrors();
    if ($loadErrors !== []) {
        printf("FAIL  %-22s config load errors: %s\n", $name, implode('; ', array_map('strval', $loadErrors)));
        $exitCode = 1;
        continue;
    }

    $blocked = [];
    $failed = false;
    $probeIndex = 0;

    foreach ($probes as $probeName => [$method, $path, $query, $userAgent]) {
        $probeIndex++;

        // Each probe gets its own client address. Sharing one would let the
        // repeat-offender blocklist carry a block from an earlier probe into
        // every later one — the firewall behaving correctly, but it would
        // report "url blocks bot_ua", which is not true and would send someone
        // hunting for a rule that does not exist.
        //
        // TEST-NET-3 for the blocked_ip probe so the IpAddress scenario has
        // something to match; distinct public addresses for the rest.
        $clientIp = $probeName === 'blocked_ip'
            ? '203.0.113.42'
            : '4.16.20.' . $probeIndex;

        $request = Request::create(
            $path,
            $method,
            $query,
            [],
            [],
            ['REMOTE_ADDR' => $clientIp, 'HTTP_USER_AGENT' => $userAgent],
        );

        try {
            $firewall->evaluate($request);
        } catch (FirewallBlockedException) {
            $blocked[] = $probeName;
        } catch (Throwable $e) {
            printf("FAIL  %-22s probe '%s' threw %s: %s\n", $name, $probeName, $e::class, $e->getMessage());
            $exitCode = 1;
            $failed = true;
            break;
        }
    }

    if ($failed) {
        continue;
    }

    printf(
        "OK    %-22s blocks: %s\n",
        $name,
        $blocked === [] ? '(none)' : implode(', ', $blocked),
    );
}

printf("\n%d scenario(s) checked.\n", $checked);

if ($exitCode !== 0) {
    fwrite(STDERR, "\nOne or more scenarios are broken. Fix these before benchmarking:\n");
    fwrite(STDERR, "a partial config produces plausible numbers for a firewall that is not running your rules.\n");
}

exit($exitCode);
