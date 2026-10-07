<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Concurrency probe for `verify: reverse-dns` (#245).
 *
 * The k6 harness measures throughput. It cannot answer the two questions that
 * decide whether the verification shipped in 2.20.0 is safe under load, both of
 * which were documented as provisional:
 *
 *   1. Does the in-flight claim actually collapse a stampede? It is a cache
 *      entry rather than a lock, and "best effort" is a claim, not a number.
 *   2. Does the breaker trip before a degraded resolver exhausts the workers?
 *      It only trips *after* one slow lookup returns, so there is a window.
 *
 * Both need many processes hitting one cold address at the same instant, which
 * is what this does. Each worker records whether it performed a lookup, so the
 * answer is a count rather than an impression.
 *
 * Usage:
 *   php tests/Performance/bin/reverse-dns-probe.php [workers] [latency-ms]
 *
 * `latency-ms` stubs the resolver at a fixed delay, so the degraded case is
 * reproducible without pointing anything at a black-hole nameserver.
 *
 * With `FW_RDNS_RESOLVER=doh`, the workers instead verify through a real
 * `DnsOverHttpResolver` (#480), so curl's time limits are what is measured:
 *
 *   FW_RDNS_DOH_ENDPOINT    endpoint template (required)
 *   FW_RDNS_DOH_ADDRESS     address to pin the endpoint's host to
 *   FW_RDNS_DOH_TIMEOUT_MS  limit on each lookup (default 300)
 *   FW_RDNS_CAINFO          a CA bundle, for a local server's own certificate;
 *                           passed to every worker as `-d openssl.cafile=` and
 *                           `-d curl.cainfo=`
 *
 * `latency-ms` is ignored then: the server decides how long it takes, and
 * `bin/doh-bench.sh` runs `fake-doh-server.py` to make that controllable. Each
 * request the resolver makes is tallied, so "DNS lookups made" counts HTTP
 * requests, reverse and forward alike.
 */

require dirname(__DIR__, 3) . '/vendor/autoload.php';

use Kanopi\Firewall\Utility\ReverseDns\DnsOverHttpResolver;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsSettings;
use Kanopi\Firewall\Utility\ReverseDnsVerifier;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

$workers = (int) ($argv[1] ?? 25);
$latencyMs = (float) ($argv[2] ?? 0);

// How long a worker that cannot claim the lookup waits for the holder's verdict
// (#261). 0 is the behaviour every release before 2.23.0 had, and is what the
// third column of #245's table measured.
$claimWaitMs = (int) (getenv('FW_RDNS_CLAIM_WAIT_MS') ?: 0);

// The resolver under test, and everything a worker needs to build it. Read once
// here, and handed to every child explicitly below -- see the note there on why.
$doh = getenv('FW_RDNS_RESOLVER') === 'doh' ? [
    'endpoint' => (string) getenv('FW_RDNS_DOH_ENDPOINT'),
    'address' => (string) getenv('FW_RDNS_DOH_ADDRESS'),
    'timeout_ms' => (int) (getenv('FW_RDNS_DOH_TIMEOUT_MS') ?: DnsOverHttpResolver::DEFAULT_TIMEOUT_MS),
] : null;
$caInfo = (string) getenv('FW_RDNS_CAINFO');

// A child inherits the parent's workspace through the environment. Deriving it
// from getmypid() would give every process a private cache, and the probe would
// report a collapse that never happened.
$workspace = getenv('FW_RDNS_PROBE_WORKSPACE')
    ?: sys_get_temp_dir() . '/fw-rdns-probe-' . getmypid();
$cacheDir = $workspace . '/cache';
$tally = $workspace . '/lookups';
$barrier = $workspace . '/go';

$isChild = ($argv[3] ?? null) === '--child';

// Only the parent prepares the workspace. A child truncating the tally would
// erase every lookup recorded before it started, which reads as a perfect
// stampede collapse and is nothing of the sort.
if (!$isChild) {
    @mkdir($cacheDir, 0700, true);
    file_put_contents($tally, '');
    @unlink($barrier);
}

/**
 * One worker: verify a single cold address and report whether it resolved.
 */
$child = static function (string $cacheDir, string $tally, float $latencyMs, string $barrier, int $claimWaitMs, ?array $doh): void {
    // Wait for the parent's signal. Without this the probe measures PHP
    // startup, not contention: interpreter boot is tens of milliseconds, so the
    // first worker finishes and caches its verdict before the last one exists,
    // and every later worker reports a cache hit. That looks like a perfect
    // stampede collapse and is nothing of the sort.
    $waitedUs = 0;

    while (!file_exists($barrier) && $waitedUs < 10_000_000) {
        usleep(1000);
        $waitedUs += 1000;
    }

    $pool = new FilesystemAdapter('rdns_probe', 3600, $cacheDir);

    if ($doh !== null) {
        $options = ['endpoint' => $doh['endpoint'], 'timeout_ms' => $doh['timeout_ms']];

        if ($doh['address'] !== '') {
            $options['address'] = $doh['address'];
        }

        $resolver = new class ($options, $tally) extends DnsOverHttpResolver {
            public function __construct(array $options, private string $tally)
            {
                parent::__construct($options);
            }

            protected function fetch(string $url): array|string
            {
                file_put_contents($this->tally, "1\n", FILE_APPEND | LOCK_EX);

                return parent::fetch($url);
            }
        };

        // The threshold and scope a rule would get from global.reverse_dns, so the
        // breaker behaves as it does in production rather than at the 250 ms default.
        $settings = ReverseDnsSettings::fromGlobal(['reverse_dns' => [
            'resolver' => DnsOverHttpResolver::class,
            'resolver_options' => $options,
        ]]);

        $verifier = new ReverseDnsVerifier(
            $pool,
            3600,
            86400,
            false,
            $settings->slowThresholdFor([]),
            300,
            $claimWaitMs,
            $resolver,
            60,
            $settings->scopeFor([])
        );
    } else {
        $verifier = new class ($pool, $tally, $latencyMs, $claimWaitMs) extends ReverseDnsVerifier {
            public function __construct(
                $pool,
                private string $tally,
                private float $latencyMs,
                int $claimWaitMs
            ) {
                parent::__construct($pool, 3600, 86400, false, 250.0, 300, $claimWaitMs);
            }

            protected function reverseLookup(string $ip): string|false
            {
                // Appended, not incremented: several processes write at once and a
                // read-modify-write would lose most of them.
                file_put_contents($this->tally, "1\n", FILE_APPEND | LOCK_EX);

                if ($this->latencyMs > 0) {
                    usleep((int) ($this->latencyMs * 1000));
                }

                return 'crawl-66-249-66-1.googlebot.com';
            }

            protected function forwardLookup(string $host): array|false
            {
                return [['ip' => '66.249.66.1']];
            }
        };
    }

    $started = microtime(true);
    $verdict = $verifier->verify('66.249.66.1', ['.googlebot.com']);
    $elapsed = (microtime(true) - $started) * 1000;

    fwrite(STDOUT, sprintf("%d %.3f\n", $verdict ? 1 : 0, $elapsed));
};

if ($isChild) {
    $child($cacheDir, $tally, $latencyMs, $barrier, $claimWaitMs, $doh);

    return;
}

// The parent forks the workers so they contend for the same cold entry at the
// same instant. proc_open rather than pcntl, so this runs without an extension.
$self = __FILE__;
$processes = [];
$pipes = [];

$startedAll = microtime(true);

for ($i = 0; $i < $workers; $i++) {
    $descriptor = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $command = sprintf(
        '%s %s%s %d %s --child',
        escapeshellarg(PHP_BINARY),
        // Both settings, on the command: they cannot be set from inside the worker,
        // and PHP's curl ignores curl.cainfo whenever openssl.cafile is set -- which
        // Homebrew's php.ini does. A local server's self-signed certificate needs both.
        $caInfo === '' ? '' : sprintf('-d %s -d %s ', escapeshellarg('openssl.cafile=' . $caInfo), escapeshellarg('curl.cainfo=' . $caInfo)),
        escapeshellarg($self),
        $workers,
        escapeshellarg((string) $latencyMs)
    );

    // Every child shares the parent's workspace, which is what makes them
    // contend rather than each getting a private cache.
    //
    // Both variables are passed explicitly because an $env array *replaces* the
    // child's environment rather than adding to it -- so anything not listed
    // here is simply absent in the child, silently. That cost an entire round
    // of measurement: the claim wait read as 0 in every worker and the probe
    // reported the feature doing nothing.
    $processes[$i] = proc_open(
        $command,
        $descriptor,
        $pipes[$i],
        null,
        [
            'FW_RDNS_PROBE_WORKSPACE' => $workspace,
            'FW_RDNS_CLAIM_WAIT_MS' => (string) $claimWaitMs,
            'FW_RDNS_RESOLVER' => $doh === null ? '' : 'doh',
            'FW_RDNS_DOH_ENDPOINT' => $doh['endpoint'] ?? '',
            'FW_RDNS_DOH_ADDRESS' => $doh['address'] ?? '',
            'FW_RDNS_DOH_TIMEOUT_MS' => (string) ($doh['timeout_ms'] ?? ''),
        ]
    );
}

// Everything is spawned and waiting; let them all go at once.
usleep(300_000);
file_put_contents($barrier, 'go');
$startedAll = microtime(true);

$verified = 0;
$latencies = [];

foreach ($processes as $i => $process) {
    if (!is_resource($process)) {
        continue;
    }

    $out = trim((string) stream_get_contents($pipes[$i][1]));
    fclose($pipes[$i][1]);
    fclose($pipes[$i][2]);
    proc_close($process);

    foreach (explode("\n", $out) as $line) {
        if (preg_match('/^(\d) ([\d.]+)$/', trim($line), $matches) === 1) {
            $verified += (int) $matches[1];
            $latencies[] = (float) $matches[2];
        }
    }
}

$wall = (microtime(true) - $startedAll) * 1000;
$lookups = count(array_filter(explode("\n", (string) file_get_contents($tally))));

sort($latencies);
$count = count($latencies);

printf("workers            : %d\n", $workers);
if ($doh === null) {
    printf("stubbed resolver   : %.0f ms per lookup\n", $latencyMs);
} else {
    printf("resolver           : DnsOverHttpResolver, %s%s, %d ms per lookup\n", $doh['endpoint'], $doh['address'] === '' ? '' : ' via ' . $doh['address'], $doh['timeout_ms']);
}

printf("DNS lookups made   : %d  (one per worker means the claim collapsed nothing)\n", $lookups);
printf("verified           : %d / %d\n", $verified, $count);

if ($count > 0) {
    printf("latency p50 / max  : %.2f ms / %.2f ms\n", $latencies[intdiv($count, 2)], $latencies[$count - 1]);
}

printf("wall clock         : %.0f ms\n", $wall);

// Leave nothing behind; this runs on developer machines. Depth-first, because
// the pool nests its own directories.
$sweep = static function (string $dir) use (&$sweep): void {
    foreach (glob($dir . '/*') ?: [] as $entry) {
        is_dir($entry) ? $sweep($entry) : @unlink($entry);
    }

    @rmdir($dir);
};

@unlink($tally);
$sweep($workspace);
