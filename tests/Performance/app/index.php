<?php

declare(strict_types=1);

/*
 * Front controller for the performance harness.
 *
 * Every request in every scenario lands here. The scenario is chosen by the
 * FIREWALL_PERF_SCENARIO environment variable, which bin/run.sh sets when it
 * recreates the php container between runs — so a given container process
 * only ever serves one scenario, and opcache / worker state never carries
 * one plugin's warm-up into another plugin's measurement.
 *
 * The response carries the timings as headers rather than in the body:
 *
 *   X-Fw-Scenario      scenario name, echoed back for sanity checking
 *   X-Fw-Outcome       allow | block | challenge | error
 *   X-Fw-Boot-Us       microseconds in Firewall::create() (config + plugin wiring)
 *   X-Fw-Eval-Us       microseconds in Firewall::evaluate() (the actual decision)
 *   X-Fw-Total-Us      microseconds for the whole PHP request
 *   X-Fw-Mem-Kb        peak memory for the request, in KiB
 *
 * k6 reads these into its own metrics, which is what lets the report separate
 * "what the firewall costs" from "what nginx, php-fpm, and the network cost".
 * Wall-clock latency alone cannot make that split.
 */

use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;

$requestStart = hrtime(true);

require dirname(__DIR__, 3) . '/vendor/autoload.php';

$scenario = getenv('FIREWALL_PERF_SCENARIO') ?: 'baseline';

/**
 * Elapsed microseconds since a hrtime(true) mark.
 */
$elapsedUs = static fn (int $from): string
    => (string) intdiv(hrtime(true) - $from, 1_000);

/**
 * Burn CPU for roughly the configured number of milliseconds.
 *
 * Without this the app under test is a hello-world, and the firewall's cost
 * looks enormous next to it — 3ms of CRS against a 0.3ms app reads as "1000%
 * slower", which is true and also useless. Real applications spend tens to
 * hundreds of milliseconds per request, and the question that matters is what
 * fraction of *that* the firewall consumes. Set PERF_APP_WORK_MS to model
 * your own app and the overhead percentages in the report become meaningful.
 *
 * A busy loop is used rather than usleep() on purpose: sleeping would release
 * the CPU and let far more workers run concurrently than a real PHP app ever
 * would, which would understate contention at high worker counts.
 */
$simulateAppWork = static function (float $milliseconds): void {
    if ($milliseconds <= 0.0) {
        return;
    }

    $deadline = hrtime(true) + (int) ($milliseconds * 1_000_000);
    $sink = 0.0;

    while (hrtime(true) < $deadline) {
        // Enough arithmetic between clock reads that hrtime() itself is not
        // the thing being benchmarked.
        for ($i = 0; $i < 200; $i++) {
            $sink += sqrt((float) $i) * 1.000001;
        }
    }

    // Defeat any future optimiser that might notice $sink is unused.
    if ($sink < 0.0) {
        echo '';
    }
};

$appWorkMs = (float) (getenv('PERF_APP_WORK_MS') ?: '0');

$bootUs = '0';
$evalUs = '0';
$outcome = 'allow';
$status = 200;

if ($scenario === 'baseline') {
    // The floor: nginx + php-fpm + autoloader, and no firewall code at all.
    // Every other scenario is read as a delta from this number.
    $simulateAppWork($appWorkMs);
} else {
    $configFile = dirname(__DIR__) . '/scenarios/' . basename($scenario) . '.yml';

    if (!is_file($configFile)) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        header('X-Fw-Scenario: ' . $scenario);
        header('X-Fw-Outcome: error');
        echo "unknown scenario '{$scenario}': no such file {$configFile}\n";
        exit;
    }

    try {
        $bootStart = hrtime(true);
        $firewall = Firewall::create([$configFile]);
        $bootUs = $elapsedUs($bootStart);

        $evalStart = hrtime(true);
        // Passing null lets the firewall build its own Request from globals,
        // which is how a real integration calls it — Request construction is
        // part of the cost and belongs inside the measurement.
        $firewall->evaluate();
        $evalUs = $elapsedUs($evalStart);

        $simulateAppWork($appWorkMs);
    } catch (FirewallBlockedException $e) {
        $evalUs = $elapsedUs($evalStart ?? $requestStart);
        $outcome = 'block';
        $status = $e->getCode() >= 400 && $e->getCode() < 600 ? $e->getCode() : 403;
    } catch (ChallengeRequiredException) {
        $evalUs = $elapsedUs($evalStart ?? $requestStart);
        $outcome = 'challenge';
        $status = 429;
    } catch (ChallengeSolvedException) {
        $evalUs = $elapsedUs($evalStart ?? $requestStart);
        $outcome = 'allow';
    } catch (Throwable $e) {
        // A misconfigured scenario must be loud. Silently returning 200 here
        // would produce a beautiful benchmark of a firewall that never ran.
        $evalUs = $elapsedUs($evalStart ?? $requestStart);
        $outcome = 'error';
        $status = 500;
        error_log(sprintf(
            'perf harness: scenario "%s" threw %s: %s',
            $scenario,
            $e::class,
            $e->getMessage(),
        ));
    }
}

http_response_code($status);
header('Content-Type: application/json; charset=utf-8');
header('X-Fw-Scenario: ' . $scenario);
header('X-Fw-Outcome: ' . $outcome);
header('X-Fw-Boot-Us: ' . $bootUs);
header('X-Fw-Eval-Us: ' . $evalUs);
header('X-Fw-Mem-Kb: ' . (string) intdiv(memory_get_peak_usage(true), 1024));
header('X-Fw-Total-Us: ' . $elapsedUs($requestStart));

// A short, fixed-size body. Response size is held constant across scenarios
// so that differences in throughput cannot be an artefact of bytes on the wire.
echo '{"o":"', $outcome, '"}';
