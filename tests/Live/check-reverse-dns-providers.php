<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Check every built-in reverse DNS provider still answers correctly (#477).
 *
 * The built-in providers depend on public APIs this project doesn't control, and Quad9
 * retired its JSON service on 5 May 2025. A provider that changes or retires its API, moves
 * its address, or lets its certificate stop matching should be caught here -- not by sites
 * finding their verified crawler rules quietly matching nobody.
 *
 * Each provider is used exactly as a site would use it: built from `BuiltinProviders` through
 * `ReverseDnsSettings`, pinned address included. Four checks:
 *
 *   1. ptr        1.66.249.66.in-addr.arpa answers crawl-66-249-66-1.googlebot.com
 *   2. forward    crawl-66-249-66-1.googlebot.com answers 66.249.66.1
 *   3. no-record  1.2.0.192.in-addr.arpa is "no record", not "could not tell"
 *   4. verify     the full round trip verifies 66.249.66.1 as .googlebot.com
 *
 * A check that comes back "could not tell" (a timeout, a server error) is retried once, so
 * one dropped packet on a CI runner does not open an issue.
 *
 * Not part of the unit suite, which makes no network calls. Run by the weekly
 * `reverse-dns-providers` workflow, or by hand:
 *
 *   php tests/Live/check-reverse-dns-providers.php [--markdown=FILE] [--junit=FILE]
 *
 * Exit code 0 when every check passes, 1 when any fails.
 */

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use Kanopi\Firewall\Utility\ReverseDns\BuiltinProviders;
use Kanopi\Firewall\Utility\ReverseDns\LookupResult;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsResolverInterface;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsSettings;
use Kanopi\Firewall\Utility\ReverseDnsVerifier;

const GOOGLEBOT_IP = '66.249.66.1';
const GOOGLEBOT_HOST = 'crawl-66-249-66-1.googlebot.com';
const NO_RECORD_IP = '192.0.2.1';

// Generous: this checks that providers answer correctly, not how fast. A tight limit on a
// shared CI runner would report the runner's network, not the provider.
const TIMEOUT_MS = 2000;

$options = getopt('', ['markdown:', 'junit:']);
$markdownFile = is_string($options['markdown'] ?? null) ? $options['markdown'] : null;
$junitFile = is_string($options['junit'] ?? null) ? $options['junit'] : null;

/**
 * Ask once, and once more if the first answer was "could not tell".
 *
 * @param callable(): LookupResult $lookup
 */
$ask = static function (callable $lookup): LookupResult {
    $lookupResult = $lookup();

    return $lookupResult->isUnknown() ? $lookup() : $lookupResult;
};

/**
 * What a result says, for the report.
 */
$describe = static fn(LookupResult $lookupResult): string => match ($lookupResult->status) {
    LookupResult::ANSWER => 'answered ' . implode(', ', $lookupResult->values),
    LookupResult::NONE => 'no record',
    default => 'could not tell: ' . $lookupResult->reason,
};

/**
 * The four checks for one provider.
 *
 * @return list<array{check: string, ok: bool, detail: string, ms: float}>
 */
$checkProvider = static function (ReverseDnsResolverInterface $resolver) use ($ask, $describe): array {
    $results = [];

    $timed = static function (string $check, callable $run) use (&$results): void {
        $started = microtime(true);
        [$ok, $detail] = $run();
        $results[] = ['check' => $check, 'ok' => $ok, 'detail' => $detail, 'ms' => (microtime(true) - $started) * 1000];
    };

    $timed('ptr', static function () use ($ask, $describe, $resolver): array {
        $lookupResult = $ask(static fn(): LookupResult => $resolver->reverse(GOOGLEBOT_IP));
        $hosts = array_map(static fn(string $host): string => rtrim(strtolower($host), '.'), $lookupResult->values);

        return [in_array(GOOGLEBOT_HOST, $hosts, true), $describe($lookupResult)];
    });

    $timed('forward', static function () use ($ask, $describe, $resolver): array {
        $lookupResult = $ask(static fn(): LookupResult => $resolver->forward(GOOGLEBOT_HOST, ReverseDnsResolverInterface::TYPE_A));

        return [in_array(GOOGLEBOT_IP, $lookupResult->values, true), $describe($lookupResult)];
    });

    $timed('no-record', static function () use ($ask, $describe, $resolver): array {
        $lookupResult = $ask(static fn(): LookupResult => $resolver->reverse(NO_RECORD_IP));

        return [$lookupResult->status === LookupResult::NONE, $describe($lookupResult)];
    });

    $timed('verify', static function () use ($resolver): array {
        // No cache, so this is a real round trip through the same code a rule uses.
        $verifier = new ReverseDnsVerifier(null, 3600, 86400, false, 60000.0, 300, 0, $resolver, 60, 'live-check');
        $verified = $verifier->verify(GOOGLEBOT_IP, ['.googlebot.com']);

        return [$verified, $verified ? 'verified' : 'not verified'];
    });

    return $results;
};

$report = [];
$failed = 0;

foreach (BuiltinProviders::names() as $name) {
    try {
        $resolver = ReverseDnsSettings::fromGlobal(['reverse_dns' => ['provider' => $name, 'timeout_ms' => TIMEOUT_MS]])->resolverFor([]);
    } catch (\Throwable $throwable) {
        $report[$name] = [['check' => 'build', 'ok' => false, 'detail' => $throwable->getMessage(), 'ms' => 0.0]];
        $failed++;
        continue;
    }

    if (!$resolver instanceof ReverseDnsResolverInterface) {
        $report[$name] = [['check' => 'build', 'ok' => false, 'detail' => 'no resolver was built', 'ms' => 0.0]];
        $failed++;
        continue;
    }

    $report[$name] = $checkProvider($resolver);
    $failed += count(array_filter($report[$name], static fn(array $result): bool => !$result['ok']));
}

$date = gmdate('Y-m-d');

foreach ($report as $name => $results) {
    foreach ($results as $result) {
        printf("%-11s %-10s %-4s %7.1f ms  %s\n", $name, $result['check'], $result['ok'] ? 'ok' : 'FAIL', $result['ms'], $result['detail']);
    }
}

printf("\n%s: %s\n", $date, $failed === 0 ? 'every built-in provider passed' : $failed . ' check(s) failed');

if ($markdownFile !== null) {
    $lines = [
        sprintf('The weekly reverse DNS provider check found %d failing check(s) on %s.', $failed, $date),
        '',
        '| Provider | Check | Result | Time | Detail |',
        '|---|---|---|---|---|',
    ];

    foreach ($report as $name => $results) {
        foreach ($results as $result) {
            $lines[] = sprintf(
                '| `%s` | %s | %s | %.0f ms | %s |',
                $name,
                $result['check'],
                $result['ok'] ? 'ok' : '**FAIL**',
                $result['ms'],
                str_replace('|', '\|', $result['detail'])
            );
        }
    }

    $lines[] = '';
    $lines[] = 'If every provider fails the same checks, the likelier cause is that Googlebot\'s `66.249.66.1` or its PTR record has changed. Check that before suspecting the providers.';
    $lines[] = '';
    $lines[] = 'A provider that fails on its own needs looking at: its API, its address or its certificate may have changed. Until it is fixed, sites selecting it get "could not tell" and verify no new crawlers. See `docs/configuration/reverse-dns.md`, and the check in `tests/Live/check-reverse-dns-providers.php`.';

    file_put_contents($markdownFile, implode("\n", $lines) . "\n");
}

if ($junitFile !== null) {
    $xml = new \XMLWriter();
    $xml->openUri($junitFile);
    $xml->setIndent(true);
    $xml->startDocument('1.0', 'UTF-8');
    $xml->startElement('testsuites');

    foreach ($report as $name => $results) {
        $xml->startElement('testsuite');
        $xml->writeAttribute('name', 'reverse-dns-provider ' . $name);
        $xml->writeAttribute('tests', (string) count($results));
        $xml->writeAttribute('failures', (string) count(array_filter($results, static fn(array $result): bool => !$result['ok'])));

        foreach ($results as $result) {
            $xml->startElement('testcase');
            $xml->writeAttribute('classname', 'reverse-dns-provider.' . $name);
            $xml->writeAttribute('name', $result['check']);
            $xml->writeAttribute('time', sprintf('%.3f', $result['ms'] / 1000));

            if (!$result['ok']) {
                $xml->startElement('failure');
                $xml->writeAttribute('message', $result['detail']);
                $xml->endElement();
            }

            $xml->endElement();
        }

        $xml->endElement();
    }

    $xml->endElement();
    $xml->endDocument();
    $xml->flush();
}

exit($failed === 0 ? 0 : 1);
