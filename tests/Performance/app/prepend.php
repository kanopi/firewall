<?php

declare(strict_types=1);

/*
 * auto_prepend_file for the performance harness.
 *
 * A load generator runs on one machine and therefore has one source IP.
 * The firewall's most interesting plugins — IpAddress, GeoLocation, Asn,
 * RateLimit, AbuseIpdb, VulnerabilityScore — all key off the client IP, so
 * benchmarking them against a single IP would measure a cache hit over and
 * over and tell us nothing about behaviour at scale.
 *
 * This runs before every request and rewrites REMOTE_ADDR from a header the
 * generator controls, so one k6 container can present tens of thousands of
 * distinct clients to the firewall.
 *
 * WHY A PREPEND AND NOT TRUSTED PROXIES:
 * Symfony's trusted-proxy handling is part of what we are measuring. Routing
 * the spoof through X-Forwarded-For would put the firewall's own header
 * parsing inside the measurement and change what the plugins see depending
 * on how trusted proxies happen to be configured. Rewriting REMOTE_ADDR
 * before PHP hands control to the app keeps the substitution invisible to
 * the code under test: as far as the firewall is concerned, this really is
 * the peer address.
 *
 * SAFETY:
 * Inert unless FIREWALL_PERF=1 is set in the environment. That variable is
 * set only by tests/Performance/docker-compose.yml. If this file is ever
 * prepended somewhere it should not be, it does nothing at all.
 */

(static function (): void {
    if (getenv('FIREWALL_PERF') !== '1') {
        return;
    }

    $headerName = getenv('FIREWALL_PERF_IP_HEADER') ?: 'X-Perf-Client-Ip';

    // Header-to-CGI translation: X-Perf-Client-Ip -> HTTP_X_PERF_CLIENT_IP.
    $serverKey = 'HTTP_' . str_replace('-', '_', strtoupper($headerName));

    if (!isset($_SERVER[$serverKey]) || !is_string($_SERVER[$serverKey])) {
        return;
    }

    // Validate rather than trust. A malformed value would otherwise reach
    // the plugins as a client IP and produce block decisions that look like
    // firewall behaviour but are really a broken generator.
    $candidate = filter_var($_SERVER[$serverKey], FILTER_VALIDATE_IP);

    if ($candidate === false) {
        return;
    }

    $_SERVER['REMOTE_ADDR'] = $candidate;

    // Symfony's Request::createFromGlobals() reads REMOTE_ADDR, but anything
    // that already captured the peer address would not see the change. The
    // harness constructs its Request after this point, so this is sufficient.
})();
