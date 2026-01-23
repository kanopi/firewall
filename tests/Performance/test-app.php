<?php

/**
 * Test application for firewall performance testing
 * This simulates a real application with the firewall enabled
 */

require_once __DIR__ . '/../../vendor/autoload.php';

use Kanopi\Firewall\Firewall;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

// Start timing
$startTime = microtime(true);

try {
    // Create request from globals but override with test headers
    $request = Request::createFromGlobals();
    
    // Override IP and other headers from test client
    if ($request->headers->has('X-Forwarded-For')) {
        $_SERVER['REMOTE_ADDR'] = $request->headers->get('X-Forwarded-For');
        $request->server->set('REMOTE_ADDR', $request->headers->get('X-Forwarded-For'));
    }
    
    // Create firewall configuration for testing
    $config = [
        'storage' => [
            'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
        ],
        'block' => [
            // IP Address blocking
            'Kanopi\Firewall\Plugins\IpAddress' => [
                'enable' => true,
                'priority' => -100,
                'config' => [
                    // Block some test IPs from specific countries
                    '1.0.0.0/8',  // China range (test)
                    '2.0.0.0/8',  // Russia range (test)
                ]
            ],
            
            // URL blocking
            'Kanopi\Firewall\Plugins\Url' => [
                'enable' => true,
                'priority' => -50,
                'config' => [
                    // Block WordPress URLs
                    'path@contains:wp-admin',
                    'path@contains:wp-login',
                    'path@contains:.env',
                    'path@contains:phpmyadmin',
                    // Block SQL injection attempts
                    'query@regex:/(union.*select|drop.*table)/i',
                ]
            ],
            
            // User Agent blocking
            'Kanopi\Firewall\Plugins\UserAgent' => [
                'enable' => true,
                'priority' => -30,
                'config' => [
                    // Block malicious user agents
                    'client.name@contains:sqlmap',
                    'client.name@contains:nikto',
                    'client.name@contains:masscan',
                ]
            ],
            
            // Rate limiting
            'Kanopi\Firewall\Plugins\RateLimit' => [
                'enable' => true,
                'priority' => 100,
                'metadata' => [
                    'default_rate' => 60,
                    'default_sample' => 60,
                    'default_expiration_time' => 300,
                    'storage' => [
                        'type' => 'Kanopi\Firewall\RateLimitStorage\InMemoryRateLimitStorage'
                    ]
                ],
                'config' => [
                    ['path' => '/api/*', 'rate' => 100, 'sample' => 60],
                    ['path' => '/admin/*', 'rate' => 20, 'sample' => 60],
                    ['path' => '/login', 'rate' => 5, 'sample' => 300],
                ]
            ]
        ]
    ];
    
    // Add GeoLocation plugin if databases are available
    $geoDbPath = getenv('GEOIP_DB_PATH') ?: '/tmp/geoip/GeoLite2-City.mmdb';
    $countryDbPath = getenv('GEOIP_COUNTRY_DB_PATH') ?: '/tmp/geoip/GeoLite2-Country.mmdb';
    
    // Use City database if available, otherwise fall back to Country database
    $dbToUse = file_exists($geoDbPath) ? $geoDbPath : (file_exists($countryDbPath) ? $countryDbPath : null);
    
    if ($dbToUse) {
        $config['block']['Kanopi\Firewall\Plugins\GeoLocation'] = [
            'enable' => true,
            'priority' => -80,
            'metadata' => [
                'reader' => [
                    'type' => 'reader',
                    'db' => $dbToUse
                ]
            ],
            'config' => [
                // Block specific countries
                'country:CN',
                'country:RU',
                'country:KP',
            ]
        ];
    }
    
    // Add ASN plugin if database is available
    $asnDbPath = getenv('ASN_DB_PATH') ?: '/tmp/geoip/GeoLite2-ASN.mmdb';
    if (file_exists($asnDbPath)) {
        $config['block']['Kanopi\Firewall\Plugins\Asn'] = [
            'enable' => true,
            'priority' => -70,
            'metadata' => [
                'reader' => [
                    'type' => 'reader',
                    'db' => $asnDbPath
                ]
            ],
            'config' => [
                // Block specific ASNs (example: known malicious)
                'asn:13335',  // Example ASN
            ]
        ];
    }
    
    // Create and evaluate firewall
    $firewall = Firewall::create([$config, [ 'global' => [ 'mode' => 'exception' ] ]]);

    // Evaluate the request
    $firewall->evaluate($request);
    
    // If we get here, request was allowed
    $response = new Response();
    $response->headers->set('Content-Type', 'application/json');
    $response->headers->set('X-Response-Time', (string)((microtime(true) - $startTime) * 1000));
    
    // Return success response
    $response->setContent(json_encode([
        'status' => 'allowed',
        'message' => 'Request passed firewall',
        'path' => $request->getPathInfo(),
        'method' => $request->getMethod(),
        'ip' => $request->getClientIp(),
        'timestamp' => date('Y-m-d H:i:s'),
    ]));
    
    $response->send();
    
} catch (Exception $e) {
    // Request was blocked
    $response = new Response();
    $response->headers->set('Content-Type', 'application/json');
    $response->headers->set('X-Response-Time', (string)((microtime(true) - $startTime) * 1000));
    
    // Extract blocking information
    $statusCode = $e->getCode() ?: 400;
    $blockingReason = $e->getMessage();
    
    // Try to determine which plugin blocked it
    $plugin = 'unknown';
    if (strpos($blockingReason, 'Rate limit') !== false) {
        $plugin = 'RateLimit';
        $statusCode = 429;
    } elseif (strpos($request->getClientIp(), '1.') === 0 || strpos($request->getClientIp(), '2.') === 0) {
        $plugin = 'IpAddress';
    } elseif (strpos($request->getPathInfo(), 'wp-') !== false || strpos($request->getPathInfo(), '.env') !== false) {
        $plugin = 'Url';
    }
    
    $response->headers->set('X-Blocked-By', $plugin);
    $response->setStatusCode($statusCode);
    
    $response->setContent(json_encode([
        'status' => 'blocked',
        'message' => $blockingReason,
        'plugin' => $plugin,
        'path' => $request->getPathInfo(),
        'method' => $request->getMethod(),
        'ip' => $request->getClientIp(),
        'timestamp' => date('Y-m-d H:i:s'),
    ]));
    
    $response->send();
}