<?php

require_once __DIR__ . '/../vendor/autoload.php';

// Put in test mode so throws an exception.
putenv('FIREWALL_TEST=1');

function print_headers()
{
    global $start, $mem_start, $end, $mem_end;

    $headers = [
        'start' => $start,
        'end' => $end,
        'time' => $end - $start,
        'memory_start' => $mem_start,
        'memory_end' => $mem_end,
        'memory' => $mem_end - $mem_start,
    ];

    foreach ($headers as $header => $value) {
        header($header . ': ' . $value);
    }
}

// Start
$start = microtime(true);
$mem_start = memory_get_usage(true);

$status = 200;
// Check to see if class loads.
if (class_exists('\Kanopi\Firewall\Firewall')) {
    // Try / Catch Block to allow to send.
    try {
        // If the X-FORWARD-FOR header is set, set the REMOTE_ADDR as the trusted proxy.
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            \Symfony\Component\HttpFoundation\Request::setTrustedProxies(
                explode(',', $_SERVER['REMOTE_ADDR']),
                \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_FOR
            );
        }
        \Kanopi\Firewall\Firewall::create(
            [
                __DIR__ . '/config.yml'
            ]
        )->evaluate();

        ob_start();
        echo "<pre>";
        print_r($_SERVER);
        print "</pre>";
        $content = ob_get_contents();
        ob_end_clean();
    } catch (\Exception $exception) {
        $content = $exception->getMessage();
        $status = $exception->getCode();
    } finally {
        $end = microtime(true);
        $mem_end = memory_get_usage(true);
        http_response_code($status);
        print_headers();
    }

    echo $content;
}
