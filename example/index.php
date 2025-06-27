<?php

require_once __DIR__ . '/../vendor/autoload.php';

//$_SERVER['REMOTE_ADDR'] = file_get_contents('https://api.ipify.org');
$_SERVER['REMOTE_ADDR'] = '108.195.124.110';

putenv('FIREWALL_TEST=1');
$start = microtime(true);
$mem_start = memory_get_usage(true);
$x = $_SERVER['REQUEST_URI'];
if (class_exists('\Kanopi\Firewall\Firewall')) {
    try {
        \Kanopi\Firewall\Firewall::create(
            [
                __DIR__ . '/config.yml'
            ]
        )->evaluate();
        phpinfo();
    } catch(\Exception $e) {}
}
$end = microtime(true);
$mem_end = memory_get_peak_usage(true);

//xdebug_info();
dump([$start, $end, $end-$start]);
dump([$mem_start, $mem_end, $mem_end-$mem_start]);
