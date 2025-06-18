<?php

require_once __DIR__ . '/../vendor/autoload.php';

$_SERVER['REMOTE_ADDR'] = file_get_contents('https://api.ipify.org');

if (class_exists('\Kanopi\Firewall\Firewall')) {
    \Kanopi\Firewall\Firewall::create(
        [
            __DIR__ . '/config.yml'
        ]
    )->evaluate();
}

//xdebug_info();
phpinfo();