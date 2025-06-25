<?php

namespace Kanopi\Firewall\RateLimitStorage;

// Simulated flag controlled from the test class
$GLOBALS['simulate_file_put_contents_failure'] = false;
$GLOBALS['simulate_is_readable_failure'] = false;
$GLOBALS['simulate_is_writeable_failure'] = false;

function file_put_contents($filename, $data, $flags = 0)
{
    if (!empty($GLOBALS['simulate_file_put_contents_failure'])) {
        return false;
    }

    return \file_put_contents($filename, $data, $flags);
}

function is_readable($filename)
{
    if (!empty($GLOBALS['simulate_is_readable_failure'])) {
        return false;
    }

    return \is_readable($filename);
}

function is_writable($filename)
{
    if (!empty($GLOBALS['simulate_is_writeable_failure'])) {
        return false;
    }

    return \is_writeable($filename);
}