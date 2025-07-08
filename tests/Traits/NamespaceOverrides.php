<?php

namespace Kanopi\Firewall\Traits;

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

function flock($filename, $operation)
{
    if (!empty($GLOBALS['simulate_flock_failure'])) {
        return false;
    }

    return \flock($filename, $operation);
}

function fopen($filename, $mode, $flags = 0, $context = null)
{
    if (!empty($GLOBALS['simulate_fopen_failure'])) {
        return false;
    }

    return \fopen($filename, $mode, $flags, $context);
}

function fgets($handle)
{
    if (!empty($GLOBALS['simulate_fgets_failure'])) {
        return false;
    }

    return \fgets($handle);
}

function fwrite($handle, $string, $length = null)
{
    if (!empty($GLOBALS['simulate_fwrite_failure'])) {
        return false;
    }

    return \fwrite($handle, $string, $length);
}
