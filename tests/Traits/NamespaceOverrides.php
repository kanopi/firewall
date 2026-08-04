<?php

namespace Kanopi\Firewall\Traits;

// Simulated flag controlled from the test class
$GLOBALS['simulate_file_put_contents_failure'] = false;
$GLOBALS['simulate_is_readable_failure'] = false;
$GLOBALS['simulate_is_writeable_failure'] = false;

function file_put_contents($filename, $data, ...$args)
{
    if (!empty($GLOBALS['simulate_file_put_contents_failure'])) {
        return false;
    }

    return \file_put_contents($filename, $data, ...$args);
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

function fopen($filename, $mode, ...$args)
{
    if (!empty($GLOBALS['simulate_fopen_failure'])) {
        return false;
    }

    return \fopen($filename, $mode, ...$args);
}

function fgets($handle)
{
    if (!empty($GLOBALS['simulate_fgets_failure'])) {
        return false;
    }

    return \fgets($handle);
}

function fwrite($handle, $string, ...$args)
{
    if (!empty($GLOBALS['simulate_fwrite_failure'])) {
        return false;
    }

    return \fwrite($handle, $string, ...$args);
}

/**
 * Forcing this false is how the mkdir() branch in FileTrait is reached: the
 * per-user temp directory survives between runs, so after the first test in
 * any environment the directory already exists and the branch never executes.
 *
 * @param string $filename
 *   Path to test.
 *
 * @return bool
 *   Whether the path is a directory, or FALSE when the flag is set.
 */
function is_dir($filename)
{
    if (!empty($GLOBALS['simulate_is_dir_failure'])) {
        return false;
    }

    return \is_dir($filename);
}
