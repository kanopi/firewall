<?php

namespace Kanopi\Firewall\Traits;

// Simulated flag controlled from the test class
$GLOBALS['simulate_file_put_contents_failure'] = false;
$GLOBALS['simulate_is_readable_failure'] = false;
$GLOBALS['simulate_is_writeable_failure'] = false;
$GLOBALS['simulate_is_dir_failure'] = false;

// `fake_fileperms` is deliberately left unset rather than NULL: the shim tests
// with isset(), so an unset key means "report the real mode".
$GLOBALS['record_chmod_calls'] = false;
$GLOBALS['recorded_chmod_calls'] = [];

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

/**
 * Report a chosen mode instead of the real one.
 *
 * The tighten-loose-permissions branch only runs for a pre-existing file that
 * is group- or world-readable, which depends on the ambient umask — so it
 * fires on a developer machine and not in CI's Docker image. Faking the mode
 * makes the branch run everywhere, independently of the filesystem.
 *
 * @param string $filename
 *   Path to inspect.
 *
 * @return int|false
 *   The faked mode when set, otherwise the real one.
 */
function fileperms($filename)
{
    if (isset($GLOBALS['fake_fileperms'])) {
        return $GLOBALS['fake_fileperms'];
    }

    return \fileperms($filename);
}

/**
 * Record the mode chmod() was asked for, then delegate.
 *
 * Recording rather than asserting the result matters here: the CircleCI
 * cimg/php images silently no-op chmod() on files under sys_get_temp_dir() —
 * the call returns TRUE but a subsequent fileperms() read shows the old mode —
 * so the only portable way to check the mask arithmetic is to look at what was
 * requested.
 *
 * @param string $filename
 *   Path to modify.
 * @param int $permissions
 *   Mode requested.
 *
 * @return bool
 *   Whether the change succeeded.
 */
function chmod($filename, $permissions)
{
    if (!empty($GLOBALS['record_chmod_calls'])) {
        $GLOBALS['recorded_chmod_calls'][] = ['path' => $filename, 'mode' => $permissions];
    }

    return \chmod($filename, $permissions);
}
