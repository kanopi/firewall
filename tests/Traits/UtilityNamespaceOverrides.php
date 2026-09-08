<?php

/*
 * Namespace-scoped shims for Kanopi\Firewall\Utility.
 *
 * PHP resolves an unqualified function call inside a namespace against that
 * namespace first, falling back to the global function. Defining a function
 * here therefore intercepts unqualified calls made from classes in
 * Kanopi\Firewall\Utility, which is the only way to reach a handful of
 * defensive branches whose trigger conditions cannot be produced on demand:
 *
 *   - file_get_contents() returning false on a path that has already passed
 *     is_file() and is_readable() — needs a permissions change or an unlink
 *     to land between the check and the read.
 *   - realpath() failing on a path that exists — stream wrappers, phar, and
 *     certain permission setups only.
 *   - is_file() being false for something that exists and is not a directory
 *     — a FIFO or socket, which is awkward and platform-specific to create.
 *
 * Each shim is inert unless its flag is set, and delegates to the global
 * function otherwise, so merely loading this file changes nothing. Callers
 * MUST reset the flag in tearDown(): these are process-global and a leaked
 * flag corrupts every later test in the run.
 *
 * Mirrors tests/Traits/NamespaceOverrides.php, which does the same for
 * Kanopi\Firewall\Traits.
 */

namespace Kanopi\Firewall\Utility;

$GLOBALS['simulate_utility_file_get_contents_failure'] = false;
$GLOBALS['simulate_utility_realpath_failure'] = false;
$GLOBALS['simulate_utility_is_file_failure'] = false;
$GLOBALS['simulate_utility_file_put_contents_failure'] = false;
$GLOBALS['utility_file_get_contents_return'] = null;
$GLOBALS['simulate_utility_fopen_failure'] = false;
$GLOBALS['simulate_utility_flock_failure'] = false;
$GLOBALS['simulate_utility_rename_failure'] = false;
$GLOBALS['simulate_utility_is_writable_failure'] = false;
$GLOBALS['simulate_utility_is_dir_failure'] = false;

/*
 * Every shim forwards its remaining arguments variadically. This is not
 * cosmetic: `Config::fileGetContents()` calls
 * `file_get_contents($url, false, $context)` with a stream context carrying
 * the request timeout, and a shim declared as `file_get_contents($filename)`
 * silently drops it — the URL is then fetched with no timeout at all and the
 * test asserting a timeout fails for reasons that look nothing like the
 * cause. A shim that does not forward faithfully is worse than no shim.
 */

/**
 * @param string $filename
 *   Path to read.
 * @param mixed ...$args
 *   Remaining native arguments, forwarded untouched.
 *
 * @return string|false
 *   Contents, or FALSE when the failure flag is set.
 */
function file_get_contents($filename, ...$args)
{
    // A canned success, so the write-back path after a remote fetch can be
    // exercised without a network. Only for URLs -- local reads must stay real
    // or the config loader has nothing to load.
    if ($GLOBALS['utility_file_get_contents_return'] !== null
        && (str_starts_with((string) $filename, 'http://') || str_starts_with((string) $filename, 'https://'))) {
        return $GLOBALS['utility_file_get_contents_return'];
    }

    if (!empty($GLOBALS['simulate_utility_file_get_contents_failure'])) {
        return false;
    }

    return \file_get_contents($filename, ...$args);
}

/**
 * @param string $path
 *   Path to canonicalise.
 *
 * @return string|false
 *   Canonical path, or FALSE when the failure flag is set.
 */
function realpath($path)
{
    if (!empty($GLOBALS['simulate_utility_realpath_failure'])) {
        return false;
    }

    return \realpath($path);
}

/**
 * @param string $filename
 *   Path to test.
 *
 * @return bool
 *   Whether the path is a regular file, or FALSE when the flag is set.
 */
function is_file($filename)
{
    if (!empty($GLOBALS['simulate_utility_is_file_failure'])) {
        return false;
    }

    return \is_file($filename);
}

/**
 * Shadow the calls the compiled-config cache and the single-flight refresh
 * guard depend on, so their failure paths can be exercised.
 *
 * All four are "the filesystem said no" branches: a lock file that cannot be
 * opened, a lock that cannot be taken, a publish that fails after a successful
 * write, and a cache directory that is not writable. None can be arranged
 * reliably for real without racing the filesystem or running as another user.
 */
function fopen($filename, $mode, ...$args)
{
    if (!empty($GLOBALS['simulate_utility_fopen_failure'])) {
        return false;
    }

    return \fopen($filename, $mode, ...$args);
}

function flock($handle, $operation, &$would_block = null)
{
    if (!empty($GLOBALS['simulate_utility_flock_failure'])) {
        return false;
    }

    return \flock($handle, $operation, $would_block);
}

function rename($from, $to)
{
    if (!empty($GLOBALS['simulate_utility_rename_failure'])) {
        return false;
    }

    return \rename($from, $to);
}

function is_writable($filename)
{
    if (!empty($GLOBALS['simulate_utility_is_writable_failure'])) {
        return false;
    }

    return \is_writable($filename);
}

function file_put_contents($filename, $data, ...$args)
{
    if (!empty($GLOBALS['simulate_utility_file_put_contents_failure'])) {
        return false;
    }

    return \file_put_contents($filename, $data, ...$args);
}

function is_dir($filename)
{
    if (!empty($GLOBALS['simulate_utility_is_dir_failure'])) {
        return false;
    }

    return \is_dir($filename);
}
