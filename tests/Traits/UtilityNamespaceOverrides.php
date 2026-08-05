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
