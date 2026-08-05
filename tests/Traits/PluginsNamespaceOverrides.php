<?php

/*
 * Namespace-scoped shims for Kanopi\Firewall\Plugins.
 *
 * `AbuseIpdb::fetch()` talks to the AbuseIPDB API through the stream wrapper —
 * `fopen()`, `stream_get_meta_data()`, `stream_get_contents()` — so every
 * response-handling branch in it (non-200 statuses, an empty body, a body that
 * is not a check result, an unreachable host) needs a real HTTP response to
 * exercise. Reaching those against the live API would mean spending quota,
 * needing a key in CI, and asking a third party to return specific errors on
 * demand.
 *
 * PHP resolves an unqualified function call against the current namespace
 * first, so defining these here intercepts the calls without touching the
 * plugin. `fopen()` hands back an in-memory stream holding a canned body, and
 * `stream_get_meta_data()` reports canned `wrapper_data` headers for exactly
 * the handles this file created — anything else is delegated untouched, so
 * other plugins in this namespace are unaffected.
 *
 * Every shim is inert unless its flag is set. Callers MUST reset the flags in
 * tearDown(): they are process-global, and a leaked flag would feed a canned
 * HTTP response to every later test in the run.
 *
 * Mirrors tests/Traits/NamespaceOverrides.php and
 * tests/Traits/UtilityNamespaceOverrides.php.
 */

namespace Kanopi\Firewall\Plugins;

/**
 * Canned response, or FALSE to make fopen() fail. NULL disables the shim.
 *
 * Shape: ['headers' => array<int, string>, 'body' => string]
 */
$GLOBALS['fake_plugin_http_response'] = null;

/**
 * Handles this file created, mapped to the headers they should report.
 */
$GLOBALS['fake_plugin_http_handles'] = [];

$GLOBALS['simulate_plugins_file_get_contents_failure'] = false;
$GLOBALS['simulate_plugins_file_put_contents_failure'] = false;
$GLOBALS['simulate_plugins_is_dir_failure'] = false;
$GLOBALS['simulate_plugins_mkdir_failure'] = false;

/**
 * @param string $filename
 *   Target to open.
 * @param string $mode
 *   Open mode.
 * @param mixed ...$args
 *   Remaining native arguments, forwarded untouched.
 *
 * @return resource|false
 *   A stream, or FALSE when the canned response says the host is unreachable.
 */
function fopen($filename, $mode, ...$args)
{
    $fake = $GLOBALS['fake_plugin_http_response'] ?? null;

    if ($fake === null) {
        return \fopen($filename, $mode, ...$args);
    }

    if ($fake === false) {
        return false;
    }

    $handle = \fopen('php://memory', 'r+');
    if ($handle === false) {
        return false;
    }

    \fwrite($handle, (string) ($fake['body'] ?? ''));
    \rewind($handle);

    $GLOBALS['fake_plugin_http_handles'][(int) $handle] = $fake['headers'] ?? [];

    return $handle;
}

/**
 * @param resource $stream
 *   Stream to describe.
 *
 * @return array<string, mixed>
 *   Metadata, with `wrapper_data` faked for handles this file created.
 */
function stream_get_meta_data($stream)
{
    $id = (int) $stream;

    if (array_key_exists($id, $GLOBALS['fake_plugin_http_handles'] ?? [])) {
        return ['wrapper_data' => $GLOBALS['fake_plugin_http_handles'][$id]];
    }

    return \stream_get_meta_data($stream);
}

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
    if (!empty($GLOBALS['simulate_plugins_file_get_contents_failure'])) {
        return false;
    }

    return \file_get_contents($filename, ...$args);
}

/**
 * @param string $filename
 *   Path to write.
 * @param mixed $data
 *   Contents to write.
 * @param mixed ...$args
 *   Remaining native arguments, forwarded untouched.
 *
 * @return int|false
 *   Bytes written, or FALSE when the failure flag is set.
 */
function file_put_contents($filename, $data, ...$args)
{
    if (!empty($GLOBALS['simulate_plugins_file_put_contents_failure'])) {
        return false;
    }

    return \file_put_contents($filename, $data, ...$args);
}

/**
 * @param string $filename
 *   Path to test.
 *
 * @return bool
 *   Whether the path is a directory, or FALSE when the flag is set.
 */
function is_dir($filename)
{
    if (!empty($GLOBALS['simulate_plugins_is_dir_failure'])) {
        return false;
    }

    return \is_dir($filename);
}

/**
 * @param string $directory
 *   Path to create.
 * @param mixed ...$args
 *   Remaining native arguments, forwarded untouched.
 *
 * @return bool
 *   Whether creation succeeded, or FALSE when the flag is set.
 */
function mkdir($directory, ...$args)
{
    if (!empty($GLOBALS['simulate_plugins_mkdir_failure'])) {
        return false;
    }

    return \mkdir($directory, ...$args);
}
