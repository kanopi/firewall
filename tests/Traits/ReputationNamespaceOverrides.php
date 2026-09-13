<?php

/*
 * Namespace-scoped shims for Kanopi\Firewall\Reputation.
 *
 * A reputation provider talks to its service through the stream wrapper --
 * `fopen()`, `stream_get_meta_data()`, `stream_get_contents()` -- so every
 * response-handling branch in one (non-200 statuses, an empty body, a body that
 * is not a verdict, an unreachable host) needs a real HTTP response to
 * exercise. Reaching those against a live service would mean spending quota,
 * needing a key in CI, and asking a third party to return specific errors on
 * demand.
 *
 * PHP resolves an unqualified function call against the current namespace
 * first, so defining these here intercepts the calls without touching the
 * provider. `fopen()` hands back an in-memory stream holding a canned body, and
 * `stream_get_meta_data()` reports canned `wrapper_data` headers for exactly
 * the handles this file created -- anything else is delegated untouched.
 *
 * These are the same two shims `tests/Traits/PluginsNamespaceOverrides.php`
 * carries, and they are here rather than shared because the interception is
 * per-namespace: the HTTP call moved to `Kanopi\Firewall\Reputation` with the
 * provider interface (#204), while the verdict cache stayed in
 * `Kanopi\Firewall\Plugins` with the rule that owns it. A test exercising both
 * halves requires both files, which is exactly what that split looks like.
 *
 * Every shim is inert unless its flag is set. Callers MUST reset the flags in
 * tearDown(): they are process-global, and a leaked flag would feed a canned
 * HTTP response to every later test in the run.
 */

namespace Kanopi\Firewall\Reputation;

/**
 * Canned response, or FALSE to make fopen() fail. NULL disables the shim.
 *
 * Shape: ['headers' => array<int, string>, 'body' => string]
 */
$GLOBALS['fake_reputation_http_response'] = null;

/**
 * Handles this file created, mapped to the headers they should report.
 */
$GLOBALS['fake_reputation_http_handles'] = [];

/**
 * The request options of each call this file intercepted.
 */
$GLOBALS['fake_reputation_http_requests'] = [];

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
    $fake = $GLOBALS['fake_reputation_http_response'] ?? null;

    if ($fake === null) {
        return \fopen($filename, $mode, ...$args);
    }

    if ($fake === false) {
        return false;
    }

    // The URL each call was made with, so a test can assert what was asked --
    // that the address reached the endpoint, and that a credential did not
    // reach anywhere it should not.
    $GLOBALS['fake_reputation_http_urls'][] = $filename;

    // And the request itself, out of the stream context: method, headers and
    // body, exactly as they would have gone on the wire. Without this a test
    // of "what did we send" can only re-do the sending code and assert its own
    // copy of it.
    $context = $args[1] ?? null;
    $GLOBALS['fake_reputation_http_requests'][] = is_resource($context)
        ? (\stream_context_get_options($context)['http'] ?? [])
        : [];

    $handle = \fopen('php://memory', 'r+');

    if ($handle === false) {
        return false;
    }

    \fwrite($handle, (string) ($fake['body'] ?? ''));
    \rewind($handle);

    $GLOBALS['fake_reputation_http_handles'][(int) $handle] = $fake['headers'] ?? [];

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

    if (array_key_exists($id, $GLOBALS['fake_reputation_http_handles'] ?? [])) {
        return ['wrapper_data' => $GLOBALS['fake_reputation_http_handles'][$id]];
    }

    return \stream_get_meta_data($stream);
}
