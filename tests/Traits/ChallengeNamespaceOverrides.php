<?php

/*
 * Namespace-scoped shims for Kanopi\Firewall\Challenge.
 *
 * `TurnstileChallengeProvider::fetch()` talks to Cloudflare's siteverify API
 * through the stream wrapper — `fopen()`, `stream_get_meta_data()`,
 * `stream_get_contents()` — so the transport itself is only reachable with a
 * real HTTP response to read. The rest of the suite substitutes `fetch()`
 * wholesale, which is right for testing the decision logic but leaves the
 * transport unexercised: the unreachable-host branch, and the read back of a
 * response whose headers carry no status line.
 *
 * Reaching those against the live endpoint would mean a network call in CI,
 * a real secret key, and asking Cloudflare to fail on demand.
 *
 * PHP resolves an unqualified function call against the current namespace
 * first, so defining these here intercepts the calls without touching the
 * provider. `fopen()` hands back an in-memory stream holding a canned body,
 * and `stream_get_meta_data()` reports canned `wrapper_data` headers for
 * exactly the handles this file created — anything else is delegated
 * untouched, so the other providers in this namespace are unaffected.
 *
 * Every shim is inert unless its flag is set. Callers MUST reset the flags in
 * tearDown(): they are process-global, and a leaked flag would feed a canned
 * HTTP response to every later test in the run.
 *
 * Mirrors tests/Traits/PluginsNamespaceOverrides.php.
 */

namespace Kanopi\Firewall\Challenge;

/**
 * Canned response, or FALSE to make fopen() fail. NULL disables the shim.
 *
 * Shape: ['headers' => array<int, string>, 'body' => string]
 */
$GLOBALS['fake_challenge_http_response'] = null;

/**
 * Handles this file created, mapped to the headers they should report.
 */
$GLOBALS['fake_challenge_http_handles'] = [];

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
    $fake = $GLOBALS['fake_challenge_http_response'] ?? null;

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

    // `headers` is deliberately allowed to be absent rather than defaulted to
    // an empty array: the two cases reach different code in the provider, and
    // only an absent key produces the missing `wrapper_data` that the status
    // parse has to survive.
    if (array_key_exists('headers', $fake)) {
        $GLOBALS['fake_challenge_http_handles'][(int) $handle] = $fake['headers'];
    } else {
        $GLOBALS['fake_challenge_http_handles'][(int) $handle] = null;
    }

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

    if (array_key_exists($id, $GLOBALS['fake_challenge_http_handles'] ?? [])) {
        $headers = $GLOBALS['fake_challenge_http_handles'][$id];

        // A NULL entry stands for a response the wrapper reported no headers
        // for at all, so the key is omitted rather than set to NULL.
        return $headers === null ? [] : ['wrapper_data' => $headers];
    }

    return \stream_get_meta_data($stream);
}
