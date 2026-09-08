<?php

/*
 * Namespace-scoped shims for Kanopi\Firewall\Storage.
 *
 * PHP resolves an unqualified function call against the current namespace first, so
 * defining these here intercepts the calls without touching the storage classes.
 *
 * `copy()` is here for one branch: FileStorage carries an old shared offense history over to
 * a store's own sidecar on first start (#244), and reports it when the copy fails. Making a
 * real copy fail is not arrangeable -- validateFilePath() has already created the
 * destination and tightened it to 0600, and the process owns it, so it is writable by
 * definition.
 */

declare(strict_types=1);

namespace Kanopi\Firewall\Storage;

$GLOBALS['simulate_storage_copy_failure'] = false;

function copy($from, $to, ...$args)
{
    if (!empty($GLOBALS['simulate_storage_copy_failure'])) {
        return false;
    }

    return \copy($from, $to, ...$args);
}
