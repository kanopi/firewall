<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Exception;

/**
 * Exception thrown when a storage backend cannot reach its backing service.
 *
 * Separate from the more general `StorageException` so a consumer can tell
 * "the database is unreachable, or its credentials are wrong" — an operational
 * problem, and one worth reporting to an administrator verbatim — from a
 * storage operation that failed for some other reason. It extends
 * `StorageException`, so existing `catch (StorageException)` and
 * `catch (FirewallException)` guards keep working unchanged.
 *
 * The original driver exception is always attached as `previous`.
 */
class StorageConnectionException extends StorageException
{
}
