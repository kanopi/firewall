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
 * Thrown when a plugin source cannot be declared, fetched, or decoded.
 *
 * Whether this reaches the caller depends on the source's `on_error` policy:
 * `abort` and `required: true` let it propagate, the other policies catch it
 * and fall back.
 */
class SourceException extends ConfigurationException
{
}
