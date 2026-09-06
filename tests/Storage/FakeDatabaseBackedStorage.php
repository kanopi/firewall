<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Storage;

use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Traits\DatabaseTrait;

/**
 * A storage class outside this package that connects through `DatabaseTrait`.
 *
 * The custom-storage guide encourages hosts to write their own, so
 * `Firewall::storageConnection()` decides whether a storage backend can lend
 * its connection to the log handler by looking for the trait rather than for
 * `DatabaseStorage` specifically. This stands in for such a class.
 *
 * It deliberately never calls `createConnection()`: the point under test is
 * that the connection *parameters* are recognised and passed on, and opening
 * one would make the test about Doctrine instead.
 */
class FakeDatabaseBackedStorage extends InMemoryStorage
{
    use DatabaseTrait;
}
